from fastapi import FastAPI, HTTPException, BackgroundTasks, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from typing import List, Optional
from scanner import NmapScanner
from llm import summarize_scan
from pdf_generator import generate_pdf_report
from tool_detector import detect_all_tools
from tool_scanners import get_scanner
from vulnerability_parser import VulnerabilityAggregator
import uuid
import logging
import asyncio

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Nmap LLM Scanner")

# CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Allow all for local dev
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

scanner = NmapScanner()

# In-memory storage
scan_results = {}

class ScanRequest(BaseModel):
    target: str
    ai_model: str = "deepseek-r1:1.5b"  # Default AI model
    selected_tools: List[str] = ["nmap_tcp"]  # Default to optimized TCP nmap
    sudo_password: Optional[str] = None

class VerifySudoRequest(BaseModel):
    password: str

@app.post("/api/verify-sudo")
async def verify_sudo(request: VerifySudoRequest):
    """
    Verify sudo password by running 'sudo -S -v'
    """
    import subprocess
    try:
        # Run sudo -S -v which reads password from stdin and validates it
        # -S: read password from stdin
        # -v: validate timestamp (check password) without running a command
        # -k: kill timestamp first to force password prompt
        cmd = ["sudo", "-S", "-v", "-k"]
        
        process = subprocess.run(
            cmd,
            input=request.password + "\n",
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if process.returncode == 0:
            return {"success": True}
        else:
            return {"success": False, "error": "Incorrect password"}
            
    except Exception as e:
        logger.error(f"Sudo verification failed: {e}")
        return {"success": False, "error": str(e)}

@app.post("/api/scan")
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    scan_id = str(uuid.uuid4())
    scan_results[scan_id] = {
        "id": scan_id,
        "status": "running",
        "target": request.target,
        "ai_model": request.ai_model,
        "selected_tools": request.selected_tools
    }
    
    background_tasks.add_task(run_scan_task, scan_id, request.target, request.ai_model, request.selected_tools, request.sudo_password)
    return {"scan_id": scan_id}

@app.get("/api/scan/{scan_id}")
def get_scan_result(scan_id: str):
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan_results[scan_id]

@app.get("/api/history")
def get_scan_history():
    # Return list of scans (summary info)
    return list(scan_results.values())

@app.get("/api/tools")
def get_available_tools():
    """
    Return list of available scanning tools with installation status.
    """
    tools = detect_all_tools()
    return {"tools": tools}

@app.get("/api/scan/{scan_id}/download-pdf")
def download_pdf(scan_id: str):
    """
    Generate and download PDF report for a completed scan.
    """
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    scan_result = scan_results[scan_id]
    
    if scan_result['status'] != 'completed':
        raise HTTPException(status_code=400, detail="Scan not completed yet")
    
    try:
        # Pass the entire raw_data which contains tool_results
        pdf_buffer = generate_pdf_report(
            scan_result.get('raw_data', {}),
            scan_result.get('summary', ''),
            scan_result.get('target', 'Unknown')
        )
        
        return StreamingResponse(
            pdf_buffer,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=scan_report_{scan_id[:8]}.pdf"}
        )
    except Exception as e:
        logger.error(f"PDF generation failed: {e}")
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {str(e)}")

async def run_scan_task(scan_id, target, ai_model, selected_tools, sudo_password=None):
    logger.info(f"Task started for scan {scan_id} with AI model {ai_model} and tools: {selected_tools}")
    
    try:
        all_results = []
        vulnerability_aggregator = VulnerabilityAggregator()
        
        # Run each selected tool
        for tool_name in selected_tools:
            logger.info(f"Running {tool_name} scan...")
            
            try:
                scanner = get_scanner(tool_name, target, sudo_password)
                if scanner:
                    # Run scan in executor to avoid blocking
                    loop = asyncio.get_running_loop()
                    result = await loop.run_in_executor(None, scanner.scan)
                    
                    all_results.append(result)
                    
                    # Add vulnerabilities to aggregator
                    vulnerability_aggregator.add_from_tool_result(result)
                    
                    # Cleanup
                    scanner.cleanup()
                else:
                    logger.warning(f"Scanner not implemented for {tool_name}")
                    all_results.append({
                        "tool": tool_name,
                        "success": False,
                        "error": "Scanner not implemented"
                    })
            except Exception as e:
                logger.error(f"Error running {tool_name}: {e}")
                all_results.append({
                    "tool": tool_name,
                    "success": False,
                    "error": str(e)
                })
        
        # Aggregate vulnerabilities
        vulnerabilities = vulnerability_aggregator.get_aggregated_vulnerabilities()
        vuln_stats = vulnerability_aggregator.get_summary_stats()
        recommendations = vulnerability_aggregator.generate_recommendations()
        
        # Extract technologies from WhatWeb
        technologies = []
        for result in all_results:
            if result.get("tool") == "whatweb" and result.get("success"):
                technologies.extend(result.get("technologies", []))
        
        # Combine data for LLM
        combined_data = {
            "target": target,
            "tools_used": selected_tools,
            "tool_results": all_results,
            "vulnerabilities": vulnerabilities,
            "vulnerability_stats": vuln_stats,
            "recommendations": recommendations,
            "technologies": list(set(technologies))  # Deduplicate
        }
        
        # Generate AI summary with enhanced prompt
        summary = summarize_scan(combined_data, ai_model)
        
        # Extract ports and OS from results (primarily from nmap_tcp)
        ports = []
        os_detection = {}
        for result in all_results:
            if result.get("tool") == "nmap_tcp" and result.get("success"):
                ports = result.get("ports", [])
                os_detection = result.get("os_detection", {})
                break
        
        scan_results[scan_id].update({
            "status": "completed",
            "raw_data": combined_data,
            "summary": summary,
            "structured_data": {
                "ports": ports,
                "os_detection": os_detection,
                "vulnerabilities": vulnerabilities,
                "vulnerability_stats": vuln_stats,
                "vulnerabilities": vulnerabilities,
                "vulnerability_stats": vuln_stats,
                "recommendations": recommendations,
                "technologies": list(set(technologies))
            }
        })
        logger.info(f"Task completed for scan {scan_id}")
        
    except Exception as e:
        logger.error(f"Task failed for scan {scan_id}: {e}")
        scan_results[scan_id].update({
            "status": "failed",
            "error": str(e)
        })


