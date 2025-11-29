import subprocess
import shutil
import logging

logger = logging.getLogger(__name__)

# Define all supported tools with their detection commands
SUPPORTED_TOOLS = {
    "nmap_tcp": {
        "name": "Nmap TCP",
        "description": "Optimized aggressive TCP port scanner with deep service detection",
        "check_cmd": ["nmap", "--version"],
        "category": "port_scanner"
    },
    "nmap_udp": {
        "name": "Nmap UDP",
        "description": "UDP port scanner for top 200 ports",
        "check_cmd": ["nmap", "--version"],
        "category": "port_scanner"
    },
    "whatweb": {
        "name": "WhatWeb",
        "description": "Web technology fingerprinting - CMS/plugin detection",
        "check_cmd": ["whatweb", "--version"],
        "category": "web_scanner"
    },
    "feroxbuster": {
        "name": "Feroxbuster (HTTP)",
        "description": "Recursive directory/file brute-forcer (HTTP)",
        "check_cmd": ["feroxbuster", "--version"],
        "category": "web_scanner"
    },
    "feroxbuster_https": {
        "name": "Feroxbuster (HTTPS)",
        "description": "Recursive directory/file brute-forcer (HTTPS)",
        "check_cmd": ["feroxbuster", "--version"],
        "category": "web_scanner"
    },
    "enum4linux-ng": {
        "name": "Enum4Linux-ng",
        "description": "Comprehensive SMB/NetBIOS enumeration - users, shares, policies",
        "check_cmd": ["enum4linux-ng", "--version"],
        "category": "smb_scanner"
    },
    "enum4linux_classic": {
        "name": "Enum4Linux Classic",
        "description": "Classic SMB enumeration tool",
        "check_cmd": ["enum4linux"],  # enum4linux doesn't have a version flag that exits cleanly sometimes, just check binary
        "category": "smb_scanner"
    },
    "sslyze": {
        "name": "SSLyze",
        "description": "Detailed TLS/SSL analysis - cipher suites, cert issues",
        "check_cmd": ["sslyze", "--version"],
        "category": "ssl_scanner"
    },
    "nbtscan": {
        "name": "Nbtscan",
        "description": "NetBIOS name scanning for subnet discovery",
        "check_cmd": ["nbtscan", "-h"],
        "category": "netbios_scanner"
    },
    "onesixtyone": {
        "name": "Onesixtyone",
        "description": "SNMP community brute-forcing",
        "check_cmd": ["onesixtyone", "-h"],
        "category": "snmp_scanner"
    },
    "snmpwalk": {
        "name": "Snmpwalk (v2c)",
        "description": "Exhaustive SNMP MIB walking (v2c)",
        "check_cmd": ["snmpwalk", "-V"],
        "category": "snmp_scanner"
    },
    "snmpwalk_v1": {
        "name": "Snmpwalk (v1)",
        "description": "Exhaustive SNMP MIB walking (v1)",
        "check_cmd": ["snmpwalk", "-V"],
        "category": "snmp_scanner"
    },
    "dnsrecon": {
        "name": "Dnsrecon",
        "description": "Reverse DNS and zone transfer checks",
        "check_cmd": ["dnsrecon", "-h"],
        "category": "dns_scanner"
    },
    "autorecon": {
        "name": "AutoRecon",
        "description": "Automated multi-tool enumeration orchestrator",
        "check_cmd": ["autorecon", "--version"],
        "category": "automation"
    }
}

def check_tool_installed(tool_id):
    """
    Check if a specific tool is installed and accessible.
    Returns dict with availability status and path.
    """
    tool_info = SUPPORTED_TOOLS.get(tool_id)
    if not tool_info:
        return {"available": False, "error": "Unknown tool"}
    
    # Try using shutil.which first (faster)
    tool_path = shutil.which(tool_id)
    if tool_path:
        return {
            "available": True,
            "path": tool_path,
            "name": tool_info["name"],
            "description": tool_info["description"],
            "category": tool_info["category"]
        }
    
    # Fallback: try running version command
    try:
        result = subprocess.run(
            tool_info["check_cmd"],
            capture_output=True,
            timeout=5,
            text=True
        )
        if result.returncode == 0:
            return {
                "available": True,
                "path": tool_id,
                "name": tool_info["name"],
                "description": tool_info["description"],
                "category": tool_info["category"]
            }
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
        logger.debug(f"Tool {tool_id} not found: {e}")
    
    return {
        "available": False,
        "name": tool_info["name"],
        "description": tool_info["description"],
        "category": tool_info["category"],
        "error": "Not installed or not in PATH"
    }

def detect_all_tools():
    """
    Detect all supported scanning tools.
    Returns dict with tool availability status.
    """
    logger.info("Detecting available scanning tools...")
    results = {}
    
    for tool_id in SUPPORTED_TOOLS.keys():
        results[tool_id] = check_tool_installed(tool_id)
        status = "✓" if results[tool_id]["available"] else "✗"
        logger.info(f"{status} {tool_id}: {results[tool_id].get('name', 'Unknown')}")
    
    available_count = sum(1 for tool in results.values() if tool["available"])
    logger.info(f"Found {available_count}/{len(SUPPORTED_TOOLS)} tools installed")
    
    return results

def get_available_tools():
    """
    Get list of only available tools.
    """
    all_tools = detect_all_tools()
    return {k: v for k, v in all_tools.items() if v["available"]}
