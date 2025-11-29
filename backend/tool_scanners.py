import subprocess
import json
import xml.etree.ElementTree as ET
import tempfile
import os
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

class ToolScanner:
    """Base class for all tool scanners"""
    
    def __init__(self, target, sudo_password=None):
        self.target = target
        self.sudo_password = sudo_password
        self.temp_dir = tempfile.mkdtemp(prefix="literecon_")
    
    def cleanup(self):
        """Clean up temporary files"""
        try:
            import shutil
            shutil.rmtree(self.temp_dir, ignore_errors=True)
        except Exception as e:
            logger.warning(f"Failed to cleanup temp dir: {e}")
            # Try with sudo if we have password (in case root created files)
            if self.sudo_password:
                try:
                    subprocess.run(
                        ["sudo", "-S", "rm", "-rf", self.temp_dir],
                        input=self.sudo_password + "\n",
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                except Exception as e2:
                    logger.error(f"Failed to cleanup with sudo: {e2}")
    
    def run_command(self, cmd, timeout=600):
        """Execute a command and return output"""
        try:
            # Prepare command with sudo if password provided
            run_cmd = cmd
            input_data = None
            
            if self.sudo_password:
                run_cmd = ["sudo", "-S"] + cmd
                input_data = self.sudo_password + "\n"
            
            logger.info(f"Running: {' '.join(run_cmd)}")
            result = subprocess.run(
                run_cmd,
                input=input_data,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=self.temp_dir
            )
            return {
                "success": result.returncode == 0,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode
            }
        except subprocess.TimeoutExpired:
            logger.error(f"Command timed out after {timeout}s")
            return {"success": False, "error": f"Timeout after {timeout}s"}
        except Exception as e:
            logger.error(f"Command failed: {e}")
            return {"success": False, "error": str(e)}


class NmapTCPScanner(ToolScanner):
    """Optimized Nmap TCP scanner with aggressive settings"""
    def scan(self):
        """Run optimized comprehensive TCP Nmap scan"""
        cmd = [
            "nmap", "-sS", "-Pn", "-A",
            "--script=default,vuln",
            "--version-intensity", "7",
            "--max-retries", "2",
            "--min-rate", "3000",
            "-T4", "-vv",
            "-oX", os.path.join(self.temp_dir, "nmap_tcp.xml"),
            self.target
        ]
        
        result = self.run_command(cmd, timeout=1200)  # 20 min timeout for aggressive scan
        
        if result["success"]:
            xml_file = os.path.join(self.temp_dir, "nmap_tcp.xml")
            if os.path.exists(xml_file):
                return self._parse_nmap_xml(xml_file, "nmap_tcp")
        
        return {"tool": "nmap_tcp", "success": False, "error": result.get("error", "Scan failed")}
    
    def _parse_nmap_xml(self, xml_file, tool_name):
        """Parse Nmap XML output"""
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            data = {
                "tool": tool_name,
                "success": True,
                "ports": [],
                "os_detection": {},
                "vulnerabilities": [],
                "scripts": []
            }
            
            for host in root.findall('.//host'):
                # Parse ports
                for port in host.findall('.//port'):
                    port_id = port.get('portid')
                    protocol = port.get('protocol')
                    state = port.find('state')
                    service = port.find('service')
                    
                    if state is not None and state.get('state') == 'open':
                        port_data = {
                            "port": int(port_id),
                            "protocol": protocol,
                            "state": "open",
                            "service": service.get('name', 'unknown') if service is not None else 'unknown',
                            "product": service.get('product', '') if service is not None else '',
                            "version": service.get('version', '') if service is not None else '',
                            "extrainfo": service.get('extrainfo', '') if service is not None else '',
                            "cpe": service.find('cpe').text if service is not None and service.find('cpe') is not None else ''
                        }
                        data["ports"].append(port_data)
                        
                        # Parse scripts for vulnerabilities and general info
                        for script in port.findall('.//script'):
                            script_id = script.get('id')
                            script_output = script.get('output', '')
                            
                            if 'vuln' in script_id or 'cve' in script_id.lower():
                                data["vulnerabilities"].append({
                                    "source": tool_name,
                                    "port": int(port_id),
                                    "script": script_id,
                                    "description": script_output[:500],
                                    "severity": self._determine_severity(script_output),
                                    "references": self._extract_references(script_output)
                                })
                            else:
                                # Add other scripts to scripts list
                                data["scripts"].append({
                                    "id": script_id,
                                    "output": script_output[:300],
                                    "severity": "Info"
                                })
                
                # Parse OS detection
                os_match = host.find('.//osmatch')
                if os_match is not None:
                    # Extract CPE and device type
                    cpe_elem = os_match.find('.//osclass/cpe')
                    osclass = os_match.find('.//osclass')
                    
                    data["os_detection"] = {
                        "name": os_match.get('name', 'Unknown'),
                        "accuracy": os_match.get('accuracy', '0'),
                        "cpe": cpe_elem.text if cpe_elem is not None else 'N/A',
                        "device_type": osclass.get('type', 'general purpose') if osclass is not None else 'general purpose'
                    }
            
            return data
        except Exception as e:
            logger.error(f"Failed to parse Nmap XML: {e}")
            return {"tool": tool_name, "success": False, "error": str(e)}
    
    def _determine_severity(self, text):
        """Determine vulnerability severity from text"""
        text_lower = text.lower()
        if any(word in text_lower for word in ['critical', 'rce', 'remote code execution']):
            return 'Critical'
        elif any(word in text_lower for word in ['high', 'exploit']):
            return 'High'
        elif any(word in text_lower for word in ['medium', 'moderate']):
            return 'Medium'
        elif any(word in text_lower for word in ['low', 'info']):
            return 'Low'
        return 'Info'
    
    def _extract_references(self, text):
        """Extract CVE or other references from script output"""
        import re
        cves = re.findall(r'CVE-\d{4}-\d{4,7}', text)
        if cves:
            return ', '.join(cves[:3])  # Limit to 3 CVEs
        return '-'


class NmapUDPScanner(ToolScanner):
    """Nmap UDP scanner for top ports"""
    def scan(self):
        """Run UDP scan for top 200 ports"""
        cmd = [
            "nmap", "-sU", "-Pn",
            "--top-ports", "200",
            "--max-retries", "2",
            "-T3", "-vv",
            "-oX", os.path.join(self.temp_dir, "nmap_udp.xml"),
            self.target
        ]
        
        result = self.run_command(cmd, timeout=1800)  # 30 min timeout for UDP
        
        if result["success"]:
            xml_file = os.path.join(self.temp_dir, "nmap_udp.xml")
            if os.path.exists(xml_file):
                return self._parse_nmap_xml(xml_file)
        
        return {"tool": "nmap_udp", "success": False, "error": result.get("error", "Scan failed")}
    
    def _parse_nmap_xml(self, xml_file):
        """Parse Nmap UDP XML output"""
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            data = {
                "tool": "nmap_udp",
                "success": True,
                "ports": [],
                "scripts": []
            }
            
            for host in root.findall('.//host'):
                for port in host.findall('.//port'):
                    port_id = port.get('portid')
                    protocol = port.get('protocol')
                    state = port.find('state')
                    service = port.find('service')
                    
                    if state is not None and state.get('state') in ['open', 'open|filtered']:
                        port_data = {
                            "port": int(port_id),
                            "protocol": protocol,
                            "state": state.get('state'),
                            "service": service.get('name', 'unknown') if service is not None else 'unknown',
                            "product": service.get('product', '') if service is not None else '',
                            "version": service.get('version', '') if service is not None else '',
                            "reason": state.get('reason', 'udp-response')
                        }
                        data["ports"].append(port_data)
                        
                        # Parse UDP scripts
                        for script in port.findall('.//script'):
                            script_id = script.get('id')
                            script_output = script.get('output', '')
                            data["scripts"].append({
                                "id": script_id,
                                "output": script_output[:300]
                            })
            
            return data
        except Exception as e:
            logger.error(f"Failed to parse Nmap UDP XML: {e}")
            return {"tool": "nmap_udp", "success": False, "error": str(e)}


class WhatWebScanner(ToolScanner):
    """WhatWeb for web technology fingerprinting"""
    def scan(self):
        """Run WhatWeb with aggressive mode"""
        log_file = os.path.join(self.temp_dir, "whatweb.log")
        cmd = [
            "whatweb",
            "-a", "3",
            "--user-agent", "Mozilla/5.0",
            "--no-errors", "--color=never",
            self.target
        ]
        
        result = self.run_command(cmd, timeout=180)
        
        if result["success"]:
            return {
                "tool": "whatweb",
                "success": True,
                "output": result["stdout"],
                "technologies": self._parse_whatweb_output(result["stdout"])
            }
        
        return {"tool": "whatweb", "success": False, "error": result.get("error", "Scan failed")}
    
    def _parse_whatweb_output(self, output):
        """Parse WhatWeb output for technologies"""
        technologies = []
        for line in output.split('\n'):
            if '[' in line and ']' in line:
                parts = line.split('[')
                for part in parts[1:]:
                    if ']' in part:
                        tech = part.split(']')[0]
                        technologies.append(tech)
        return technologies


class FeroxbusterScanner(ToolScanner):
    """Feroxbuster for recursive directory/file brute-forcing"""
    def scan(self):
        """Run Feroxbuster with extensions"""
        output_file = os.path.join(self.temp_dir, "feroxbuster.txt")
        cmd = [
            "feroxbuster",
            "-u", f"http://{self.target}/",
            "-t", "10",
            "--depth", "5",
            "-x", "php,html,txt",
            "-o", output_file
        ]
        
        result = self.run_command(cmd, timeout=900)
        
        if result["success"] or os.path.exists(output_file):
            return {
                "tool": "feroxbuster",
                "success": True,
                "output": result["stdout"],
                "findings": self._parse_feroxbuster_output(result["stdout"])
            }
        
        return {"tool": "feroxbuster", "success": False, "error": result.get("error", "Scan failed")}
    
    def _parse_feroxbuster_output(self, output):
        """Parse Feroxbuster output for discovered paths"""
        findings = []
        for line in output.split('\n'):
            if line.strip() and any(code in line for code in ['200', '301', '302', '403']):
                findings.append(line.strip())
        return findings


class Enum4LinuxScanner(ToolScanner):
    """Enum4linux-ng for comprehensive SMB/NetBIOS enumeration"""
    def scan(self):
        """Run Enum4linux-ng"""
        cmd = ["enum4linux-ng", "-A", "--timeout", "10", self.target]
        
        result = self.run_command(cmd, timeout=600)
        
        if result["success"]:
            return {
                "tool": "enum4linux-ng",
                "success": True,
                "output": result["stdout"],
                "findings": self._parse_enum4linux_output(result["stdout"])
            }
        
        return {"tool": "enum4linux-ng", "success": False, "error": result.get("error", "Scan failed")}
    
    def _parse_enum4linux_output(self, output):
        """Parse Enum4linux output for key findings"""
        findings = {
            "users": [],
            "shares": [],
            "groups": []
        }
        
        lines = output.split('\n')
        for i, line in enumerate(lines):
            if 'user:' in line.lower():
                findings["users"].append(line.strip())
            elif 'share:' in line.lower() or 'disk' in line.lower():
                findings["shares"].append(line.strip())
            elif 'group:' in line.lower():
                findings["groups"].append(line.strip())
        
        return findings


class SSLyzeScanner(ToolScanner):
    """SSLyze for detailed TLS/SSL analysis"""
    def scan(self):
        """Run SSLyze with JSON output"""
        json_file = os.path.join(self.temp_dir, "sslyze.json")
        cmd = [
            "sslyze",
            "--sslv2", "--sslv3", "--tlsv1", "--tlsv1_1", "--tlsv1_2", "--tlsv1_3",
            "--heartbleed", "--robot", "--resum", "--reneg", "--certinfo",
            f"{self.target}:443",
            "--json_out", json_file
        ]
        
        result = self.run_command(cmd, timeout=180)
        
        if result["success"] and os.path.exists(json_file):
            return self._parse_sslyze_json(json_file)
        
        return {"tool": "sslyze", "success": False, "error": result.get("error", "Scan failed")}
    
    def _parse_sslyze_json(self, json_file):
        """Parse SSLyze JSON output"""
        try:
            with open(json_file, 'r') as f:
                data = json.load(f)
            
            vulnerabilities = []
            # Extract SSL/TLS issues from JSON
            if 'server_scan_results' in data:
                for server in data['server_scan_results']:
                    scan_commands = server.get('scan_commands_results', {})
                    
                    # Check for weak ciphers, protocols, etc.
                    for cmd_name, cmd_result in scan_commands.items():
                        if 'error' in str(cmd_result).lower() or 'vulnerable' in str(cmd_result).lower():
                            vulnerabilities.append({
                                "source": "sslyze",
                                "check": cmd_name,
                                "description": str(cmd_result)[:200],
                                "severity": "Medium"
                            })
            
            return {
                "tool": "sslyze",
                "success": True,
                "vulnerabilities": vulnerabilities,
                "raw_data": data
            }
        except Exception as e:
            logger.error(f"Failed to parse SSLyze JSON: {e}")
            return {"tool": "sslyze", "success": False, "error": str(e)}


class NbtscanScanner(ToolScanner):
    """Nbtscan for NetBIOS name scanning"""
    def scan(self):
        """Run nbtscan"""
        # Handle both single IP and subnet
        target = self.target if '/' in self.target else f"{self.target}/24"
        cmd = ["nbtscan", target]
        
        result = self.run_command(cmd, timeout=120)
        
        if result["success"]:
            return {
                "tool": "nbtscan",
                "success": True,
                "output": result["stdout"],
                "hosts": self._parse_nbtscan_output(result["stdout"])
            }
        
        return {"tool": "nbtscan", "success": False, "error": result.get("error", "Scan failed")}
    
    def _parse_nbtscan_output(self, output):
        """Parse nbtscan output"""
        hosts = []
        for line in output.split('\n'):
            if line.strip() and not line.startswith('Doing'):
                hosts.append(line.strip())
        return hosts


class OneSixtyOneScanner(ToolScanner):
    """Onesixtyone for SNMP community brute-forcing"""
    def scan(self):
        """Run onesixtyone"""
        wordlist = "/usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt"
        
        # Fallback wordlist if SecLists not installed
        if not os.path.exists(wordlist):
            wordlist = "/usr/share/wordlists/metasploit/snmp_default_pass.txt"
        
        cmd = ["onesixtyone", "-c", wordlist, self.target]
        
        result = self.run_command(cmd, timeout=120)
        
        if result["success"]:
            return {
                "tool": "onesixtyone",
                "success": True,
                "output": result["stdout"],
                "communities": self._parse_onesixtyone_output(result["stdout"])
            }
        
        return {"tool": "onesixtyone", "success": False, "error": result.get("error", "Scan failed")}
    
    def _parse_onesixtyone_output(self, output):
        """Parse onesixtyone output for found communities"""
        communities = []
        for line in output.split('\n'):
            if '[' in line and ']' in line:
                communities.append(line.strip())
        return communities


class SnmpwalkScanner(ToolScanner):
    """Snmpwalk for exhaustive SNMP MIB walking"""
    def scan(self):
        """Run snmpwalk"""
        cmd = ["snmpwalk", "-v2c", "-c", "public", self.target]
        
        result = self.run_command(cmd, timeout=300)
        
        if result["success"]:
            return {
                "tool": "snmpwalk",
                "success": True,
                "output": result["stdout"][:5000],  # Limit output size
                "oid_count": len(result["stdout"].split('\n'))
            }
        
        return {"tool": "snmpwalk", "success": False, "error": result.get("error", "Scan failed")}


class SnmpwalkV1Scanner(ToolScanner):
    """Snmpwalk v1"""
    def scan(self):
        """Run snmpwalk v1"""
        cmd = ["snmpwalk", "-v1", "-c", "public", self.target]
        
        result = self.run_command(cmd, timeout=300)
        
        if result["success"]:
            return {
                "tool": "snmpwalk_v1",
                "success": True,
                "output": result["stdout"][:5000],  # Limit output size
                "oid_count": len(result["stdout"].split('\n'))
            }
        
        return {"tool": "snmpwalk_v1", "success": False, "error": result.get("error", "Scan failed")}


class DnsreconScanner(ToolScanner):
    """Dnsrecon for reverse DNS and zone checks"""
    def scan(self):
        """Run dnsrecon"""
        # Handle both single IP and subnet
        if '/' in self.target:
             cmd = ["dnsrecon", "-r", self.target]
        else:
             cmd = ["dnsrecon", "-d", self.target]
        
        result = self.run_command(cmd, timeout=180)
        
        if result["success"]:
            return {
                "tool": "dnsrecon",
                "success": True,
                "output": result["stdout"],
                "records": self._parse_dnsrecon_output(result["stdout"])
            }
        
        return {"tool": "dnsrecon", "success": False, "error": result.get("error", "Scan failed")}
    
    def _parse_dnsrecon_output(self, output):
        """Parse dnsrecon output"""
        records = []
        for line in output.split('\n'):
            if 'PTR' in line or 'A' in line or 'CNAME' in line:
                records.append(line.strip())
        return records


class AutoreconScanner(ToolScanner):
    """Autorecon for automated multi-tool enumeration"""
    def scan(self):
        """Run autorecon"""
        output_dir = os.path.join(self.temp_dir, "autorecon_results")
        cmd = ["autorecon", "-v", "--single-target", self.target, "-o", output_dir]
        
        result = self.run_command(cmd, timeout=3600)  # 1 hour timeout
        
        if result["success"] or os.path.exists(output_dir):
            return {
                "tool": "autorecon",
                "success": True,
                "output": result["stdout"],
                "output_dir": output_dir,
                "summary": "Autorecon completed. Check output directory for detailed results."
            }
        
        return {"tool": "autorecon", "success": False, "error": result.get("error", "Scan failed")}



class FeroxbusterHTTPSScanner(ToolScanner):
    """Feroxbuster for recursive directory/file brute-forcing (HTTPS)"""
    def scan(self):
        """Run Feroxbuster with extensions over HTTPS"""
        output_file = os.path.join(self.temp_dir, "feroxbuster_https.txt")
        cmd = [
            "feroxbuster",
            "-u", f"https://{self.target}/",
            "-t", "10",
            "--depth", "5",
            "-x", "php,html,txt",
            "-k",  # Ignore SSL errors
            "-o", output_file
        ]
        
        result = self.run_command(cmd, timeout=900)
        
        if result["success"] or os.path.exists(output_file):
            return {
                "tool": "feroxbuster_https",
                "success": True,
                "output": result["stdout"],
                "findings": self._parse_feroxbuster_output(result["stdout"])
            }
        
        return {"tool": "feroxbuster_https", "success": False, "error": result.get("error", "Scan failed")}
    
    def _parse_feroxbuster_output(self, output):
        """Parse Feroxbuster output for discovered paths"""
        findings = []
        for line in output.split('\n'):
            if line.strip() and any(code in line for code in ['200', '301', '302', '403']):
                findings.append(line.strip())
        return findings


class Enum4LinuxClassicScanner(ToolScanner):
    """Enum4linux classic for SMB enumeration"""
    def scan(self):
        """Run Enum4linux classic"""
        cmd = ["enum4linux", "-a", self.target]
        
        result = self.run_command(cmd, timeout=600)
        
        if result["success"]:
            return {
                "tool": "enum4linux_classic",
                "success": True,
                "output": result["stdout"],
                "findings": self._parse_enum4linux_output(result["stdout"])
            }
        
        return {"tool": "enum4linux_classic", "success": False, "error": result.get("error", "Scan failed")}
    
    def _parse_enum4linux_output(self, output):
        """Parse Enum4linux output for key findings"""
        findings = {
            "users": [],
            "shares": [],
            "groups": []
        }
        
        lines = output.split('\n')
        for i, line in enumerate(lines):
            if 'user:' in line.lower():
                findings["users"].append(line.strip())
            elif 'share:' in line.lower() or 'disk' in line.lower():
                findings["shares"].append(line.strip())
            elif 'group:' in line.lower():
                findings["groups"].append(line.strip())
        
        return findings


# Factory function to get scanner instance
def get_scanner(tool_name, target, sudo_password=None):
    """Get scanner instance for a tool"""
    scanners = {
        "nmap_tcp": NmapTCPScanner,
        "nmap_udp": NmapUDPScanner,
        "whatweb": WhatWebScanner,
        "feroxbuster": FeroxbusterScanner,
        "feroxbuster_https": FeroxbusterHTTPSScanner,
        "enum4linux-ng": Enum4LinuxScanner,
        "enum4linux_classic": Enum4LinuxClassicScanner,
        "sslyze": SSLyzeScanner,
        "nbtscan": NbtscanScanner,
        "onesixtyone": OneSixtyOneScanner,
        "snmpwalk": SnmpwalkScanner,
        "snmpwalk_v1": SnmpwalkV1Scanner,
        "dnsrecon": DnsreconScanner,
        "autorecon": AutoreconScanner
    }
    
    scanner_class = scanners.get(tool_name)
    if scanner_class:
        return scanner_class(target, sudo_password)
    return None
