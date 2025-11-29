"""
Report Parsers Module

This module contains specialized parsers for each scanning tool.
Each parser extracts structured data from raw tool outputs and generates
table data with appropriate columns for PDF report generation.
"""

import re
import json
import logging
from typing import Dict, List, Any, Optional
import xml.etree.ElementTree as ET

logger = logging.getLogger(__name__)


class BaseParser:
    """Base class for all report parsers"""
    
    def __init__(self, tool_result: Dict[str, Any]):
        self.tool_result = tool_result
        self.tool_name = tool_result.get("tool", "unknown")
        self.success = tool_result.get("success", False)
    
    def parse(self) -> Dict[str, Any]:
        """Parse tool result and return structured table data"""
        raise NotImplementedError("Subclasses must implement parse()")
    
    def _create_no_data_table(self, table_name: str, columns: List[str]) -> Dict[str, Any]:
        """Create a table with a single 'No Data' row"""
        return {
            "name": table_name,
            "columns": columns,
            "rows": [["No Data"] + [""] * (len(columns) - 1)]
        }


class NmapTCPParser(BaseParser):
    """Parser for Nmap TCP scan results"""
    
    def parse(self) -> Dict[str, Any]:
        """Parse Nmap TCP results into 3 tables"""
        tables = []
        
        # Table 1: Open Ports
        ports_table = self._parse_ports_table()
        tables.append(ports_table)
        
        # Table 2: OS Detection
        os_table = self._parse_os_detection_table()
        tables.append(os_table)
        
        # Table 3: Vulnerabilities/Script Results
        vuln_table = self._parse_vulnerabilities_table()
        tables.append(vuln_table)
        
        return {
            "tool": self.tool_name,
            "tables": tables
        }
    
    def _parse_ports_table(self) -> Dict[str, Any]:
        """Parse open ports into table format"""
        columns = ["Port", "Protocol", "State", "Service", "Version", "Extra Info"]
        
        if not self.success:
            return self._create_no_data_table("Open Ports", columns)
        
        ports = self.tool_result.get("ports", [])
        if not ports:
            return self._create_no_data_table("Open Ports", columns)
        
        rows = []
        for port in ports:
            version_info = f"{port.get('product', '')} {port.get('version', '')}".strip()
            extra_info = port.get('extrainfo', '') or port.get('cpe', '')
            
            rows.append([
                str(port.get('port', '')),
                port.get('protocol', 'tcp').upper(),
                port.get('state', 'open'),
                port.get('service', 'unknown'),
                version_info or 'N/A',
                extra_info or '-'
            ])
        
        return {
            "name": "Open Ports",
            "columns": columns,
            "rows": rows
        }
    
    def _parse_os_detection_table(self) -> Dict[str, Any]:
        """Parse OS detection into table format"""
        columns = ["OS Type", "Accuracy (%)", "CPE", "Device Type"]
        
        if not self.success:
            return self._create_no_data_table("OS Detection", columns)
        
        os_detection = self.tool_result.get("os_detection", {})
        if not os_detection:
            return self._create_no_data_table("OS Detection", columns)
        
        rows = [[
            os_detection.get('name', 'Unknown'),
            os_detection.get('accuracy', '0'),
            os_detection.get('cpe', 'N/A'),
            os_detection.get('device_type', 'general purpose')
        ]]
        
        return {
            "name": "OS Detection",
            "columns": columns,
            "rows": rows
        }
    
    def _parse_vulnerabilities_table(self) -> Dict[str, Any]:
        """Parse vulnerability/script results into table format"""
        columns = ["Script Name", "Severity", "Description", "References"]
        
        if not self.success:
            return self._create_no_data_table("Vulnerabilities/Script Results", columns)
        
        vulnerabilities = self.tool_result.get("vulnerabilities", [])
        scripts = self.tool_result.get("scripts", [])
        
        if not vulnerabilities and not scripts:
            return self._create_no_data_table("Vulnerabilities/Script Results", columns)
        
        rows = []
        
        # Add vulnerabilities
        for vuln in vulnerabilities:
            rows.append([
                vuln.get('script', 'N/A'),
                vuln.get('severity', 'Info'),
                vuln.get('description', '')[:200],  # Truncate long descriptions
                vuln.get('references', '-')
            ])
        
        # Add script results
        for script in scripts:
            rows.append([
                script.get('id', 'N/A'),
                script.get('severity', 'Info'),
                script.get('output', '')[:200],
                '-'
            ])
        
        if not rows:
            return self._create_no_data_table("Vulnerabilities/Script Results", columns)
        
        return {
            "name": "Vulnerabilities/Script Results",
            "columns": columns,
            "rows": rows
        }


class NmapUDPParser(BaseParser):
    """Parser for Nmap UDP scan results"""
    
    def parse(self) -> Dict[str, Any]:
        """Parse Nmap UDP results into 2 tables"""
        tables = []
        
        # Table 1: UDP Ports
        ports_table = self._parse_udp_ports_table()
        tables.append(ports_table)
        
        # Table 2: UDP Script Results
        scripts_table = self._parse_udp_scripts_table()
        tables.append(scripts_table)
        
        return {
            "tool": self.tool_name,
            "tables": tables
        }
    
    def _parse_udp_ports_table(self) -> Dict[str, Any]:
        """Parse UDP ports into table format"""
        columns = ["Port", "State", "Service", "Version", "Reason"]
        
        if not self.success:
            return self._create_no_data_table("UDP Ports", columns)
        
        ports = self.tool_result.get("ports", [])
        if not ports:
            return self._create_no_data_table("UDP Ports", columns)
        
        rows = []
        for port in ports:
            version_info = f"{port.get('product', '')} {port.get('version', '')}".strip()
            
            rows.append([
                str(port.get('port', '')),
                port.get('state', 'open|filtered'),
                port.get('service', 'unknown'),
                version_info or 'N/A',
                port.get('reason', 'udp-response')
            ])
        
        return {
            "name": "UDP Ports",
            "columns": columns,
            "rows": rows
        }
    
    def _parse_udp_scripts_table(self) -> Dict[str, Any]:
        """Parse UDP script results into table format"""
        columns = ["Script Name", "Output/Details"]
        
        if not self.success:
            return self._create_no_data_table("UDP Script Results", columns)
        
        scripts = self.tool_result.get("scripts", [])
        if not scripts:
            return self._create_no_data_table("UDP Script Results", columns)
        
        rows = []
        for script in scripts:
            rows.append([
                script.get('id', 'N/A'),
                script.get('output', '')[:300]  # Truncate long outputs
            ])
        
        return {
            "name": "UDP Script Results",
            "columns": columns,
            "rows": rows
        }


class WhatWebParser(BaseParser):
    """Parser for WhatWeb scan results"""
    
    def parse(self) -> Dict[str, Any]:
        """Parse WhatWeb results into 1 table"""
        tables = []
        
        # Table 1: Web Technologies
        tech_table = self._parse_technologies_table()
        tables.append(tech_table)
        
        return {
            "tool": self.tool_name,
            "tables": tables
        }
    
    def _parse_technologies_table(self) -> Dict[str, Any]:
        """Parse web technologies into table format"""
        columns = ["Plugin/Category", "Details", "Certainty/Notes"]
        
        if not self.success:
            return self._create_no_data_table("Web Technologies", columns)
        
        technologies = self.tool_result.get("technologies", [])
        output = self.tool_result.get("output", "")
        
        if not technologies and not output:
            return self._create_no_data_table("Web Technologies", columns)
        
        rows = []
        
        # Parse technologies from list
        for tech in technologies:
            # Parse format like "HTTPServer: Apache/2.4.7"
            if ':' in tech:
                parts = tech.split(':', 1)
                category = parts[0].strip()
                details = parts[1].strip() if len(parts) > 1 else ''
                rows.append([category, details, 'Detected'])
            else:
                rows.append([tech, '', 'Detected'])
        
        if not rows:
            return self._create_no_data_table("Web Technologies", columns)
        
        return {
            "name": "Web Technologies",
            "columns": columns,
            "rows": rows
        }


class FeroxbusterParser(BaseParser):
    """Parser for Feroxbuster scan results"""
    
    def parse(self) -> Dict[str, Any]:
        """Parse Feroxbuster results into 1 table"""
        tables = []
        
        # Table 1: Discovered Resources
        resources_table = self._parse_resources_table()
        tables.append(resources_table)
        
        return {
            "tool": self.tool_name,
            "tables": tables
        }
    
    def _parse_resources_table(self) -> Dict[str, Any]:
        """Parse discovered resources into table format"""
        columns = ["Status", "Method", "Lines", "Words", "Chars", "URL/Path"]
        
        if not self.success:
            return self._create_no_data_table("Discovered Resources", columns)
        
        findings = self.tool_result.get("findings", [])
        output = self.tool_result.get("output", "")
        
        if not findings and not output:
            return self._create_no_data_table("Discovered Resources", columns)
        
        rows = []
        
        # Parse findings (format: "200 GET 41l 104w 1539c http://example.com/")
        for finding in findings:
            match = re.search(r'(\d{3})\s+(\w+)\s+(\d+)l\s+(\d+)w\s+(\d+)c\s+(.+)', finding)
            if match:
                rows.append([
                    match.group(1),  # Status code
                    match.group(2),  # Method
                    match.group(3),  # Lines
                    match.group(4),  # Words
                    match.group(5),  # Characters
                    match.group(6)   # URL
                ])
        
        # Also parse from output if findings is empty
        if not rows and output:
            for line in output.split('\n'):
                match = re.search(r'(\d{3})\s+(\w+)\s+(\d+)l\s+(\d+)w\s+(\d+)c\s+(.+)', line)
                if match:
                    rows.append([
                        match.group(1),
                        match.group(2),
                        match.group(3),
                        match.group(4),
                        match.group(5),
                        match.group(6)
                    ])
        
        if not rows:
            return self._create_no_data_table("Discovered Resources", columns)
        
        return {
            "name": "Discovered Resources",
            "columns": columns,
            "rows": rows[:50]  # Limit to 50 entries
        }


class Enum4LinuxParser(BaseParser):
    """Parser for Enum4linux-ng scan results"""
    
    def parse(self) -> Dict[str, Any]:
        """Parse Enum4linux results into 3 tables"""
        tables = []
        
        # Table 1: SMB Users
        users_table = self._parse_users_table()
        tables.append(users_table)
        
        # Table 2: SMB Shares
        shares_table = self._parse_shares_table()
        tables.append(shares_table)
        
        # Table 3: Password Policy
        policy_table = self._parse_password_policy_table()
        tables.append(policy_table)
        
        return {
            "tool": self.tool_name,
            "tables": tables
        }
    
    def _parse_users_table(self) -> Dict[str, Any]:
        """Parse SMB users into table format"""
        columns = ["Username", "RID", "Description", "Flags"]
        
        if not self.success:
            return self._create_no_data_table("SMB Users", columns)
        
        findings = self.tool_result.get("findings", {})
        users = findings.get("users", [])
        
        if not users:
            return self._create_no_data_table("SMB Users", columns)
        
        rows = []
        for user in users:
            # Parse format like "user:[username] rid:[0x1f4]"
            username = re.search(r'user:\[([^\]]+)\]', user)
            rid = re.search(r'rid:\[([^\]]+)\]', user)
            
            rows.append([
                username.group(1) if username else 'N/A',
                rid.group(1) if rid else 'N/A',
                '',  # Description not typically in output
                ''   # Flags not typically in output
            ])
        
        if not rows:
            return self._create_no_data_table("SMB Users", columns)
        
        return {
            "name": "SMB Users",
            "columns": columns,
            "rows": rows
        }
    
    def _parse_shares_table(self) -> Dict[str, Any]:
        """Parse SMB shares into table format"""
        columns = ["Share Name", "Type", "Comment", "Permissions"]
        
        if not self.success:
            return self._create_no_data_table("SMB Shares", columns)
        
        findings = self.tool_result.get("findings", {})
        shares = findings.get("shares", [])
        
        if not shares:
            return self._create_no_data_table("SMB Shares", columns)
        
        rows = []
        for share in shares:
            # Parse format like "share:[IPC$] type:[IPC] comment:[IPC Service]"
            share_name = re.search(r'share:\[([^\]]+)\]', share)
            share_type = re.search(r'type:\[([^\]]+)\]', share)
            comment = re.search(r'comment:\[([^\]]+)\]', share)
            
            rows.append([
                share_name.group(1) if share_name else 'N/A',
                share_type.group(1) if share_type else 'Disk',
                comment.group(1) if comment else '',
                'Unknown'  # Permissions typically require additional enumeration
            ])
        
        if not rows:
            return self._create_no_data_table("SMB Shares", columns)
        
        return {
            "name": "SMB Shares",
            "columns": columns,
            "rows": rows
        }
    
    def _parse_password_policy_table(self) -> Dict[str, Any]:
        """Parse password policy into table format"""
        columns = ["Policy Item", "Value"]
        
        if not self.success:
            return self._create_no_data_table("Password Policy", columns)
        
        output = self.tool_result.get("output", "")
        
        if not output:
            return self._create_no_data_table("Password Policy", columns)
        
        rows = []
        
        # Parse common password policy items
        policy_patterns = {
            "Minimum Password Length": r'Minimum password length:\s*(\d+)',
            "Password Complexity": r'Password complexity:\s*(\w+)',
            "Lockout Threshold": r'Lockout threshold:\s*(\d+)',
            "Lockout Duration": r'Lockout duration:\s*(.+)',
            "Password History": r'Password history length:\s*(\d+)'
        }
        
        for policy_name, pattern in policy_patterns.items():
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                rows.append([policy_name, match.group(1)])
        
        if not rows:
            return self._create_no_data_table("Password Policy", columns)
        
        return {
            "name": "Password Policy",
            "columns": columns,
            "rows": rows
        }


class SSLyzeParser(BaseParser):
    """Parser for SSLyze scan results"""
    
    def parse(self) -> Dict[str, Any]:
        """Parse SSLyze results into 3 tables"""
        tables = []
        
        # Table 1: Supported Ciphers
        ciphers_table = self._parse_ciphers_table()
        tables.append(ciphers_table)
        
        # Table 2: Certificate Details
        cert_table = self._parse_certificate_table()
        tables.append(cert_table)
        
        # Table 3: Vulnerability Scan
        vuln_table = self._parse_vulnerability_scan_table()
        tables.append(vuln_table)
        
        return {
            "tool": self.tool_name,
            "tables": tables
        }
    
    def _parse_ciphers_table(self) -> Dict[str, Any]:
        """Parse supported ciphers into table format"""
        columns = ["Cipher Suite", "Protocol", "Preference", "Key Size"]
        
        if not self.success:
            return self._create_no_data_table("Supported Ciphers", columns)
        
        raw_data = self.tool_result.get("raw_data", {})
        
        if not raw_data:
            return self._create_no_data_table("Supported Ciphers", columns)
        
        rows = []
        
        # Parse cipher suites from SSLyze JSON structure
        server_results = raw_data.get("server_scan_results", [])
        for server in server_results:
            scan_commands = server.get("scan_commands_results", {})
            
            # Check various TLS version scan results
            for cmd_name, cmd_result in scan_commands.items():
                if 'tls' in cmd_name.lower() or 'ssl' in cmd_name.lower():
                    # Extract cipher information (structure varies by SSLyze version)
                    # This is a simplified parser
                    if isinstance(cmd_result, dict):
                        accepted_ciphers = cmd_result.get("accepted_cipher_suites", [])
                        for cipher in accepted_ciphers[:10]:  # Limit to 10
                            rows.append([
                                cipher.get("name", "Unknown"),
                                cmd_name.replace("_", " ").upper(),
                                "Preferred" if cipher.get("is_preferred", False) else "Accepted",
                                str(cipher.get("key_size", "N/A"))
                            ])
        
        if not rows:
            return self._create_no_data_table("Supported Ciphers", columns)
        
        return {
            "name": "Supported Ciphers",
            "columns": columns,
            "rows": rows
        }
    
    def _parse_certificate_table(self) -> Dict[str, Any]:
        """Parse certificate details into table format"""
        columns = ["Subject", "Issuer", "Validity", "Serial Number", "Signature Algorithm"]
        
        if not self.success:
            return self._create_no_data_table("Certificate Details", columns)
        
        raw_data = self.tool_result.get("raw_data", {})
        
        if not raw_data:
            return self._create_no_data_table("Certificate Details", columns)
        
        rows = []
        
        # Parse certificate information
        server_results = raw_data.get("server_scan_results", [])
        for server in server_results:
            scan_commands = server.get("scan_commands_results", {})
            cert_info = scan_commands.get("certificate_info", {})
            
            if cert_info:
                # Extract certificate details (simplified)
                cert_deployments = cert_info.get("certificate_deployments", [])
                for deployment in cert_deployments[:1]:  # Just first cert
                    received_cert = deployment.get("received_certificate_chain", [])
                    if received_cert:
                        cert = received_cert[0]
                        rows.append([
                            cert.get("subject", {}).get("rfc4514_string", "N/A")[:50],
                            cert.get("issuer", {}).get("rfc4514_string", "N/A")[:50],
                            f"{cert.get('not_valid_before', 'N/A')} to {cert.get('not_valid_after', 'N/A')}",
                            str(cert.get("serial_number", "N/A")),
                            cert.get("signature_algorithm_oid", {}).get("name", "N/A")
                        ])
        
        if not rows:
            return self._create_no_data_table("Certificate Details", columns)
        
        return {
            "name": "Certificate Details",
            "columns": columns,
            "rows": rows
        }
    
    def _parse_vulnerability_scan_table(self) -> Dict[str, Any]:
        """Parse vulnerability scan results into table format"""
        columns = ["Test Name", "Result", "Details"]
        
        if not self.success:
            return self._create_no_data_table("Vulnerability Scan", columns)
        
        vulnerabilities = self.tool_result.get("vulnerabilities", [])
        
        if not vulnerabilities:
            return self._create_no_data_table("Vulnerability Scan", columns)
        
        rows = []
        for vuln in vulnerabilities:
            rows.append([
                vuln.get("check", "Unknown"),
                "Vulnerable" if "vulnerable" in vuln.get("description", "").lower() else "Compliant",
                vuln.get("description", "")[:200]
            ])
        
        if not rows:
            return self._create_no_data_table("Vulnerability Scan", columns)
        
        return {
            "name": "Vulnerability Scan",
            "columns": columns,
            "rows": rows
        }


class NbtscanParser(BaseParser):
    """Parser for Nbtscan scan results"""
    
    def parse(self) -> Dict[str, Any]:
        """Parse Nbtscan results into 1 table"""
        tables = []
        
        # Table 1: NetBIOS Hosts
        hosts_table = self._parse_hosts_table()
        tables.append(hosts_table)
        
        return {
            "tool": self.tool_name,
            "tables": tables
        }
    
    def _parse_hosts_table(self) -> Dict[str, Any]:
        """Parse NetBIOS hosts into table format"""
        columns = ["IP Address", "NetBIOS Name", "Service/Type", "Flags", "MAC Address"]
        
        if not self.success:
            return self._create_no_data_table("NetBIOS Hosts", columns)
        
        hosts = self.tool_result.get("hosts", [])
        
        if not hosts:
            return self._create_no_data_table("NetBIOS Hosts", columns)
        
        rows = []
        for host in hosts:
            # Parse format like "192.168.1.1 WORKSTATION<00> GROUP MAC"
            parts = host.split()
            if len(parts) >= 2:
                ip = parts[0]
                netbios_name = parts[1] if len(parts) > 1 else 'N/A'
                service_type = parts[2] if len(parts) > 2 else ''
                flags = parts[3] if len(parts) > 3 else ''
                mac = parts[4] if len(parts) > 4 else ''
                
                rows.append([ip, netbios_name, service_type, flags, mac])
        
        if not rows:
            return self._create_no_data_table("NetBIOS Hosts", columns)
        
        return {
            "name": "NetBIOS Hosts",
            "columns": columns,
            "rows": rows
        }


class OneSixtyOneParser(BaseParser):
    """Parser for Onesixtyone scan results"""
    
    def parse(self) -> Dict[str, Any]:
        """Parse Onesixtyone results into 1 table"""
        tables = []
        
        # Table 1: SNMP Communities
        communities_table = self._parse_communities_table()
        tables.append(communities_table)
        
        return {
            "tool": self.tool_name,
            "tables": tables
        }
    
    def _parse_communities_table(self) -> Dict[str, Any]:
        """Parse SNMP communities into table format"""
        columns = ["IP Address", "Community String", "System Description"]
        
        if not self.success:
            return self._create_no_data_table("SNMP Communities", columns)
        
        communities = self.tool_result.get("communities", [])
        
        if not communities:
            return self._create_no_data_table("SNMP Communities", columns)
        
        rows = []
        for community in communities:
            # Parse format like "[192.168.1.1] (public) Linux 2.6.32"
            match = re.search(r'\[([^\]]+)\]\s*\(([^\)]+)\)\s*(.+)', community)
            if match:
                rows.append([
                    match.group(1),  # IP
                    match.group(2),  # Community string
                    match.group(3)   # System description
                ])
        
        if not rows:
            return self._create_no_data_table("SNMP Communities", columns)
        
        return {
            "name": "SNMP Communities",
            "columns": columns,
            "rows": rows
        }


class SnmpwalkParser(BaseParser):
    """Parser for Snmpwalk scan results"""
    
    def parse(self) -> Dict[str, Any]:
        """Parse Snmpwalk results into 1 table"""
        tables = []
        
        # Table 1: SNMP MIB
        mib_table = self._parse_mib_table()
        tables.append(mib_table)
        
        return {
            "tool": self.tool_name,
            "tables": tables
        }
    
    def _parse_mib_table(self) -> Dict[str, Any]:
        """Parse SNMP MIB data into table format"""
        columns = ["OID", "Type", "Value"]
        
        if not self.success:
            return self._create_no_data_table("SNMP MIB", columns)
        
        output = self.tool_result.get("output", "")
        
        if not output:
            return self._create_no_data_table("SNMP MIB", columns)
        
        rows = []
        
        # Parse format like "iso.3.6.1.2.1.1.1.0 = STRING: 'Linux server 5.4.0-42-generic'"
        for line in output.split('\n')[:50]:  # Limit to 50 entries
            match = re.search(r'([^\s]+)\s*=\s*([^:]+):\s*(.+)', line)
            if match:
                rows.append([
                    match.group(1),  # OID
                    match.group(2).strip(),  # Type
                    match.group(3).strip()[:100]  # Value (truncated)
                ])
        
        if not rows:
            return self._create_no_data_table("SNMP MIB", columns)
        
        return {
            "name": "SNMP MIB",
            "columns": columns,
            "rows": rows
        }


class DnsreconParser(BaseParser):
    """Parser for Dnsrecon scan results"""
    
    def parse(self) -> Dict[str, Any]:
        """Parse Dnsrecon results into 1 table"""
        tables = []
        
        # Table 1: DNS Records
        records_table = self._parse_records_table()
        tables.append(records_table)
        
        return {
            "tool": self.tool_name,
            "tables": tables
        }
    
    def _parse_records_table(self) -> Dict[str, Any]:
        """Parse DNS records into table format"""
        columns = ["Record Type", "Host/Domain", "Value", "TTL"]
        
        if not self.success:
            return self._create_no_data_table("DNS Records", columns)
        
        records = self.tool_result.get("records", [])
        
        if not records:
            return self._create_no_data_table("DNS Records", columns)
        
        rows = []
        for record in records:
            # Parse format like "PTR record: host.example.com"
            record_type = "PTR"
            if "PTR" in record:
                record_type = "PTR"
            elif "A" in record:
                record_type = "A"
            elif "MX" in record:
                record_type = "MX"
            elif "CNAME" in record:
                record_type = "CNAME"
            
            # Extract host and value
            parts = record.split(':', 1)
            value = parts[1].strip() if len(parts) > 1 else record
            
            rows.append([
                record_type,
                value.split()[0] if value else 'N/A',
                value,
                'N/A'  # TTL not typically in dnsrecon output
            ])
        
        if not rows:
            return self._create_no_data_table("DNS Records", columns)
        
        return {
            "name": "DNS Records",
            "columns": columns,
            "rows": rows
        }


class AutoreconParser(BaseParser):
    """Parser for Autorecon scan results"""
    
    def parse(self) -> Dict[str, Any]:
        """Parse Autorecon results into 2 tables"""
        tables = []
        
        # Table 1: Service Summary
        service_table = self._parse_service_summary_table()
        tables.append(service_table)
        
        # Table 2: Overall Vulnerabilities
        vuln_table = self._parse_overall_vulnerabilities_table()
        tables.append(vuln_table)
        
        return {
            "tool": self.tool_name,
            "tables": tables
        }
    
    def _parse_service_summary_table(self) -> Dict[str, Any]:
        """Parse service summary into table format"""
        columns = ["Port/Service", "Tool Used", "Key Findings"]
        
        if not self.success:
            return self._create_no_data_table("Service Summary", columns)
        
        # Autorecon aggregates results, so we parse from summary
        summary = self.tool_result.get("summary", "")
        
        if not summary:
            return self._create_no_data_table("Service Summary", columns)
        
        rows = [
            ["Multiple", "Autorecon", "Automated enumeration completed. Check output directory for detailed results."]
        ]
        
        return {
            "name": "Service Summary",
            "columns": columns,
            "rows": rows
        }
    
    def _parse_overall_vulnerabilities_table(self) -> Dict[str, Any]:
        """Parse overall vulnerabilities into table format"""
        columns = ["Severity", "Description", "Affected Service/Port", "Remediation Notes"]
        
        if not self.success:
            return self._create_no_data_table("Overall Vulnerabilities", columns)
        
        # Autorecon doesn't directly provide structured vulnerability data
        # This would require parsing the output files
        
        return self._create_no_data_table("Overall Vulnerabilities", columns)


# Factory function to get appropriate parser
def get_parser(tool_result: Dict[str, Any]) -> Optional[BaseParser]:
    """Get appropriate parser for a tool result"""
    tool_name = tool_result.get("tool", "")
    
    parsers = {
        "nmap_tcp": NmapTCPParser,
        "nmap_udp": NmapUDPParser,
        "whatweb": WhatWebParser,
        "feroxbuster": FeroxbusterParser,
        "feroxbuster_https": FeroxbusterParser,
        "enum4linux-ng": Enum4LinuxParser,
        "enum4linux_classic": Enum4LinuxParser,
        "sslyze": SSLyzeParser,
        "nbtscan": NbtscanParser,
        "onesixtyone": OneSixtyOneParser,
        "snmpwalk": SnmpwalkParser,
        "snmpwalk_v1": SnmpwalkParser,
        "dnsrecon": DnsreconParser,
        "autorecon": AutoreconParser
    }
    
    parser_class = parsers.get(tool_name)
    if parser_class:
        return parser_class(tool_result)
    return None
