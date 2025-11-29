import nmap
import asyncio
import logging
import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class NmapScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()

    def scan(self, target):
        """
        Runs comprehensive nmap scan.
        """
        # Comprehensive OSCP-style scan
        arguments = '-Pn -A -sC -sV -O --top-ports 200 --script=default,vuln,banner --traceroute --reason --min-rate 5000 -T4 -vv'
        
        logger.info(f"Starting comprehensive nmap scan on {target}")
        try:
            scan_result = self.nm.scan(hosts=target, arguments=arguments)
            
            # Parse and structure the output
            structured_data = self._parse_scan_result(scan_result, target)
            return structured_data
        except Exception as e:
            logger.error(f"Nmap scan failed: {e}")
            return {"error": str(e)}

    def _parse_scan_result(self, scan_result, target):
        """
        Parse nmap scan result into structured format.
        """
        try:
            structured = {
                "target": target,
                "scan_info": scan_result.get('nmap', {}),
                "ports": [],
                "os_detection": {},
                "raw_output": scan_result
            }
            
            # Extract host data
            if 'scan' in scan_result and target in scan_result['scan']:
                host_data = scan_result['scan'][target]
                
                # Extract open ports
                if 'tcp' in host_data:
                    for port, port_data in host_data['tcp'].items():
                        if port_data['state'] == 'open':
                            structured['ports'].append({
                                'port': port,
                                'protocol': 'tcp',
                                'service': port_data.get('name', 'unknown'),
                                'version': port_data.get('version', ''),
                                'product': port_data.get('product', ''),
                                'extrainfo': port_data.get('extrainfo', '')
                            })
                
                if 'udp' in host_data:
                    for port, port_data in host_data['udp'].items():
                        if port_data['state'] == 'open':
                            structured['ports'].append({
                                'port': port,
                                'protocol': 'udp',
                                'service': port_data.get('name', 'unknown'),
                                'version': port_data.get('version', ''),
                                'product': port_data.get('product', ''),
                                'extrainfo': port_data.get('extrainfo', '')
                            })
                
                # Extract OS detection
                if 'osmatch' in host_data:
                    os_matches = host_data['osmatch']
                    if os_matches:
                        structured['os_detection'] = {
                            'name': os_matches[0].get('name', 'Unknown'),
                            'accuracy': os_matches[0].get('accuracy', '0'),
                            'all_matches': [{'name': m.get('name'), 'accuracy': m.get('accuracy')} for m in os_matches[:3]]
                        }
            
            return structured
        except Exception as e:
            logger.error(f"Error parsing scan result: {e}")
            return {"error": f"Parse error: {str(e)}", "raw_output": scan_result}

    async def scan_async(self, target):
        """
        Runs nmap scan asynchronously using an executor.
        """
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self.scan, target)

