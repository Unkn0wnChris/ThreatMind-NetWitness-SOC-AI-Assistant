"""
- Correlation Engine for NetWitness Incidents
- Finds relationships between incidents based on IPs, domains, ports, and other IOCs
"""
#Imported dependencies
from typing import List, Dict, Set, Tuple
import json
import re
from datetime import datetime
from collections import defaultdict


class CorrelationEngine:
    """
    - Analyzes incidents to find correlations and relationships.
    - Supports queries like "Show all cases involving 192.168.1.111 and port 80"
    """
    
    #Initialise Correlation Engine with raw log data to parse raw logs and reverse index for fast lookups
    def __init__(self, logs: List[str]):
        """
        Initialize with a list of log strings.
        
        Args:
            logs: List of security log strings (JSON format)
        """
        self.logs = logs
        self.incidents = self._parse_incidents()
        self.correlation_index = self._build_correlation_index()
    
    #Data ingestion to convert various log formats into incident objects 
    def _parse_incidents(self) -> List[Dict]:
        """
        Parse JSON logs into structured incident objects.
        
        Returns:
            List of parsed incident dictionaries
        """
        incidents = []
        
        for idx, log in enumerate(self.logs):
            try:
                # Try parsing as JSON
                if log.strip().startswith('{'):
                    data = json.loads(log)
                    
                    # Handle NetWitness format with incidents array
                    if isinstance(data, dict) and "incidents" in data:
                        for incident in data["incidents"]:
                            parsed_incident = self._extract_incident_data(incident, idx)
                            if parsed_incident:
                                incidents.append(parsed_incident)
                    else:
                        # Single incident object
                        parsed_incident = self._extract_incident_data(data, idx)
                        if parsed_incident:
                            incidents.append(parsed_incident)
            except:
                # Fallback: try to extract info from raw string
                parsed = self._extract_from_raw_text(log, idx)
                if parsed:
                    incidents.append(parsed)
        
        return incidents
    
    #Data extraction for Netwitness incident objects via the metadata found on netwitness logs
    def _extract_incident_data(self, incident: Dict, log_index: int) -> Dict:
        """
        Extract relevant data from a NetWitness incident object.
        """
        extracted = {
            "log_index": log_index,
            "incident_id": incident.get("_id", f"INC-{log_index}"),
            "name": incident.get("name", "Unknown"),
            "priority": incident.get("priority", "UNKNOWN"),
            "severity": self._extract_severity(incident),
            "status": incident.get("status", "NEW"),
            "timestamp": self._parse_timestamp(incident.get("created", {})),
            "ips_src": set(),
            "ips_dst": set(),
            "ports_dst": set(),
            "domains": set(),
            "files": set(),
            "users": set(),
            "attack_tactics": set(),
            "attack_techniques": set(),
        }
        
        # Extract from alerts and events
        for alert in incident.get("alerts", []):
            events = alert.get("originalAlert", {}).get("events", [])
            for event in events:
                # IPs
                if event.get("ip_src"):
                    extracted["ips_src"].add(event.get("ip_src"))
                if event.get("ip_dst"):
                    extracted["ips_dst"].add(event.get("ip_dst"))
                
                # Ports
                if event.get("tcp_dstport"):
                    extracted["ports_dst"].add(str(event.get("tcp_dstport")))
                if event.get("tcp_srcport"):
                    extracted["ports_dst"].add(str(event.get("tcp_srcport")))
                
                # Domains
                if event.get("domain"):
                    extracted["domains"].add(event.get("domain").lower())
                if event.get("alias_host"):
                    for host in event.get("alias_host", []):
                        extracted["domains"].add(host.lower())
                
                # Files
                if event.get("filename"):
                    extracted["files"].add(event.get("filename"))
                
                # Attack info
                if event.get("attack_tactic"):
                    extracted["attack_tactics"].add(event.get("attack_tactic"))
                if event.get("attack_technique"):
                    extracted["attack_techniques"].add(event.get("attack_technique"))
        
        return extracted
    
    #Fallback parser mechanism for irregular logs through regular expressions 
    def _extract_from_raw_text(self, text: str, log_index: int) -> Dict:
        """
        Fallback: extract IOCs from raw text using regex patterns.
        """
        extracted = {
            "log_index": log_index,
            "incident_id": f"INC-{log_index}",
            "name": text[:100],
            "priority": "UNKNOWN",
            "severity": "UNKNOWN",
            "status": "NEW",
            "timestamp": datetime.now(),
            "ips_src": set(),
            "ips_dst": set(),
            "ports_dst": set(),
            "domains": set(),
            "files": set(),
            "users": set(),
            "attack_tactics": set(),
            "attack_techniques": set(),
        }
        
        # Extract IPs
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips = re.findall(ip_pattern, text)
        extracted["ips_src"].update(ips)
        extracted["ips_dst"].update(ips)
        
        # Extract ports
        port_pattern = r'(?:port|:)\s*(\d{2,5})\b'
        ports = re.findall(port_pattern, text)
        extracted["ports_dst"].update(ports)
        
        # Extract domains
        domain_pattern = r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b'
        domains = re.findall(domain_pattern, text.lower())
        extracted["domains"].update(domains)
        
        return extracted if ips or ports or domains else None
    
    #Creation of inverted index mapping IOCs to incdients for quick correlation 
    def _build_correlation_index(self) -> Dict:
        """
        Build an index for fast correlation lookups.
        Maps IOCs (IPs, domains, ports) to incident indices.
        """
        index = defaultdict(set)
        
        for incident in self.incidents:
            inc_idx = incident["log_index"]
            
            # Index IPs
            for ip in incident["ips_src"]:
                index[f"ip_src:{ip}"].add(inc_idx)
            for ip in incident["ips_dst"]:
                index[f"ip_dst:{ip}"].add(inc_idx)
            
            # Index ports
            for port in incident["ports_dst"]:
                index[f"port:{port}"].add(inc_idx)
            
            # Index domains
            for domain in incident["domains"]:
                index[f"domain:{domain}"].add(inc_idx)
            
            # Index attack tactics
            for tactic in incident["attack_tactics"]:
                index[f"tactic:{tactic}"].add(inc_idx)
        
        return index
    

    def _extract_severity(self, incident: Dict) -> str:
        """Extract severity from incident."""
        if incident.get("priority") == "CRITICAL":
            return "CRITICAL"
        elif incident.get("priority") == "HIGH":
            return "HIGH"
        elif incident.get("priority") == "MEDIUM":
            return "MEDIUM"
        return "LOW"
    
    def _parse_timestamp(self, date_obj) -> datetime:
        """Parse timestamp from incident."""
        try:
            if isinstance(date_obj, dict) and "$date" in date_obj:
                return datetime.fromisoformat(date_obj["$date"].replace("Z", "+00:00"))
        except:
            pass
        return datetime.now()
    
    #Parse text into queries to look for incidents containing specific meta keys and IOCs
    def correlate_by_query(self, query: str) -> List[Dict]:
        """
        Find correlations based on a natural language query.
        Examples:
        - "Show all cases involving 192.168.1.111"
        - "Find incidents with port 80 and domain example.com"
        - "IP 10.0.0.1 and port 443"
        
        Args:
            query: Natural language query
            
        Returns:
            List of correlated incidents
        """
        # Extract IPs
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips = set(re.findall(ip_pattern, query))
        
        # Extract ports
        port_pattern = r'\b(\d{2,5})\b'
        ports = set(re.findall(port_pattern, query))
        
        # Extract domains
        domain_pattern = r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b'
        domains = set(re.findall(domain_pattern, query.lower()))
        
        # Find matching incidents
        matching_indices = set()
        
        for ip in ips:
            # Check both source and destination IPs
            matching_indices.update(self.correlation_index.get(f"ip_src:{ip}", set()))
            matching_indices.update(self.correlation_index.get(f"ip_dst:{ip}", set()))
        
        for port in ports:
            matching_indices.update(self.correlation_index.get(f"port:{port}", set()))
        
        for domain in domains:
            matching_indices.update(self.correlation_index.get(f"domain:{domain}", set()))
        
        # Get incident details for matching indices
        correlated = []
        for idx in sorted(matching_indices):
            for incident in self.incidents:
                if incident["log_index"] == idx:
                    correlated.append(incident)
                    break
        
        return correlated
    
    #Calculate correlation strength against incidents based on IOCs
    def find_related_incidents(self, incident_index: int) -> List[Tuple[Dict, int]]:
        """
        Find all incidents related to a specific incident.
        Returns related incidents with correlation strength (number of shared IOCs).
        
        Args:
            incident_index: Index of the incident to find relations for
            
        Returns:
            List of (incident, correlation_strength) tuples
        """
        target = None
        for incident in self.incidents:
            if incident["log_index"] == incident_index:
                target = incident
                break
        
        if not target:
            return []
        
        related = []
        
        for incident in self.incidents:
            if incident["log_index"] == incident_index:
                continue
            
            # Count shared IOCs
            shared_count = 0
            
            # Shared IPs
            shared_count += len(target["ips_src"] & incident["ips_src"])
            shared_count += len(target["ips_dst"] & incident["ips_dst"])
            
            # Shared ports
            shared_count += len(target["ports_dst"] & incident["ports_dst"]) * 2
            
            # Shared domains
            shared_count += len(target["domains"] & incident["domains"]) * 2
            
            # Shared attack tactics
            shared_count += len(target["attack_tactics"] & incident["attack_tactics"])
            
            if shared_count > 0:
                related.append((incident, shared_count))
        
        # Sort by correlation strength (descending)
        related.sort(key=lambda x: x[1], reverse=True)
        return related
    
    
    #Creation of human readable summary output of incident 
    def get_incident_summary(self, incident: Dict) -> str:
        """Generate a summary of an incident with its IOCs."""
        summary = f"""
        **Incident:** {incident['incident_id']} - {incident['name']}
        **Priority:** {incident['priority']} | **Status:** {incident['status']}
        **Time:** {incident['timestamp']}

        **IOCs Found:**
        - Source IPs: {', '.join(incident['ips_src']) if incident['ips_src'] else 'N/A'}
        - Destination IPs: {', '.join(incident['ips_dst']) if incident['ips_dst'] else 'N/A'}
        - Ports: {', '.join(incident['ports_dst']) if incident['ports_dst'] else 'N/A'}
        - Domains: {', '.join(incident['domains']) if incident['domains'] else 'N/A'}
        - Files: {', '.join(incident['files']) if incident['files'] else 'N/A'}
        - Attack Tactics: {', '.join(incident['attack_tactics']) if incident['attack_tactics'] else 'N/A'}
        """
        return summary.strip()
    
    #Generation of formatted correlation reports 
    def generate_correlation_report(self, correlated_incidents: List[Dict]) -> str:
        """Generate a formatted report of correlated incidents."""
        if not correlated_incidents:
            return "No correlated incidents found."
        
        report = f"**Found {len(correlated_incidents)} correlated incident(s):**\n\n"
        
        for incident in correlated_incidents:
            report += self.get_incident_summary(incident)
            report += "\n" + "="*60 + "\n\n"
        
        return report
