"""
NetWitness Platform JSON Log Parser
Parses incident and alert data from NetWitness Platform exports
"""
#Imported dependecies 
import json
from typing import List, Dict, Optional, Any
from datetime import datetime

#Loads, parses and transformation of raw Netwitness JSON data into structured security incidents
class NetWitnessParser:
    """Parser for NetWitness Platform JSON logs"""
    #Loads JSON incident and handles nested incident structures
    @staticmethod
    def load_incidents(filepath: str) -> List[Dict]:
        """
        Load NetWitness incident JSON file.
        
        Args:
            filepath: Path to the JSON file containing incidents
            
        Returns:
            List of incident dictionaries
        """
        with open(filepath, "r") as f:
            data = json.load(f)
        
        # Handle nested incidents structure
        if isinstance(data, dict) and "incidents" in data:
            return data["incidents"]
        elif isinstance(data, list):
            return data
        else:
            return []

    #Extraction and normalise incident metadata/IOCs
    @staticmethod
    def parse_incident(incident: Dict) -> Dict:
        """
        Extract and normalize incident data from NetWitness format.
        
        Args:
            incident: Raw incident dictionary from NetWitness
            
        Returns:
            Normalized incident dictionary
        """
        parsed = {
            "id": incident.get("_id", "UNKNOWN"),
            "name": incident.get("name", ""),
            "summary": incident.get("summary", ""),
            "priority": incident.get("priority", "UNKNOWN"),
            "risk_score": incident.get("riskScore", 0),
            "status": incident.get("status", "UNKNOWN"),
            "alert_count": incident.get("alertCount", 0),
            "average_alert_risk_score": incident.get("averageAlertRiskScore", 0),
            "event_count": incident.get("eventCount", 0),
            "created_time": NetWitnessParser._parse_date(incident.get("created")),
            "last_updated": NetWitnessParser._parse_date(incident.get("lastUpdated")),
            "assignee": NetWitnessParser._parse_assignee(incident.get("assignee")),
            "sources": incident.get("sources", []),
            "tactics": incident.get("tactics", []),
            "techniques": incident.get("techniques", []),
            "url": incident.get("url", ""),
        }
        return parsed

    #Parsing of alert data in incidents and extraction of device information, risk score and signatures 
    @staticmethod
    def parse_alert(alert: Dict) -> Dict:
        """
        Extract and normalize alert data from NetWitness format.
        
        Args:
            alert: Raw alert dictionary from NetWitness
            
        Returns:
            Normalized alert dictionary
        """
        original_alert = alert.get("originalAlert", {})
        original_headers = alert.get("originalHeaders", {})
        
        parsed = {
            "id": str(alert.get("_id", {}).get("$oid", "UNKNOWN")),
            "received_time": NetWitnessParser._parse_date(alert.get("receivedTime")),
            "name": original_headers.get("name", ""),
            "severity": original_headers.get("severity", 0),
            "signature_id": original_headers.get("signatureId", ""),
            "device_vendor": original_headers.get("deviceVendor", ""),
            "device_product": original_headers.get("deviceProduct", ""),
            "device_version": original_headers.get("deviceVersion", ""),
            "risk_score": original_alert.get("risk_score", 0),
            "source": original_alert.get("source", ""),
            "datasource_host": original_alert.get("datasource_host", ""),
            "datasource_port": original_alert.get("datasource_port", ""),
        }
        return parsed

    #Extraction of event details 
    @staticmethod
    def parse_event(event: Dict) -> Dict:
        """
        Extract and normalize event data from alert.
        
        Args:
            event: Raw event dictionary from alert
            
        Returns:
            Normalized event dictionary
        """
        parsed = {
            "time": event.get("time", ""),
            "action": event.get("action", ""),
            "attack_tactic": event.get("attack_tactic", ""),
            "attack_tid": event.get("attack_tid", ""),
            "attack_technique": event.get("attack_technique", ""),
            "direction": event.get("direction", ""),
            "ip_src": event.get("ip_src", ""),
            "ip_dst": event.get("ip_dst", ""),
            "tcp_srcport": event.get("tcp_srcport", ""),
            "tcp_dstport": event.get("tcp_dstport", ""),
            "country_dst": event.get("country_dst", ""),
            "domain_dst": event.get("domain_dst", ""),
            "filetype": event.get("filetype", ""),
            "filename": event.get("filename", ""),
            "payload": event.get("payload", ""),
            "packets": event.get("packets", ""),
            "client": event.get("client", ""),
            "user_agent": event.get("user_agent", ""),
            "analysis_service": event.get("analysis_service", ""),
            "analysis_desc": event.get("analysis_desc", ""),
        }
        return parsed

    #Extraction of date format conversions 
    @staticmethod
    def _parse_date(date_obj: Optional[Dict]) -> Optional[str]:
        """
        Parse MongoDB date format to ISO string.
        
        Args:
            date_obj: Date object with $date key or ISO string
            
        Returns:
            ISO format date string or None
        """
        if not date_obj:
            return None
        
        if isinstance(date_obj, dict) and "$date" in date_obj:
            return date_obj["$date"]
        elif isinstance(date_obj, str):
            return date_obj
        
        return None

    #Extraction and normalise assignee information for incident ownership tracking 
    @staticmethod
    def _parse_assignee(assignee_obj: Optional[Dict]) -> Optional[Dict]:
        """
        Parse assignee information.
        
        Args:
            assignee_obj: Assignee dictionary
            
        Returns:
            Normalized assignee dictionary or None
        """
        if not assignee_obj:
            return None
        
        return {
            "id": assignee_obj.get("id", ""),
            "name": assignee_obj.get("name", ""),
            "email": assignee_obj.get("email", ""),
            "login": assignee_obj.get("login", ""),
        }

    #Combines incident, alert and event parsing into a single structure for comprehensive incident analysis 
    @staticmethod
    def parse_full_incident(incident: Dict) -> Dict:
        """
        Parse complete incident with all related alerts and events.
        
        Args:
            incident: Raw incident dictionary
            
        Returns:
            Complete parsed incident with normalized alerts
        """
        parsed_incident = NetWitnessParser.parse_incident(incident)
        
        # Parse all alerts
        alerts = incident.get("alerts", [])
        parsed_alerts = []
        
        for alert in alerts:
            parsed_alert = NetWitnessParser.parse_alert(alert)
            
            # Parse events within alert
            events = alert.get("originalAlert", {}).get("events", [])
            parsed_events = [NetWitnessParser.parse_event(event) for event in events]
            
            parsed_alert["events"] = parsed_events
            parsed_alerts.append(parsed_alert)
        
        parsed_incident["alerts"] = parsed_alerts
        
        return parsed_incident

    #Batch processing of raw JSON file and converting incidents to parsed strctures
    @staticmethod
    def load_and_parse_incidents(filepath: str) -> List[Dict]:
        """
        Load and parse all incidents from file.
        
        Args:
            filepath: Path to the JSON file
            
        Returns:
            List of fully parsed incidents
        """
        raw_incidents = NetWitnessParser.load_incidents(filepath)
        return [NetWitnessParser.parse_full_incident(incident) for incident in raw_incidents]

    #Filtering of incidents by severity level 
    @staticmethod
    def filter_by_priority(incidents: List[Dict], priority: str) -> List[Dict]:
        """
        Filter incidents by priority.
        
        Args:
            incidents: List of parsed incidents
            priority: Priority level (CRITICAL, HIGH, MEDIUM, LOW)
            
        Returns:
            Filtered list of incidents
        """
        return [inc for inc in incidents if inc["priority"] == priority]

    #Filter incidents based on workflow status 
    @staticmethod
    def filter_by_status(incidents: List[Dict], status: str) -> List[Dict]:
        """
        Filter incidents by status.
        
        Args:
            incidents: List of parsed incidents
            status: Status (NEW, ASSIGNED, IN_PROGRESS, RESOLVED, CLOSED)
            
        Returns:
            Filtered list of incidents
        """
        return [inc for inc in incidents if inc["status"] == status]
 
    #Filter incidents based on risk score 
    @staticmethod
    def filter_by_risk_score(incidents: List[Dict], min_score: int = 0, max_score: int = 100) -> List[Dict]:
        """
        Filter incidents by risk score range.
        
        Args:
            incidents: List of parsed incidents
            min_score: Minimum risk score
            max_score: Maximum risk score
            
        Returns:
            Filtered list of incidents
        """
        return [inc for inc in incidents 
                if min_score <= inc["risk_score"] <= max_score]

    #Extract MITRE ATT&CK techniques 
    @staticmethod
    def extract_attack_paths(incident: Dict) -> List[Dict]:
        """
        Extract MITRE ATT&CK tactics and techniques from incident.
        
        Args:
            incident: Parsed incident dictionary
            
        Returns:
            List of attack patterns
        """
        attack_paths = []
        
        for alert in incident.get("alerts", []):
            for event in alert.get("events", []):
                attack_path = {
                    "tactic": event.get("attack_tactic", ""),
                    "technique_id": event.get("attack_tid", ""),
                    "technique": event.get("attack_technique", ""),
                    "source_ip": event.get("ip_src", ""),
                    "dest_ip": event.get("ip_dst", ""),
                    "timestamp": event.get("time", ""),
                }
                if attack_path["tactic"] or attack_path["technique_id"]:
                    attack_paths.append(attack_path)
        
        return attack_paths

    #Identification of IOCs 
    @staticmethod
    def extract_network_indicators(incident: Dict) -> Dict:
        """
        Extract network indicators of compromise from incident.
        
        Args:
            incident: Parsed incident dictionary
            
        Returns:
            Dictionary of network IOCs
        """
        iocs = {
            "source_ips": set(),
            "destination_ips": set(),
            "domains": set(),
            "files": set(),
            "ports": set(),
            "user_agents": set(),
        }
        
        for alert in incident.get("alerts", []):
            for event in alert.get("events", []):
                if event.get("ip_src"):
                    iocs["source_ips"].add(event["ip_src"])
                if event.get("ip_dst"):
                    iocs["destination_ips"].add(event["ip_dst"])
                if event.get("domain_dst"):
                    iocs["domains"].add(event["domain_dst"])
                if event.get("filename"):
                    filenames = event["filename"].split(",")
                    iocs["files"].update(filenames)
                if event.get("tcp_dstport"):
                    iocs["ports"].add(event["tcp_dstport"])
                if event.get("user_agent"):
                    iocs["user_agents"].add(event["user_agent"])
        
        # Convert sets to sorted lists for JSON serialization
        return {
            "source_ips": sorted(list(iocs["source_ips"])),
            "destination_ips": sorted(list(iocs["destination_ips"])),
            "domains": sorted(list(iocs["domains"])),
            "files": sorted(list(iocs["files"])),
            "ports": sorted(list(iocs["ports"])),
            "user_agents": sorted(list(iocs["user_agents"])),
        }

    #Splitting incident into smaller chunks 
    @staticmethod
    def parse_and_chunk_incidents(
        filepath: str,
        max_events_per_chunk: int = 3
    ) -> List[Dict]:
        """
        Compatibility method expected by pipeline.py.
        Splits parsed incidents into event-sized chunks.
        DOES NOT change parsing logic.
        """

        incidents = NetWitnessParser.load_and_parse_incidents(filepath)
        chunks: List[Dict] = []

        for incident in incidents:
            base_incident = {
                k: v for k, v in incident.items() if k != "alerts"
            }

            for alert in incident.get("alerts", []):
                events = alert.get("events", [])

                # Chunk events
                for i in range(0, len(events), max_events_per_chunk):
                    event_chunk = events[i:i + max_events_per_chunk]

                    chunk = {
                        **base_incident,
                        "alert": {
                            **{k: v for k, v in alert.items() if k != "events"},
                            "events": event_chunk
                        }
                    }
                    chunks.append(chunk)

        return chunks


if __name__ == "__main__":
    # Example usage
    incidents = NetWitnessParser.load_and_parse_incidents("netwitness_incidents.json")
    
    for incident in incidents:
        print(f"\n{'='*60}")
        print(f"Incident: {incident['id']} - {incident['name']}")
        print(f"Priority: {incident['priority']}, Risk Score: {incident['risk_score']}")
        print(f"Status: {incident['status']}, Alerts: {incident['alert_count']}")
        
        # Extract attack paths
        attack_paths = NetWitnessParser.extract_attack_paths(incident)
        if attack_paths:
            print("\nATT&CK Tactics/Techniques:")
            for path in attack_paths:
                print(f"  - {path['tactic']} ({path['technique_id']}): {path['technique']}")
        
        # Extract IOCs
        iocs = NetWitnessParser.extract_network_indicators(incident)
        print("\nNetwork Indicators:")
        print(f"  - Source IPs: {iocs['source_ips']}")
        print(f"  - Dest IPs: {iocs['destination_ips']}")
        print(f"  - Domains: {iocs['domains']}")
        print(f"  - Files: {iocs['files']}")
