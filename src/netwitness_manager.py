"""
NetWitness Manager - Main integration point for NetWitness functionality
"""
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from typing import Dict, List, Any, Optional, Tuple
import json
from datetime import datetime, timedelta

# NetWitness imports
try:
    from src.netwitness_client import NetWitnessClient
    from src.netwitness_automation import fetch_incident_stats_text
    from src.netwitness_metadata import query_sessions_by_ip, query_sessions_for_incident_ips
    from src.netwitness_queries import (
        get_incident_with_related_alerts, 
        get_alerts_brief,
        format_incident_and_alerts,
        derive_incident_summary
    )
    from src.netwitness_models import AlertSummary, IncidentSummary
    
    NETWITNESS_AVAILABLE = True
except ImportError as e:
    print(f"NetWitness modules not available: {e}")
    NETWITNESS_AVAILABLE = False


class NetWitnessManager:
    """Manages all NetWitness operations and provides decision logic"""
    
    def __init__(self, host: str, username: str, password: str, verify_ssl: bool = False):
        if not NETWITNESS_AVAILABLE:
            raise ImportError("NetWitness modules are not available")
        
        self.client = NetWitnessClient(host, username, password, verify_ssl)
        self._extend_client_methods()
    
    def _extend_client_methods(self):
        """Extend the client with missing methods from the provided files"""
        # Add methods that are referenced but not defined in netwitness_client.py
        def get_incident_stats(since=None, until=None, page_number=0, page_size=100):
            """Mock implementation - replace with actual API call"""
            # This should be replaced with actual NetWitness REST API call
            return {"items": []}
        
        def get_incidents(incident_id):
            """Mock implementation - replace with actual API call"""
            return {"id": incident_id, "title": "Sample Incident"}
        
        def get_incidents_alerts(incident_id, page_number=0, page_size=20):
            """Mock implementation - replace with actual API call"""
            return {"items": []}
        
        def get_alert_count(since=None, until=None):
            """Mock implementation - replace with actual API call"""
            return 0
        
        def get_alerts(since=None, until=None, page_number=0, page_size=20):
            """Mock implementation - replace with actual API call"""
            return {"items": []}
        
        def extract_meta_ips(item):
            """Extract source and destination IPs from metadata"""
            src_ips = item.get("source_ips", []) or item.get("src_ip", [])
            dst_ips = item.get("destination_ips", []) or item.get("dst_ip", [])
            
            if isinstance(src_ips, str):
                src_ips = [src_ips]
            if isinstance(dst_ips, str):
                dst_ips = [dst_ips]
            
            return src_ips, dst_ips
        
        def extract_metadata_ips(incident_obj):
            """Extract IPs from incident metadata"""
            return extract_meta_ips(incident_obj)
        
        def metadata_query(query):
            """Execute metadata query"""
            return self.client.query(query)
        
        # Attach methods to client
        self.client.get_incident_stats = get_incident_stats
        self.client.get_incidents = get_incidents
        self.client.get_incidents_alerts = get_incidents_alerts
        self.client.get_alert_count = get_alert_count
        self.client.get_alerts = get_alerts
        self.client.extract_meta_ips = extract_meta_ips
        self.client.extract_metadata_ips = extract_metadata_ips
        self.client.metadata_query = metadata_query
    
    def analyze_prompt(self, prompt: str) -> Dict[str, Any]:
        """
        Analyze user prompt to determine which NetWitness functions to use
        
        Returns:
            Dict with 'action', 'parameters', and 'confidence' score
        """
        prompt_lower = prompt.lower()
        
        # Define trigger patterns
        patterns = {
            'incident_stats': ['statistics', 'stats', 'mtta', 'mttd', 'mttr', 'mean time', 'incident metrics'],
            'incident_details': ['incident', 'alert details', 'get incident', 'show incident', 'incident id'],
            'alerts_summary': ['alerts', 'recent alerts', 'alert summary', 'show alerts'],
            'session_query': ['sessions', 'session data', 'ip sessions', 'metadata', 'session information'],
            'ip_lookup': ['ip address', 'lookup ip', 'search ip', 'find sessions for ip'],
            'incident_timeline': ['timeline', 'incident timeline', 'related events', 'sequence']
        }
        
        # Check for incident IDs (e.g., INC-1234, INC_5678)
        import re
        incident_id_match = re.search(r'(INC[-_]\d+|incident\s+\d+)', prompt, re.IGNORECASE)
        incident_id = incident_id_match.group(0).replace(' ', '_') if incident_id_match else None
        
        # Check for IP addresses
        ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', prompt)
        ip_address = ip_match.group(0) if ip_match else None
        
        # Check for date ranges
        date_patterns = [
            r'today', r'yesterday', r'last\s+\d+\s+days?',
            r'since\s+[\w\s\d]+', r'from\s+[\w\s\d]+\s+to'
        ]
        date_range = None
        for pattern in date_patterns:
            if re.search(pattern, prompt_lower):
                date_range = self._parse_date_range(prompt_lower)
                break
        
        # Determine action based on patterns
        action = None
        parameters = {}
        confidence = 0
        
        # Check for specific actions
        if any(word in prompt_lower for word in patterns['incident_stats']):
            action = 'incident_stats'
            confidence = 0.8
            if date_range:
                parameters.update(date_range)
        
        elif any(word in prompt_lower for word in patterns['incident_details']) or incident_id:
            action = 'incident_details'
            confidence = 0.9 if incident_id else 0.6
            if incident_id:
                parameters['incident_id'] = incident_id
        
        elif any(word in prompt_lower for word in patterns['alerts_summary']):
            action = 'alerts_summary'
            confidence = 0.7
            if date_range:
                parameters.update(date_range)
        
        elif any(word in prompt_lower for word in patterns['session_query']) or ip_address:
            action = 'session_query'
            confidence = 0.8 if ip_address else 0.5
            if ip_address:
                parameters['ip_address'] = ip_address
        
        elif any(word in prompt_lower for word in patterns['ip_lookup']):
            action = 'session_query'
            confidence = 0.7
            if ip_address:
                parameters['ip_address'] = ip_address
        
        return {
            'action': action,
            'parameters': parameters,
            'confidence': confidence,
            'incident_id': incident_id,
            'ip_address': ip_address
        }
    
    def _parse_date_range(self, prompt: str) -> Dict[str, str]:
        """Parse date range from prompt"""
        today = datetime.now()
        
        if 'today' in prompt:
            return {'since': today.strftime('%Y-%m-%d')}
        elif 'yesterday' in prompt:
            yesterday = today - timedelta(days=1)
            return {'since': yesterday.strftime('%Y-%m-%d'), 'until': today.strftime('%Y-%m-%d')}
        elif 'last week' in prompt:
            last_week = today - timedelta(days=7)
            return {'since': last_week.strftime('%Y-%m-%d')}
        elif 'last month' in prompt:
            last_month = today - timedelta(days=30)
            return {'since': last_month.strftime('%Y-%m-%d')}
        
        # Default: last 7 days
        last_week = today - timedelta(days=7)
        return {'since': last_week.strftime('%Y-%m-%d')}
    
    def execute_action(self, action: str, parameters: Dict[str, Any]) -> str:
        """Execute the appropriate NetWitness action"""
        try:
            if action == 'incident_stats':
                since = parameters.get('since')
                until = parameters.get('until')
                return fetch_incident_stats_text(self.client, since=since, until=until)
            
            elif action == 'incident_details':
                incident_id = parameters.get('incident_id')
                if not incident_id:
                    return "Please specify an incident ID (e.g., INC-1234)"
                
                incident_sum, alerts = get_incident_with_related_alerts(self.client, incident_id)
                return format_incident_and_alerts(incident_sum, alerts)
            
            elif action == 'alerts_summary':
                since = parameters.get('since')
                until = parameters.get('until')
                count, alerts = get_alerts_brief(self.client, since=since, until=until)
                
                if count == 0:
                    return f"No alerts found for the specified time period."
                
                result = [f"Found {count} alerts. Showing first {len(alerts)}:"]
                for alert in alerts:
                    result.append(f"- {alert.id}: {alert.title} (Severity: {alert.severity})")
                return "\n".join(result)
            
            elif action == 'session_query':
                ip_address = parameters.get('ip_address')
                if not ip_address:
                    return "Please specify an IP address to query sessions."
                
                sessions = query_sessions_by_ip(self.client, ip_address, limit=20)
                if not sessions or len(sessions.get('results', [])) == 0:
                    return f"No sessions found for IP: {ip_address}"
                
                result = [f"Sessions for IP {ip_address}:"]
                for session in sessions.get('results', [])[:10]:
                    result.append(f"- Session ID: {session.get('id', 'N/A')}")
                return "\n".join(result)
            
            else:
                return f"Action '{action}' not implemented."
                
        except Exception as e:
            return f"Error executing NetWitness action: {str(e)}"
    
    def get_capabilities(self) -> str:
        """Return a description of available NetWitness capabilities"""
        capabilities = [
            "NetWitness Capabilities:",
            "1. Incident Statistics (MTTA/MTTD/MTTR)",
            "2. Incident Details with related alerts",
            "3. Alert Summaries with filtering by date",
            "4. Session/Metadata queries by IP address",
            "5. IP address lookup and session analysis"
        ]
        return "\n".join(capabilities)


# Helper function to check if prompt should use NetWitness
def should_use_netwitness(prompt: str) -> bool:
    """Determine if a prompt is likely requesting NetWitness data"""
    netwitness_keywords = [
        'netwitness', 'nw', 'incident', 'alert', 'session',
        'mtta', 'mttd', 'mttr', 'statistics', 'metrics',
        'ip address', 'metadata', 'soc metrics', 'threat'
    ]
    
    prompt_lower = prompt.lower()
    return any(keyword in prompt_lower for keyword in netwitness_keywords)