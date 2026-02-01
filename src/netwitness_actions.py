'''
"""
NetWitness Action Handler - Direct query execution
"""
from typing import Dict, Any, Optional
from netwitness_client import NetWitnessClient
from netwitness_queries import get_incident_with_related_alerts, format_incident_and_alerts


class NetWitnessActions:
    """Direct action handler for NetWitness queries"""
    
    def __init__(self, client: NetWitnessClient):
        self.client = client
    
    def get_incident_details(self, incident_id: str) -> str:
        """Get detailed information about a specific incident"""
        try:
            # Clean the incident ID
            incident_id = incident_id.strip().upper()
            if "INC-" not in incident_id and "INC_" not in incident_id:
                incident_id = f"INC-{incident_id}"
            
            # Get incident and related alerts
            incident_sum, alerts = get_incident_with_related_alerts(self.client, incident_id, max_alerts=20)
            
            if not incident_sum:
                return f"Incident {incident_id} not found in NetWitness."
            
            # Format the response
            formatted = format_incident_and_alerts(incident_sum, alerts)
            
            # Add additional details
            response = f"""
🔍 **INCIDENT DETAILS: {incident_id}**

{formatted}

📊 **Summary:**
- Incident Title: {incident_sum.title}
- Status: {incident_sum.status}
- Priority: {incident_sum.priority}
- Created: {incident_sum.created}
- Last Updated: {incident_sum.last_updated}
- Related Alerts: {len(alerts)}

🎯 **Key Information:**
- Source IPs: {', '.join(incident_sum.source_ips or ['None'])}
- Destination IPs: {', '.join(incident_sum.destination_ips or ['None'])}
"""
            return response
            
        except Exception as e:
            return f"❌ Error retrieving incident {incident_id}: {str(e)}"
    
    def get_incident_stats(self, time_range: str = "last 7 days") -> str:
        """Get incident statistics"""
        try:
            from netwitness_automation import fetch_incident_stats_text
            
            # Parse time range
            time_params = self._parse_time_range(time_range)
            
            stats_text = fetch_incident_stats_text(
                self.client, 
                since=time_params.get('since'),
                until=time_params.get('until')
            )
            
            return f"📈 **Incident Statistics ({time_range}):**\n\n{stats_text}"
            
        except Exception as e:
            return f"❌ Error retrieving statistics: {str(e)}"
    
    def search_by_ip(self, ip_address: str) -> str:
        """Search for sessions by IP address"""
        try:
            from netwitness_metadata import query_sessions_by_ip
            
            sessions = query_sessions_by_ip(self.client, ip_address, limit=20)
            
            if not sessions or 'results' not in sessions or len(sessions['results']) == 0:
                return f"🔍 No sessions found for IP: {ip_address}"
            
            results = sessions['results'][:10]  # Limit to 10 sessions
            
            response_lines = [f"📡 **Sessions for IP {ip_address}:**", ""]
            
            for idx, session in enumerate(results, 1):
                session_id = session.get('id', 'N/A')
                timestamp = session.get('time', session.get('timestamp', 'N/A'))
                src_ip = session.get('src_ip', session.get('ip.src', 'N/A'))
                dst_ip = session.get('dst_ip', session.get('ip.dst', 'N/A'))
                
                response_lines.append(f"{idx}. **Session ID:** {session_id}")
                response_lines.append(f"   - Time: {timestamp}")
                response_lines.append(f"   - Source: {src_ip} → Destination: {dst_ip}")
                response_lines.append(f"   - Protocol: {session.get('service', session.get('protocol', 'N/A'))}")
                response_lines.append("")
            
            response_lines.append(f"📊 Total sessions found: {len(sessions['results'])} (showing 10)")
            
            return "\n".join(response_lines)
            
        except Exception as e:
            return f"❌ Error searching for IP {ip_address}: {str(e)}"
    
    def get_recent_alerts(self, count: int = 10, time_range: str = "last 24 hours") -> str:
        """Get recent alerts"""
        try:
            from netwitness_queries import get_alerts_brief
            
            time_params = self._parse_time_range(time_range)
            
            total_count, alerts = get_alerts_brief(
                self.client,
                since=time_params.get('since'),
                until=time_params.get('until'),
                max_alerts=count
            )
            
            if total_count == 0:
                return f"🔔 No alerts found for the specified time period ({time_range})."
            
            response_lines = [f"🚨 **Recent Alerts ({time_range}):**", f"Total alerts: {total_count}", ""]
            
            for idx, alert in enumerate(alerts[:count], 1):
                response_lines.append(f"{idx}. **{alert.title}**")
                response_lines.append(f"   - ID: {alert.id}")
                response_lines.append(f"   - Severity: {alert.severity}")
                response_lines.append(f"   - Created: {alert.created}")
                response_lines.append(f"   - Source: {alert.source}")
                if alert.source_ips:
                    response_lines.append(f"   - Source IPs: {', '.join(alert.source_ips)}")
                response_lines.append("")
            
            return "\n".join(response_lines)
            
        except Exception as e:
            return f"❌ Error retrieving alerts: {str(e)}"
    
    def _parse_time_range(self, time_range: str) -> Dict[str, Optional[str]]:
        """Parse time range string to date parameters"""
        from datetime import datetime, timedelta
        
        now = datetime.now()
        
        if "today" in time_range.lower():
            today = now.strftime('%Y-%m-%d')
            return {'since': today}
        elif "yesterday" in time_range.lower():
            yesterday = (now - timedelta(days=1)).strftime('%Y-%m-%d')
            today = now.strftime('%Y-%m-%d')
            return {'since': yesterday, 'until': today}
        elif "last 24 hours" in time_range.lower() or "past day" in time_range.lower():
            yesterday_time = (now - timedelta(hours=24)).strftime('%Y-%m-%dT%H:%M:%S')
            return {'since': yesterday_time}
        elif "last 7 days" in time_range.lower() or "past week" in time_range.lower():
            last_week = (now - timedelta(days=7)).strftime('%Y-%m-%d')
            return {'since': last_week}
        elif "last 30 days" in time_range.lower() or "past month" in time_range.lower():
            last_month = (now - timedelta(days=30)).strftime('%Y-%m-%d')
            return {'since': last_month}
        else:
            # Default: last 7 days
            last_week = (now - timedelta(days=7)).strftime('%Y-%m-%d')
            return {'since': last_week}
'''


"""
NetWitness Action Handler - Direct query execution
"""
from typing import Dict, Any, Optional, List, Tuple  # <-- Added List and Tuple
from datetime import datetime, timedelta  # <-- Added datetime imports
from src.netwitness_client import NetWitnessClient
from src.netwitness_queries import get_incident_with_related_alerts, format_incident_and_alerts, get_alerts_brief
from src.netwitness_automation import fetch_incident_stats_text
from src.netwitness_metadata import query_sessions_by_ip


class NetWitnessActions:
    """Direct action handler for NetWitness queries"""
    
    def __init__(self, client: NetWitnessClient):
        self.client = client
    
    def get_incident_details(self, incident_id: str) -> str:
        """Get detailed information about a specific incident"""
        try:
            # Clean the incident ID
            incident_id = incident_id.strip().upper()
            if "INC-" not in incident_id and "INC_" not in incident_id:
                incident_id = f"INC-{incident_id}"
            
            # Get incident and related alerts
            incident_sum, alerts = get_incident_with_related_alerts(self.client, incident_id, max_alerts=20)
            
            if not incident_sum:
                return f"Incident {incident_id} not found in NetWitness."
            
            # Format the response
            formatted = format_incident_and_alerts(incident_sum, alerts)
            
            # Add additional details
            response = f"""
🔍 **INCIDENT DETAILS: {incident_id}**

{formatted}

📊 **Summary:**
- Incident Title: {incident_sum.title}
- Status: {incident_sum.status}
- Priority: {incident_sum.priority}
- Created: {incident_sum.created}
- Last Updated: {incident_sum.last_updated}
- Related Alerts: {len(alerts)}

🎯 **Key Information:**
- Source IPs: {', '.join(incident_sum.source_ips or ['None'])}
- Destination IPs: {', '.join(incident_sum.destination_ips or ['None'])}
"""
            return response
            
        except Exception as e:
            return f"❌ Error retrieving incident {incident_id}: {str(e)}"
    
    def get_incident_stats(self, time_range: str = "last 7 days") -> str:
        """Get incident statistics"""
        try:
            # Parse time range
            time_params = self._parse_time_range(time_range)
            
            stats_text = fetch_incident_stats_text(
                self.client, 
                since=time_params.get('since'),
                until=time_params.get('until')
            )
            
            return f"📈 **Incident Statistics ({time_range}):**\n\n{stats_text}"
            
        except Exception as e:
            return f"❌ Error retrieving statistics: {str(e)}"
    
    def search_by_ip(self, ip_address: str) -> str:
        """Search for sessions by IP address"""
        try:
            sessions = query_sessions_by_ip(self.client, ip_address, limit=20)
            
            if not sessions or 'results' not in sessions or len(sessions.get('results', [])) == 0:
                return f"🔍 No sessions found for IP: {ip_address}"
            
            results = sessions.get('results', [])[:10]  # Limit to 10 sessions
            
            response_lines = [f"📡 **Sessions for IP {ip_address}:**", ""]
            
            for idx, session in enumerate(results, 1):
                session_id = session.get('id', 'N/A')
                timestamp = session.get('time', session.get('timestamp', 'N/A'))
                src_ip = session.get('src_ip', session.get('ip.src', 'N/A'))
                dst_ip = session.get('dst_ip', session.get('ip.dst', 'N/A'))
                
                response_lines.append(f"{idx}. **Session ID:** {session_id}")
                response_lines.append(f"   - Time: {timestamp}")
                response_lines.append(f"   - Source: {src_ip} → Destination: {dst_ip}")
                response_lines.append(f"   - Protocol: {session.get('service', session.get('protocol', 'N/A'))}")
                response_lines.append("")
            
            response_lines.append(f"📊 Total sessions found: {len(sessions.get('results', []))} (showing 10)")
            
            return "\n".join(response_lines)
            
        except Exception as e:
            return f"❌ Error searching for IP {ip_address}: {str(e)}"
    
    def get_recent_alerts(self, count: int = 10, time_range: str = "last 24 hours") -> str:
        """Get recent alerts"""
        try:
            time_params = self._parse_time_range(time_range)
            
            total_count, alerts = get_alerts_brief(
                self.client,
                since=time_params.get('since'),
                until=time_params.get('until'),
                max_alerts=count
            )
            
            if total_count == 0:
                return f"🔔 No alerts found for the specified time period ({time_range})."
            
            response_lines = [f"🚨 **Recent Alerts ({time_range}):**", f"Total alerts: {total_count}", ""]
            
            for idx, alert in enumerate(alerts[:count], 1):
                response_lines.append(f"{idx}. **{alert.title}**")
                response_lines.append(f"   - ID: {alert.id}")
                response_lines.append(f"   - Severity: {alert.severity}")
                response_lines.append(f"   - Created: {alert.created}")
                response_lines.append(f"   - Source: {alert.source}")
                if alert.source_ips:
                    response_lines.append(f"   - Source IPs: {', '.join(alert.source_ips)}")
                response_lines.append("")
            
            return "\n".join(response_lines)
            
        except Exception as e:
            return f"❌ Error retrieving alerts: {str(e)}"
    
    def _parse_time_range(self, time_range: str) -> Dict[str, Optional[str]]:
        """Parse time range string to date parameters"""
        now = datetime.now()
        
        if "today" in time_range.lower():
            today = now.strftime('%Y-%m-%d')
            return {'since': today}
        elif "yesterday" in time_range.lower():
            yesterday = (now - timedelta(days=1)).strftime('%Y-%m-%d')
            today = now.strftime('%Y-%m-%d')
            return {'since': yesterday, 'until': today}
        elif "last 24 hours" in time_range.lower() or "past day" in time_range.lower():
            yesterday_time = (now - timedelta(hours=24)).strftime('%Y-%m-%dT%H:%M:%S')
            return {'since': yesterday_time}
        elif "last 7 days" in time_range.lower() or "past week" in time_range.lower():
            last_week = (now - timedelta(days=7)).strftime('%Y-%m-%d')
            return {'since': last_week}
        elif "last 30 days" in time_range.lower() or "past month" in time_range.lower():
            last_month = (now - timedelta(days=30)).strftime('%Y-%m-%d')
            return {'since': last_month}
        else:
            # Default: last 7 days
            last_week = (now - timedelta(days=7)).strftime('%Y-%m-%d')
            return {'since': last_week}