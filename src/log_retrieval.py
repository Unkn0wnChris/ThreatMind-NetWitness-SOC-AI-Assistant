"""
Log Retrieval and Query System for NetWitness Logs
Enables semantic and keyword-based searching of security logs
"""
#Imported dependencies
from typing import List, Dict, Optional
import re
from src.ollama_client import ollama_query

#Searching capabilities across the log using keyword based matching and AI semantic analysis 
class LogRetriever:
    """Intelligent log retrieval system"""
    
    #Initialise security log and indexes it for quick searching with metadata
    def __init__(self, logs: List[str], chunked: bool = False):
        """
        Initialize with a list of logs.
        
        Args:
            logs: List of security log strings or incident data
            chunked: Whether logs are pre-chunked (for tracking purposes)
        """
        self.logs = logs
        self.chunked = chunked
        self.indexed_logs = self._create_index()
    
    #Creation of searchable index via extraction of keywords, metadata/IOCs and threat indicators for uploaded logs
    def _create_index(self) -> List[Dict]:
        """
        Create an index of logs with metadata for fast searching.
        
        Returns:
            List of indexed log entries with extracted features
        """
        indexed = []
        for idx, log in enumerate(self.logs):
            entry = {
                "index": idx,
                "original": log,
                "content_lower": log.lower(),
                "keywords": self._extract_keywords(log),
                "entities": self._extract_entities(log),
                "threat_indicators": self._extract_threat_indicators(log),
            }
            indexed.append(entry)
        return indexed
    
    #Extraction of keywords in uploaded logs using regex expressions 
    def _extract_keywords(self, log: str) -> List[str]:
        """Extract key terms from log"""
        # Common security terms
        keywords_pattern = r'\b(dns|ip|port|domain|user|process|file|powershell|cmd|execute|connect|access|denied|failed|success|critical|high|medium|low|malware|phishing|exploit|ransomware|exfiltration|c2|beacon|shellcode|buffer|overflow|injection|xss|sql|privilege|escalation|lateral|movement|persistence|evasion|detection|alert|incident|breach|compromise|threat|vulnerability|patch|credential|password|token|api|endpoint|network|traffic|http|https|ftp|ssh|smtp|telnet|rdp|smb|ldap|kerberos|ntlm|authentication|authorization|firewall|proxy|vpn|encryption|hash|signature|malicious|suspicious|anomaly|outlier|baseline|deviation|statistical|behavioral|heuristic|signature|pattern|rule|yara|regex|hash|md5|sha|ssdeep|fuzzy|cardinality|entropy|codec|compression|obfuscation|packing|polymorphic|metamorphic)\b'
        found = re.findall(keywords_pattern, log.lower())
        return list(set(found))
    
    #Identifies and categorizes metadata/IOCs from log text 
    def _extract_entities(self, log: str) -> Dict:
        """Extract IP addresses, domains, files, users, etc."""
        entities = {
            "ips": [],
            "domains": [],
            "files": [],
            "users": [],
            "ports": [],
        }
        
        # IP addresses
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        entities["ips"] = re.findall(ip_pattern, log)
        
        # Domains
        domain_pattern = r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b'
        entities["domains"] = re.findall(domain_pattern, log.lower())
        
        # File extensions
        file_pattern = r'\b[\w-]+\.(?:exe|dll|ps1|bat|cmd|scr|jar|zip|rar|7z|gz|tar|iso|dmg|app|bin|so|o|obj|lib|a|out|txt|log|conf|cfg|ini|xml|json|yaml|yml|py|js|php|asp|jsp|html|css|sh|bash|ksh|csh|zsh|fish)\b'
        entities["files"] = re.findall(file_pattern, log.lower())
        
        # Port numbers
        port_pattern = r'(?:port|:)\s*(\d{1,5})\b'
        entities["ports"] = re.findall(port_pattern, log.lower())
        
        return entities
    
    #Detection of attack types, severity levels and incident statuses through pattern matching
    def _extract_threat_indicators(self, log: str) -> Dict:
        """Extract threat-related indicators"""
        indicators = {
            "attack_types": [],
            "severity": None,
            "status": None,
        }
        
        # Attack types
        attack_patterns = {
            "dns": r'\bdns\b',
            "malware": r'\b(malware|trojan|worm|virus|ransomware|spyware|rootkit|botnet)\b',
            "exfiltration": r'\b(exfiltration|data\s+leak|data\s+loss|theft)\b',
            "command_execution": r'\b(powershell|cmd|execute|command|shell|bash|sh|spawn)\b',
            "lateral_movement": r'\b(lateral\s+movement|lateral\s+move|pivot|hop)\b',
            "persistence": r'\b(persistence|startup|registry|scheduled\s+task|cron)\b',
            "privilege_escalation": r'\b(privilege\s+escalation|privilege\s+escalate|sudo|runas|uac\s+bypass)\b',
            "reconnaissance": r'\b(reconnaissance|scan|enumerate|discovery|fingerprint)\b',
            "defense_evasion": r'\b(evasion|obfuscation|encryption|hiding|stealth|detection\s+evasion)\b',
        }
        
        log_lower = log.lower()
        for attack_type, pattern in attack_patterns.items():
            if re.search(pattern, log_lower):
                indicators["attack_types"].append(attack_type)
        
        # Severity
        if re.search(r'\b(critical|severity\s*[:=]\s*critical)\b', log_lower):
            indicators["severity"] = "CRITICAL"
        elif re.search(r'\b(high|severity\s*[:=]\s*high)\b', log_lower):
            indicators["severity"] = "HIGH"
        elif re.search(r'\b(medium|severity\s*[:=]\s*medium)\b', log_lower):
            indicators["severity"] = "MEDIUM"
        elif re.search(r'\b(low|severity\s*[:=]\s*low)\b', log_lower):
            indicators["severity"] = "LOW"
        
        # Status
        if re.search(r'\b(resolved|closed|completed|fixed)\b', log_lower):
            indicators["status"] = "RESOLVED"
        elif re.search(r'\b(in\s+progress|investigating|pending)\b', log_lower):
            indicators["status"] = "IN_PROGRESS"
        elif re.search(r'\b(new|open|unresolved)\b', log_lower):
            indicators["status"] = "NEW"
        
        return indicators
    
     #Perform traditional keyword search matching with weighted scoring 
    def keyword_search(self, query: str, top_k: int = 5) -> List[Dict]:
        """
        Simple keyword-based search of logs.
        
        Args:
            query: Search query (e.g., "DNS")
            top_k: Number of results to return
            
        Returns:
            List of matching logs with relevance scores
        """
        query_lower = query.lower()
        query_terms = set(query_lower.split())
        
        results = []
        for entry in self.indexed_logs:
            # Match against keywords and content
            keyword_matches = sum(1 for term in query_terms if term in entry["keywords"])
            content_matches = sum(1 for term in query_terms if term in entry["content_lower"])
            
            # Check entity matches
            entity_matches = 0
            entities = entry["entities"]
            for term in query_terms:
                entity_matches += sum(1 for e in entities.get("domains", []) if term in e)
                entity_matches += sum(1 for e in entities.get("ips", []) if term in e)
                entity_matches += sum(1 for e in entities.get("files", []) if term in e)
            
            score = (keyword_matches * 3) + (content_matches * 2) + (entity_matches * 1.5)
            
            if score > 0:
                results.append({
                    "index": entry["index"],
                    "log": entry["original"],
                    "relevance_score": score,
                    "matched_keywords": [t for t in query_terms if t in entry["keywords"]],
                })
        
        # Sort by relevance and return top_k
        results.sort(key=lambda x: x["relevance_score"], reverse=True)
        return results[:top_k]
    
    # Use of AI to interpret analyst queries and convert to structured search for log matching 
    def semantic_search(self, query: str, top_k: int = 5) -> List[Dict]:
        """
        AI-powered semantic search using natural language understanding.
        
        Args:
            query: Natural language query (e.g., "Show all cases involving DNS attacks")
            top_k: Number of results to return
            
        Returns:
            List of semantically relevant logs
        """
        prompt = f"""
You are a log analysis expert. I have {len(self.logs)} security logs/incidents.

User Query: {query}

Analyze the query and determine:
1. What specific security event types to look for (e.g., DNS, malware, data exfiltration)
2. What entities to match (domains, IPs, file names, users)
3. What severity levels are relevant
4. What status filters apply (new, in progress, resolved)

Return a JSON object with these search criteria:
{{
    "event_types": ["list", "of", "security", "event", "types"],
    "entities": {{"domains": ["list"], "ips": ["list"], "files": ["list"]}},
    "severity_filter": "CRITICAL|HIGH|MEDIUM|LOW|None",
    "status_filter": "NEW|IN_PROGRESS|RESOLVED|None",
    "keywords": ["list", "of", "important", "keywords"]
}}

Return ONLY valid JSON, no other text.
"""
        
        try:
            response = ollama_query(prompt)
            import json
            criteria = json.loads(response)
        except:
            # Fallback to keyword search if AI parsing fails
            return self.keyword_search(query, top_k)
        
        # Filter logs based on criteria
        results = []
        for entry in self.indexed_logs:
            score = 0
            
            # Match event types
            if criteria.get("event_types"):
                for event_type in criteria["event_types"]:
                    if event_type.lower() in entry["threat_indicators"]["attack_types"]:
                        score += 2
            
            # Match severity
            if criteria.get("severity_filter") and criteria["severity_filter"] != "None":
                if entry["threat_indicators"]["severity"] == criteria["severity_filter"]:
                    score += 1.5
            
            # Match status
            if criteria.get("status_filter") and criteria["status_filter"] != "None":
                if entry["threat_indicators"]["status"] == criteria["status_filter"]:
                    score += 1
            
            # Match keywords
            if criteria.get("keywords"):
                for keyword in criteria["keywords"]:
                    if keyword.lower() in entry["content_lower"]:
                        score += 1
            
            # Match entities
            if criteria.get("entities"):
                for domain in criteria["entities"].get("domains", []):
                    if domain.lower() in entry["content_lower"]:
                        score += 1.5
                for ip in criteria["entities"].get("ips", []):
                    if ip in entry["content_lower"]:
                        score += 1.5
            
            if score > 0:
                results.append({
                    "index": entry["index"],
                    "log": entry["original"],
                    "relevance_score": score,
                    "threat_indicators": entry["threat_indicators"],
                    "entities": entry["entities"],
                })
        
        results.sort(key=lambda x: x["relevance_score"], reverse=True)
        return results[:top_k]
    
    #Creation of formatted summary of relevance score and previewing of log 
    def get_logs_summary(self, logs: List[Dict]) -> str:
        """
        Generate a summary of retrieved logs.
        
        Args:
            logs: List of retrieved log entries
            
        Returns:
            Formatted summary string
        """
        if not logs:
            return "No logs found matching the criteria."
        
        summary = f"Found {len(logs)} matching cases:\n\n"
        for i, log_entry in enumerate(logs, 1):
            summary += f"{i}. **Case {log_entry['index']}** (Relevance: {log_entry['relevance_score']:.1f})\n"
            summary += f"   {log_entry['log'][:150]}...\n\n"
        
        return summary

