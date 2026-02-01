import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
import requests

@dataclass
class NetWitnessConfig:
    # Public domain URL for NetWitness
    domain: str = "uvo1gp037tg5ufq0prf.vm.cld.sr"

    # Respond API (Incidents/Alerts) over 443 with token
    respond_port: int = 443
    respond_username: str = "admin"
    respond_password: str = "Password123!"

    # Metadata API over Port 12346 (Fallback Port 50103) with basic auth
    metadata_port_primary: int = 12346
    metadata_port_fallback: int = 50103
    metadata_username: str = "admin"
    metadata_password: str = "netwitness"

    # TLS Handler
    verify_ssl: bool = False
    timeout_secs: int = 30

class NetWitnessClient:
    '''
    Dual-Port Client for NetWitness Respond and Metadata APIs
      - Respond API: https://{domain}:443/rest/api/... uses Netwitness-Token
      - Metadata API: https://{domain}:12346/sdk?msg=query... uses Basic Auth
    '''

    def __init__(self, config: NetWitnessConfig):
        self.config = config
        self.respond_token: Optional[str] = None
        self.refresh_token: Optional[str] = None
        self._token_acquired_at: float = 0.0
        
        self.session = requests.Session()
        self.session.verify = config.verify_ssl

    #--------------------------
    # URL Builders
    #--------------------------   
    def _respond_base_url(self) -> str:
        # Avoid explicitly adding :443 for standard HTTPS, as some proxies/WAFs behave oddly with explicit 443
        if int(self.config.respond_port) == 443:
            return f"https://{self.config.domain}"
        return f"https://{self.config.domain}:{self.config.respond_port}"
    
    def metadata_base_url(self, port: int) -> str:
        # Metadata ports are typically non-443 (e.g., 12346 / 50103), but keep the same safe logic anyway
        if int(port) == 443:
            return f"https://{self.config.domain}"
        return f"https://{self.config.domain}:{port}"
    
    #--------------------------
    # Token Authentication (Respond API)
    #--------------------------
    def authenticate(self, force: bool = False) -> str:
        '''
        Obtain (or reuse) access token for Respond API
        '''
        if self.respond_token and not force:
            return self.respond_token
        
        url = f"{self._respond_base_url()}/rest/api/auth/userpass"
        params = {
            "username": self.config.respond_username,
            "password": self.config.respond_password
        }

        headers = {
            "Accept": "application/json;charset=UTF-8",
            "Content-Type": "application/x-www-form-urlencoded; charset=ISO-8859-1",
        }

        response = self.session.post(url, params=params, headers=headers, timeout=self.config.timeout_secs)
        response.raise_for_status()

        data = response.json()
        token = data.get("accessToken") or data.get("token")
        if not token:
            raise RuntimeError(f"Authentication succeeded but no accessToken returned: {data}")
        
        self.respond_token = token
        self.refresh_token = data.get("refreshToken") or data.get("refresh_token")
        self._token_acquired_at = time.time()
        return token
    
    def _respond_headers(self) -> Dict[str, str]:
        token = self.authenticate()
        return {
            "Accept": "application/json;charset=UTF-8",
            "Netwitness-Token": token
        }
    
    def _respond_get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Any:
        url = f"{self._respond_base_url()}{path}"
        headers = self._respond_headers()
        response = self.session.get(url, headers=headers, params=params, timeout=self.config.timeout_secs)

        # If token expired, retry with a new token
        if response.status_code == 401:
            self.authenticate(force=True)
            headers = self._respond_headers()
            response = self.session.get(url, headers=headers, params=params, timeout=self.config.timeout_secs)

        try:
            response.raise_for_status()
        except requests.HTTPError as e:
            # Include a short response body snippet to make CloudShare 500s debuggable
            body = (response.text or "")
            snippet = body[:400].replace("\n", " ").replace("\r", " ")
            raise requests.HTTPError(
                f"{e} | URL={url} | status={response.status_code} | body={snippet}",
                response=response,
            )

        # Some endpoints may return empty body
        if not response.text:
            return {}
        return response.json()
    
    #--------------------------
    # Respond API: incidents/alerts
    #-------------------------
    def get_incidents(self, incident_id: str) -> Dict[str, Any]:
        # Get /rest/api/incidents/{INC-ID}
        return self._respond_get(f"/rest/api/incidents/{incident_id}")
    
    def list_incidents(self, page_number: int = 0, page_size: int = 20) -> Dict[str, Any]:
        """List incidents (paged).
        Useful as a fallback when a specific INC-ID lookup returns a CloudShare 500.
        """
        return self._respond_get(
            "/rest/api/incidents",
            params={"pageNumber": page_number, "pageSize": page_size},
        )

    def get_incidents_alerts(
            self, incident_id: str, page_number: int = 0, page_size: int = 100
    ) -> Dict[str, Any]:
        # GET /rest/api/incidents/{INC-ID}/alerts
        return self._respond_get(
            f"/rest/api/incidents/{incident_id}/alerts",
            params={"pageNumber": page_number, "pageSize": page_size}
        )
    
    def get_alerts(
            self,
            since: Optional[str] = None,
            until: Optional[str] = None,
            page_number: int = 0,
            page_size: int = 100,
    ) -> Dict[str, Any]:
        # GET /rest/api/alerts?since=....&until=....
        params: Dict[str, Any] = {"pageNumber": page_number, "pageSize": page_size}
        if since:
            params["since"] = since
        if until:
            params["until"] = until
        return self._respond_get("/rest/api/alerts", params=params)

    def get_alert_count(self, since: Optional[str] = None, until: Optional[str] = None) -> int:
        '''
        Fast count of alerts via /rest/api/alerts/count: fetch first page and use totalItems when present.
        '''
        page = self.get_alerts(since=since, until=until, page_number=0, page_size=1)
        # Many NetWitness paginated responses include totalItems
        return int(page.get("totalItems", 0))
    
    def get_incident_stats(
            self,
            since: Optional[str] = None,
            until: Optional[str] = None,
            page_number: int = 0,
            page_size: int = 100,
    ) -> Dict[str, Any]:
        # GET /rest/api/incidents/stats?since=....&until=....
        params: Dict[str, Any] = {"pageNumber": page_number, "pageSize": page_size}
        if since:
            params["since"] = since
        if until:
            params["until"] = until
        return self._respond_get("/rest/api/incidents/stats", params=params)
    
    #--------------------------
    # Metadata API: /sdk query endpoint on port 12346 or 50103
    #--------------------------
    def metadata_query(self, netwitness_query: str) -> Dict[str, Any]:
        """
        Execute Metadata API query via /sdk endpoint with Basic Auth
        Tries primary port first, then fallback port.
        """
        ports = [self.config.metadata_port_primary, self.config.metadata_port_fallback]
        last_err: Optional[Exception] = None

        for port in ports:
            url = f"{self.metadata_base_url(port)}/sdk"
            params = {"msg": "query", "query": netwitness_query}

            try:
                resp = self.session.get(
                    url,
                    params=params,  # ✅ must be params= for GET
                    auth=(self.config.metadata_username, self.config.metadata_password),
                    timeout=self.config.timeout_secs,
                )

                # If auth is wrong, no point trying another port with same creds
                if resp.status_code in (401, 403):
                    raise RuntimeError(f"Metadata auth failed ({resp.status_code}) on port {port}: {resp.text[:200]}")

                resp.raise_for_status()

                # Try JSON first, else return raw text
                try:
                    return resp.json()
                except ValueError:
                    return {"raw": resp.text, "port": port}

            except Exception as e:
                last_err = e
                continue

        raise RuntimeError(f"Metadata query failed on ports {ports}. Last error: {last_err}")

    
    #--------------------------
    # Convenience: consolidate IP metadata
    #-------------------------
    @staticmethod
    def extract_metadata_ips(obj: Dict[str, Any]) -> Tuple[List[str], List[str]]:
        '''
        Attempts to pull sourceIP/destIP from common NetWitness alert/incident structures.
        Example fields are shown in API responses under alertMeta, :contentReference[oaiocite:7]{index=7}
        '''
        src_ips: List[str] = []
        dst_ips: List[str] = []

        # Common: incident["alertMeta"] or alert["alertmeta"]
        alert_meta = obj.get("alertMeta") or obj.get("meta") or {}
        if isinstance(alert_meta, dict):
            src = alert_meta.get("SourceIp") or alert_meta.get("sourceIp") or []
            dst = alert_meta.get("DestinationIp") or alert_meta.get("destinationIp") or []
            if isinstance(src, list):
                src_ips.extend([str(x) for x in src])
            if isinstance(dst, list):
                dst_ips.extend([str(x) for x in dst])

        # De-duplication
        src_ips = sorted(set(src_ips))
        dst_ips = sorted(set(dst_ips))
        return src_ips, dst_ips
            