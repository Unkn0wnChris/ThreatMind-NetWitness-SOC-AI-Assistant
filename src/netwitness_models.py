from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

@dataclass
class AlertSummary:
    id: str
    severity: Optional[str] = None
    title: str = ""
    created: str = ""
    source: str = ""
    detail: str = ""
    source_ips: List[str] = field(default_factory=list)
    destination_ips: List[str] = field(default_factory=list)

@dataclass
class IncidentSummary:
    id: str
    severity: Optional[str] = None
    priority: Optional[str] = None
    status: str = ""
    title: str = ""
    created: str = ""
    last_updated: str = ""
    source_ips: List[str] = field(default_factory=list)
    destination_ips: List[str] = field(default_factory=list)
    raw: Optional[Dict[str, Any]] = None