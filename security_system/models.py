"""
Shared Pydantic models — these are the data contracts
that flow between agents in the pipeline.
"""

from pydantic import BaseModel, Field
from typing import Optional
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


class Endpoint(BaseModel):
    """One discovered route from the crawler."""
    url:         str
    method:      str = "GET"
    params:      list[str] = Field(default_factory=list)    # query params
    form_fields: list[str] = Field(default_factory=list)    # POST form fields
    description: str = ""


class PayloadResult(BaseModel):
    """One fired payload and the raw response."""
    endpoint:        str
    method:          str
    parameter:       str
    payload:         str
    payload_type:    str   # sqli, xss, path_traversal, idor, auth_bypass
    response_status: int
    response_body:   str
    response_time_ms: float = 0.0


class Vulnerability(BaseModel):
    """A confirmed (or suspected) vulnerability found by the Analyzer."""
    title:           str
    severity:        Severity
    vuln_type:       str
    endpoint:        str
    method:          str
    parameter:       str
    payload:         str
    evidence:        str   # what in the response proved this
    description:     str
    remediation:     str
    cvss_score:      float = 0.0


class ScanReport(BaseModel):
    """Final report produced by the Report Agent."""
    target_url:      str
    scan_timestamp:  str
    total_endpoints: int
    total_tested:    int
    vulnerabilities: list[Vulnerability]
    summary:         str
    recommendations: list[str]
    raw_markdown:    str = ""