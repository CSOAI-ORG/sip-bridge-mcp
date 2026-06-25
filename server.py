#!/usr/bin/env python3
"""
SIP (telephony / VoIP) Bridge MCP — CSOAI Layer-0 legacy-bridge family.
Parse SIP messages, map to modern call events, govern telecom (STIR/SHAKEN / lawful intercept / privacy).
Sibling of cobol-bridge-mcp.
Tools: parse_sip · map_to_modern · govern_telecom
"""
from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional

mcp = FastMCP("SIP Bridge", instructions="Bridge SIP / VoIP signalling to ONE OS — parse, map, govern telecom (STIR/SHAKEN, lawful intercept, privacy).")

# ── SIGIL: every governed action → one signed hash-chained hop (SIGIL_LOG unifies all layers) ──
import hashlib as _hl, time as _t, json as _j, os as _os
_SIGIL_LOG = _os.environ.get("SIGIL_LOG", _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "bridge_sigil.log"))
def _sigil(op, body):
    try:
        prev = ""
        if _os.path.exists(_SIGIL_LOG):
            with open(_SIGIL_LOG) as f:
                ls = f.readlines()
                if ls: prev = _j.loads(ls[-1]).get("digest", "")
        ts = int(_t.time()); dg = _hl.sha256(f"{op}|{ts}|{prev[:8]}|{body}".encode()).hexdigest()[:16]
        _os.makedirs(_os.path.dirname(_SIGIL_LOG), exist_ok=True)
        with open(_SIGIL_LOG, "a") as f: f.write(_j.dumps({"ts": ts, "op": op, "body": body, "prev_digest": prev, "digest": dg}) + "\n")
        return dg
    except Exception: return ""

METHODS = {"INVITE": "Call setup", "ACK": "Ack", "BYE": "Call teardown", "CANCEL": "Cancel",
           "REGISTER": "Registration", "OPTIONS": "Capabilities", "REFER": "Transfer", "MESSAGE": "IM"}


class SIPParsed(BaseModel):
    method: Optional[str] = None
    description: str = "SIP message"
    from_uri: Optional[str] = None
    to_uri: Optional[str] = None
    call_id: Optional[str] = None
    is_status: bool = False
    status_code: Optional[str] = None
    has_identity: bool = False


class Governance(BaseModel):
    risk_flags: List[str] = Field(default_factory=list)
    frameworks: List[str] = Field(default_factory=list)
    attestable: bool = True
    note: str = ""


def _headers(message: str) -> Dict[str, str]:
    h: Dict[str, str] = {}
    for ln in (message or "").replace("\r\n", "\n").split("\n"):
        if ":" in ln and not ln.startswith(("INVITE", "SIP/", "REGISTER", "BYE", "ACK", "CANCEL", "OPTIONS", "REFER", "MESSAGE")):
            k, v = ln.split(":", 1)
            h[k.strip().lower()] = v.strip()
    return h


@mcp.tool()
def parse_sip(message: str) -> SIPParsed:
    """Parse a SIP message: method or status line + From/To/Call-ID; note Identity header (STIR/SHAKEN)."""
    first = (message or "").strip().split("\n", 1)[0].strip()
    h = _headers(message)
    p = SIPParsed(from_uri=h.get("from"), to_uri=h.get("to"), call_id=h.get("call-id"),
                  has_identity="identity" in h)
    if first.startswith("SIP/"):
        p.is_status = True
        parts = first.split()
        p.status_code = parts[1] if len(parts) > 1 else None
        p.description = "SIP response " + (p.status_code or "")
    else:
        m = first.split(" ", 1)[0].upper()
        p.method = m
        p.description = METHODS.get(m, "SIP request")
    return p


@mcp.tool()
def map_to_modern(message: str) -> Dict[str, Any]:
    """Map a SIP message to a modern call/event object for ONE OS."""
    p = parse_sip(message)
    return {"source": "SIP", "event": p.method or ("response " + (p.status_code or "")),
            "from": p.from_uri, "to": p.to_uri, "call_id": p.call_id,
            "attested_caller_id": p.has_identity, "target": "modern call event"}


@mcp.tool()
def govern_telecom(message: str) -> Governance:
    """Governance: telecom surface — caller-ID attestation, privacy, lawful-intercept (attestable)."""
    _sigil("G", "sip|govern_telecom")
    p = parse_sip(message)
    flags = []
    if p.method == "INVITE" and not p.has_identity:
        flags.append("INVITE without Identity header — no STIR/SHAKEN attestation (robocall/spoofing risk)")
    flags.append("Call metadata is personal data — GDPR/ePrivacy retention + access controls")
    return Governance(risk_flags=flags,
                      frameworks=["STIR/SHAKEN (RFC 8224)", "GDPR / ePrivacy", "CALEA / lawful intercept", "Ofcom/FCC telecom rules"],
                      note="CSOAI governs the bridge: call-signalling lineage attestable on the ledger.")


def main():
    mcp.run()


if __name__ == "__main__":
    main()
