import sys,os
sys.path.insert(0,os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import server

INV="INVITE sip:bob@example.com SIP/2.0\nFrom: sip:alice@example.com\nTo: sip:bob@example.com\nCall-ID: abc123\nVia: SIP/2.0/UDP"
def test_parse():
    p=server.parse_sip(INV); assert p.method=="INVITE"; assert p.call_id=="abc123"
def test_govern():
    g=server.govern_telecom(INV); assert any("SHAKEN" in f for f in g.frameworks); assert g.risk_flags
