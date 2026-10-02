import os, sys
from pathlib import Path
import pytest
ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path: sys.path.insert(0,str(ROOT))
os.environ.setdefault("API_KEY","dev-analyst-key")
os.environ.setdefault("RATE_LIMIT_PER_MINUTE","10000")

@pytest.fixture
def normal_flow():
    return {"flow_id":"T-FLOW-001","timestamp":"2026-09-29T10:00:00+00:00","source_ip":"192.0.2.10","destination_ip":"198.51.100.20","source_port":50000,"destination_port":443,"protocol":"TCP","packet_count":40,"byte_count":30000,"duration_seconds":5,"connection_count":3,"failed_connection_count":0,"syn_count":2,"rst_count":0,"unique_destination_ports":1,"unique_destination_ips":1}
