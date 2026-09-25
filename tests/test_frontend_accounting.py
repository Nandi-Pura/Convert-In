from app.web.api import _line_accounting
from fastapi.testclient import TestClient
from app.main import app


def test_line_accounting_uses_unique_source_lines_and_safety_precedence():
    entities=[
        {"user_status":"READY","source_lines":[1,2]},
        {"user_status":"REVIEW REQUIRED","source_lines":[2,3]},
        {"user_status":"BLOCKED","source_lines":[3,4]},
    ]
    assert _line_accounting("1\n2\n3\n4\n5\n",entities)=={
        "total_analyzed_lines":5,
        "converted_lines":1,
        "review_lines":1,
        "unsupported_lines":2,
        "unchanged_lines":1,
        "method":"UNIQUE_PROVENANCE_ANCHORS_V1",
    }


def test_line_accounting_handles_empty_source():
    assert _line_accounting("",[])["total_analyzed_lines"]==0


def test_detection_returns_exact_fortios_patch_version():
    source="#config-version=FG39E8-7.0.13-FW-build0000-000000:opmode=0:vdom=0:user=admin\nconfig firewall address\nend\nconfig firewall policy\nend\n"
    response=TestClient(app).post("/api/convert/detect",json={"source_text":source})
    assert response.status_code==200
    assert response.json()["version"]=="7.0.13"