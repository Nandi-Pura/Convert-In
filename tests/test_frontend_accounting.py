from app.web.api import _line_accounting


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