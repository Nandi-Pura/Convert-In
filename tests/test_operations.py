import logging

from app.core import operations


def test_operation_order_skip_completion_and_isolation(caplog):
    caplog.set_level(logging.INFO,logger="convert_in.operations")
    first=operations.create("project-a","ANALYZE",False); second=operations.create("project-b","CONVERT",True)
    operations.update(first,"VALIDATING_SOURCE","COMPLETE"); operations.update(first,"PARSING","ACTIVE"); operations.update(first,"PARSING","COMPLETE",{"constructs":4}); operations.finish(first,{"ok":True})
    state=operations.get(first)
    assert [x["name"] for x in state["stages"]]==list(operations.STAGES)
    assert next(x for x in state["stages"] if x["name"]=="RENDERING")["status"]=="SKIPPED"
    assert state["status"]==state["stage"]=="COMPLETE" and state["counts"]["PARSING"]=={"constructs":4}
    assert operations.get(second)["project_id"]=="project-b" and operations.get(second)["status"]=="RUNNING"
    assert "constructs=4" in caplog.text


def test_failure_reports_exact_stage_without_sensitive_content(caplog):
    caplog.set_level(logging.INFO,logger="convert_in.operations"); operation_id=operations.create("safe-project","CONVERT",True)
    operations.update(operation_id,"CP2","ACTIVE"); operations.fail(operation_id,"CP2",ValueError("Target profile is not available."))
    state=operations.get(operation_id)
    assert state["status"]=="FAILED" and state["stage"]=="CP2" and state["error"]["type"]=="ValueError"
    assert "stage=cp2 status=failed error_type=ValueError" in caplog.text
    assert "TOP_SECRET_SENTINEL_123" not in caplog.text and "set address SECRET" not in caplog.text