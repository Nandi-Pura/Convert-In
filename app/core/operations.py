import logging
import threading
import time
from copy import deepcopy
from uuid import uuid4

logger=logging.getLogger("convert_in.operations")
STAGES=("VALIDATING_SOURCE","PARSING","NORMALIZING","CP0","CP1","CP2","RENDERING","SEMANTIC_DIFF","FINDINGS","FINALIZING","COMPLETE")
_operations={}; _lock=threading.Lock()

def create(project_id:str,operation_type:str,render:bool,context:dict|None=None):
    operation_id=str(uuid4()); stages=[{"name":name,"status":"SKIPPED" if name=="RENDERING" and not render else "PENDING","counts":{}} for name in STAGES]
    state={"operation_id":operation_id,"project_id":project_id,"operation_type":operation_type,"status":"RUNNING","stage":"VALIDATING_SOURCE","stages":stages,"counts":{},"error":None,"started":time.perf_counter(),"completed":False,"result":None,"context":context or {}}
    with _lock:_operations[operation_id]=state
    update(operation_id,"VALIDATING_SOURCE","ACTIVE")
    return operation_id

def update(operation_id:str,stage:str,status:str,counts:dict|None=None):
    now=time.perf_counter()
    with _lock:
        state=_operations[operation_id]; item=next(x for x in state["stages"] if x["name"]==stage)
        if status=="ACTIVE": item["started"]=now; state["stage"]=stage
        if status in {"COMPLETE","WARNING","FAILED"}: item["duration_ms"]=round((now-item.get("started",now))*1000); item["counts"]=counts or {}; state["counts"][stage]=counts or {}
        item["status"]=status; context=state["context"]
    fields=" ".join(f"{key}={value}" for key,value in ({"project":state["project_id"],**context,"stage":stage.lower(),"status":status.lower(),"duration_ms":item.get("duration_ms"),**(counts or {})}).items() if value is not None)
    logger.info("convert %s",fields)

def finish(operation_id:str,result:dict):
    update(operation_id,"FINALIZING","COMPLETE"); update(operation_id,"COMPLETE","COMPLETE")
    with _lock:
        state=_operations[operation_id]; state.update(status="COMPLETE",stage="COMPLETE",completed=True,result=result,finished=time.perf_counter())
    logger.info("convert project=%s status=completed duration_ms=%s",state["project_id"],round((state["finished"]-state["started"])*1000))

def fail(operation_id:str,stage:str,error:Exception):
    update(operation_id,stage,"FAILED")
    with _lock:
        state=_operations[operation_id]; state.update(status="FAILED",stage=stage,completed=True,error={"type":type(error).__name__,"message":str(error)},finished=time.perf_counter())
    logger.error("convert project=%s stage=%s status=failed error_type=%s",state["project_id"],stage.lower(),type(error).__name__)

def get(operation_id:str):
    with _lock:
        state=deepcopy(_operations.get(operation_id))
    if not state:return None
    end=state.get("finished",time.perf_counter()); state["elapsed_ms"]=round((end-state["started"])*1000)
    for key in ("started","finished","context"):state.pop(key,None)
    return state