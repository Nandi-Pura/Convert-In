from app.config import settings
from app.web.api import ingest_source_text
from fastapi import HTTPException
import pytest
from app.core.models import Vendor
from app.core.parsing import parse_config
from fastapi.testclient import TestClient
from app.main import app

client=TestClient(app)

def test_xxe_and_doctype_rejected():
    xml='<!DOCTYPE x [<!ENTITY e SYSTEM "http://example.invalid/secret">]><config>&e;</config>'
    cfg=parse_config(xml,Vendor.PALO_ALTO)
    assert cfg.warnings[0].severity == "ERROR" and not cfg.addresses

def test_oversized_input_rejected():
    with pytest.raises(HTTPException) as error:ingest_source_text("x"*(settings.max_input_bytes+1))
    assert error.value.status_code == 413

def test_api_has_no_filename_or_path_input(tmp_path):
    response=client.post("/api/analyze",data={"source":"hostname ../../escape","source_vendor":"cisco_asa","target_vendor":"paloalto","filename":"../../escape"})
    assert response.status_code == 200
    project=response.text.split("<code>",1)[1].split("</code>",1)[0]
    assert "/" not in project and "\\" not in project