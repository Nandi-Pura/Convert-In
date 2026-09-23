import re
from pathlib import Path
from fastapi.testclient import TestClient
from app.main import app

client=TestClient(app)
def test_analysis_graph_impact_and_references_api():
    source=Path("examples/fortigate/basic.conf").read_text()
    response=client.post("/api/analyze",data={"source":source,"source_vendor":"fortigate","target_vendor":"paloalto"})
    assert response.status_code==200 and "Analysis Findings" in response.text
    project=re.search(r"Project: <code>([^<]+)",response.text).group(1)
    assert client.get(f"/api/projects/{project}/analysis").status_code==200
    graph=client.get(f"/api/projects/{project}/graph"); assert graph.status_code==200 and graph.json()["edges"]>0
    nodes=graph.json()["graph"]["nodes"]; address=next(x for x in nodes if x["type"]=="address")
    assert client.get(f"/api/projects/{project}/impact/{address['object_id']}").status_code==200
    assert client.get(f"/api/projects/{project}/objects/{address['object_id']}/references").status_code==200
    assert client.get(f"/api/projects/{project}/impact/no-such-object").status_code==404

def test_finding_html_escapes_source_names():
    source="object network <script>alert(1)</script>\n host 10.0.0.1"
    response=client.post("/api/analyze",data={"source":source,"source_vendor":"cisco_asa","target_vendor":"paloalto"})
    assert "<script>alert(1)</script>" not in response.text

def test_bounded_graph_search_and_scopes():
    source=Path("examples/fortigate/basic.conf").read_text()
    response=client.post("/api/analyze",data={"source":source,"source_vendor":"fortigate","target_vendor":"paloalto"})
    project=re.search(r"Project: <code>([^<]+)",response.text).group(1)
    full=client.get(f"/api/projects/{project}/graph").json()["graph"]["nodes"]
    policy=next(x for x in full if x["type"]=="security_policy")
    address=next(x for x in full if x["type"]=="address")
    found=client.get(f"/api/projects/{project}/graph/search",params={"q":policy["name"]}).json()
    assert found and found[0]["id"]==policy["id"]
    dependencies=client.get(f"/api/projects/{project}/graph/scope",params={"root":policy["object_id"],"mode":"policy","depth":3,"limit":2})
    assert dependencies.status_code==200
    scope=dependencies.json(); assert len(scope["graph"]["nodes"])<=2 and scope["root"]["id"]==policy["id"]
    impact=client.get(f"/api/projects/{project}/graph/scope",params={"root":address["object_id"],"mode":"impact"}).json()
    assert any(x["type"]=="security_policy" for x in impact["graph"]["nodes"])
    assert client.get(f"/api/projects/{project}/graph/scope",params={"root":address["object_id"],"depth":4}).status_code==422
    assert client.get(f"/api/projects/{project}/graph/scope",params={"root":address["object_id"],"mode":"whole"}).status_code==400

def test_visualizer_uses_only_local_assets():
    page=client.get("/advanced")
    assert "/static/vendor/cytoscape/cytoscape.min.js" in page.text
    assert "https://" not in page.text and "http://" not in page.text
    assert client.get("/static/vendor/cytoscape/cytoscape.min.js").status_code==200