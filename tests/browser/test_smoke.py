from pathlib import Path
from urllib.parse import urlparse
import pytest

pytestmark=pytest.mark.browser

def test_fortigate_offline_workflow(page,live_server):
    live_server,server_log=live_server
    external=[]; errors=[]; assets={}; failed=[]
    page.on("request",lambda request: external.append(request.url) if urlparse(request.url).scheme not in {"data","blob"} and urlparse(request.url).hostname not in {"127.0.0.1","localhost","::1"} else None)
    page.on("console",lambda message: errors.append(f"console {message.type}: {message.text}") if message.type in {"error","warning"} else None)
    page.on("pageerror",lambda error: errors.append(f"pageerror: {error}"))
    page.on("response",lambda response: assets.update({urlparse(response.url).path:response.status}) if "/static/" in response.url else None)
    page.on("response",lambda response: failed.append(f"{response.status} {response.url}") if response.status>=400 else None)
    page.goto(live_server+"/advanced")
    assert assets=={"/static/css/app.css":200,"/static/vendor/htmx/htmx.min.js":200,"/static/vendor/cytoscape/cytoscape.min.js":200,"/static/js/app.js":200}
    page.locator('#import-form [name="source_vendor"]').select_option("fortigate"); page.locator('#import-form [name="source_version"]').select_option("7.4"); page.locator("#target-version").select_option("11.1")
    page.locator("#file").set_input_files(str(Path("examples/fortigate/basic.conf").resolve()))
    page.wait_for_function("() => document.querySelector('#source').value.length > 0")
    page.get_by_role("button",name="Analyze & Convert").click(); page.locator("#workbench").wait_for()
    assert page.get_by_role("tabpanel",name="Overview").is_visible()
    assert page.locator("#category-table").is_visible()
    nat=page.locator("#category-table tbody tr").filter(has_text="NAT")
    assert "0" in nat.locator("td").nth(1).inner_text() and "REVIEW REQUIRED" in nat.inner_text()
    page.get_by_role("tab",name="Migration",exact=True).click()
    assert page.locator(".mapping-table").is_visible()
    page.locator(".mapping-row").first.wait_for(); page.locator(".mapping-row input[name=target_interface]").evaluate_all("xs=>xs.forEach((x,i)=>x.value=`ethernet1/${i+1}`)")
    page.locator(".mapping-row input[name=target_zone]").evaluate_all("xs=>xs.forEach(x=>x.value=x.closest('.mapping-row').dataset.nameif)")
    for checkbox in page.locator(".mapping-row input[name=confirmed]").all(): checkbox.check()
    page.locator("#migration-mappings button[type=submit]").click()
    page.locator("#migration-status").get_by_text("Mappings saved.").wait_for()
    page.locator("#migration-generate").click()
    page.locator("#migration-status").get_by_text("entities",exact=False).wait_for()
    page.get_by_role("tab",name="Candidate",exact=True).click()
    assert page.locator("#migration-candidate").is_visible()
    page.get_by_role("tab",name="Review",exact=True).click()
    assert page.locator(".review-workbench").is_visible()
    page.locator("#review-filters").select_option("NOT_REVIEWED")
    page.locator("#review-list button").first.wait_for()
    while page.locator("#review-list button").count():
        remaining=page.locator("#review-list button").count()
        page.locator("#review-list button").first.click(); page.locator("#review-detail select").select_option("ACCEPTED")
        with page.expect_response(lambda response:"/migration/review/" in response.url) as save_response: page.get_by_role("button",name="Save Engineer Review").click()
        if not save_response.value.ok:
            body=save_response.value.text(); log=Path(server_log).read_text(encoding="utf-8")
            pytest.fail(f"review save HTTP {save_response.value.status}: {body}\nServer exception:\n{log[-8000:]}")
        page.wait_for_function("count => document.querySelectorAll('#review-list button').length < count",arg=remaining)
    page.get_by_role("tab",name="Validation",exact=True).click()
    assert page.get_by_role("heading",name="Application Validation").is_visible()
    assert page.get_by_role("heading",name="PAN-OS Lab Validation").is_visible()
    with page.expect_response(lambda response:"/migration/validate" in response.url) as validation_response: page.locator("#migration-validate").click()
    assert validation_response.value.ok,validation_response.value.text()
    page.wait_for_function("() => document.querySelector('#validation-result').textContent !== 'Not run.'")
    assert "BLOCKING" not in page.locator("#validation-result").inner_text()
    page.get_by_role("tab",name="Export",exact=True).click()
    assert page.locator("#export-manifest").is_visible()
    with page.expect_download() as download: page.locator("#review-package").click()
    assert download.value.suggested_filename.endswith(".zip")
    assert not external,external
    assert not failed,failed
    assert not errors,errors

def test_malformed_is_recoverable(page,live_server):
    live_server,_=live_server
    page.goto(live_server+"/advanced"); page.get_by_role("tab",name="Paste").click(); page.locator("#source").fill("not a firewall configuration"); page.get_by_role("button",name="Analyze & Convert").click()
    page.wait_for_timeout(300); assert page.locator("#source").input_value()=="not a firewall configuration"

def open_result(page,live_server):
    page.goto(live_server)
    page.get_by_role("textbox",name="Configuration").fill(Path("examples/fortigate/basic.conf").read_text())
    page.get_by_role("button",name="Use pasted configuration").click()
    page.get_by_role("button",name="Analyze / Convert").click()
    page.get_by_role("tab",name="Raw Comparison").wait_for(timeout=120000)


def test_configmorph_workbench_flow_and_safety(page,live_server):
    live_server,_=live_server; page.set_viewport_size({"width":1440,"height":900}); open_result(page,live_server)
    assert page.get_by_text("Network Configuration Migration Workbench").is_visible()
    assert page.get_by_text("Visualize. Analyze. Migrate.").is_visible()
    assert page.locator(".compare > section").count()==3
    for tab in ("Semantic Diff","Raw Comparison","Findings","Migration Plan","Evidence"):
        page.get_by_role("tab",name=tab,exact=True).click(); assert page.get_by_role("tab",name=tab,exact=True).get_attribute("aria-selected")=="true"
    page.get_by_role("tab",name="Raw Comparison",exact=True).click()
    page.get_by_role("button",name="Blocked",exact=False).click()
    blocked=page.locator(".status > button").first
    if blocked.count():
        blocked.click(); assert page.get_by_role("button",name="Copy Selected").is_disabled()
    assert page.get_by_text("Engineer Review Required",exact=False).is_visible()


def test_configmorph_viewports_and_focus(page,live_server):
    live_server,_=live_server; page.set_viewport_size({"width":1280,"height":800}); open_result(page,live_server)
    for width,height in ((1280,800),(1440,900),(1600,900),(1920,1080)):
        page.set_viewport_size({"width":width,"height":height})
        assert page.evaluate("document.documentElement.scrollHeight <= document.documentElement.clientHeight + 1")
        assert page.evaluate("document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1")
    page.get_by_role("button",name="Expand").click(); assert "focus" in page.locator("main").get_attribute("class")
    page.keyboard.press("Escape"); assert "focus" not in page.locator("main").get_attribute("class")


def test_configmorph_line_accounting_and_project_export(page,live_server):
    live_server,_=live_server; open_result(page,live_server)
    values=[int(x.rstrip('%')) for x in page.locator(".conversion p > b").all_text_contents()]
    assert sum(values)==100
    assert page.get_by_role("link",name="Export Project").is_visible()
    assert "7.4" in page.locator(".context article").first.inner_text()
