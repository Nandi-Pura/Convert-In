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
    page.goto(live_server+"/advanced"); page.get_by_role("tab",name="Paste").click(); page.locator("#source").fill("not a firewall configuration")
    with page.expect_response(lambda response: response.url.endswith("/api/analyze")) as response: page.get_by_role("button",name="Analyze & Convert").click()
    assert response.value.status==422; assert page.locator("#source").input_value()=="not a firewall configuration"

def open_result(page, live_server):
    import io
    import json
    import zipfile

    source = "\n".join(f"source-line-{i}" for i in range(1500))
    profile = {"id": "ui-source", "vendor": "PALO_ALTO", "platform": "PAN_OS", "domain": "FIREWALL", "supported_versions": [], "target_capability": "", "version": "10.2.8"}
    entity = {"entity_type": "address", "source_snippet": "", "source_lines": [1], "target_snippet": "", "findings": []}
    result = {
        "project_id": "ui-fixture", "mode": "CONVERT", "renderer_available": True,
        "source_profile": profile, "target_profile": {**profile, "id": "ui-target", "version": "11.1.6"},
        "source_text": source, "candidate": "READY_ONLY\n" + "\n".join(f"# candidate-line-{i}" for i in range(1500)),
        "cp0_summary": {}, "cp1_summary": {}, "cp2_summary": {},
        "entities": [
            {**entity, "id": "ready", "source_title": "Ready address", "user_status": "READY", "detailed_status": "EXACT", "copyable": True, "commands": ["READY_ONLY"]},
            {**entity, "id": "review", "source_title": "Review address", "user_status": "REVIEW REQUIRED", "detailed_status": "MANUAL_REVIEW", "copyable": True, "commands": ["REVIEW_ONLY"]},
            {**entity, "id": "blocked", "source_title": "Blocked address", "user_status": "BLOCKED", "detailed_status": "UNSUPPORTED", "copyable": True, "commands": ["BLOCKED_ONLY"]},
        ],
        "lint_findings": [],
        "semantic_diff": {"entities": [{"entity_id": "ready", "entity_type": "address", "source_identity": "Ready address", "overall_classification": "PRESERVED", "property_diffs": []}]},
        "line_accounting": {"total_analyzed_lines": 1500, "converted_lines": 900, "review_lines": 300, "unsupported_lines": 150, "unchanged_lines": 150, "method": "UI test fixture"},
    }
    manifest = {"project_id": "ui-fixture", "source": {"filename": "ui-fixture.cfg", "size_bytes": len(source), "line_count": 1500, "exact_version": "10.2.8"}, "target": {"exact_version": "11.1.6"}, "artifacts": {}, "fingerprint": "fixture"}
    page.route("**/api/projects/ui-fixture", lambda route: route.fulfill(json={"manifest": manifest, "source_text": source, "result": result}))
    page.route("**/api/projects/ui-fixture/migration/plan", lambda route: route.fulfill(json={"plan_id": "fixture", "summary": {"total_entities": 0}, "entities": [], "blocked": [], "advisories": []}))
    page.route("**/api/projects/ui-fixture/migration/evidence-pack", lambda route: route.fulfill(json={"fingerprint": "fixture", "artifacts": []}))
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as zipped:
        zipped.writestr("manifest.json", json.dumps(manifest))
    page.route("**/api/projects/ui-fixture/export", lambda route: route.fulfill(body=archive.getvalue(), headers={"Content-Type": "application/zip", "Content-Disposition": 'attachment; filename="ui-fixture.zip"'}))
    page.goto(live_server)
    page.once("dialog", lambda dialog: dialog.accept("ui-fixture"))
    page.get_by_role("button", name="Project: Untitled", exact=True).click()
    page.locator(".locked-comparison").wait_for()
    return result


def test_configmorph_workbench_flow_and_safety(page, context, live_server):
    context.grant_permissions(["clipboard-read", "clipboard-write"])
    page.set_viewport_size({"width": 1440, "height": 900})
    open_result(page, live_server[0])
    assert page.get_by_text("Network Configuration Migration", exact=True).is_visible()
    for tab in ("Raw Comparison", "Semantic Diff", "Migration Plan", "Candidate Configuration", "Evidence"):
        page.get_by_role("tab", name=tab, exact=True).click()
        assert page.get_by_role("tab", name=tab, exact=True).get_attribute("aria-selected") == "true"
    page.get_by_role("tab", name="Candidate Configuration", exact=True).click()
    page.get_by_role("button", name="Copy All READY", exact=True).click()
    page.locator("#result-panel").get_by_role("status").wait_for()
    copied = page.evaluate("navigator.clipboard.readText()")
    assert "READY_ONLY" in copied
    assert "REVIEW_ONLY" not in copied
    assert "BLOCKED_ONLY" not in copied
    assert "ENGINEER REVIEW REQUIRED" in copied
    assert page.locator("footer").get_by_text("CANDIDATE CONFIGURATION", exact=False).is_visible()


def test_configmorph_visual_composition(page, live_server):
    page.set_viewport_size({"width": 1440, "height": 900})
    open_result(page, live_server[0])
    boxes = [page.locator(selector).bounding_box() for selector in (".source-card", ".target-card", ".conversion-success")]
    assert max(box["y"] for box in boxes) - min(box["y"] for box in boxes) < 2
    assert boxes[2]["x"] > boxes[1]["x"]
    panes = page.locator(".locked-comparison > .locked-editor")
    assert panes.count() == 2
    assert abs(panes.nth(0).bounding_box()["width"] - panes.nth(1).bounding_box()["width"]) < 2
    assert page.locator(".semantic-markers").count() == 0
    assert page.locator(".conversion-summary").is_visible()


def test_configmorph_viewports_and_keyboard_tabs(page, live_server):
    page.set_viewport_size({"width": 1440, "height": 900})
    open_result(page, live_server[0])
    for width, height in ((1440,900),(1600,900),(1920,1080)):
        page.set_viewport_size({"width": width, "height": height})
        assert page.locator("main").evaluate("el => el.scrollHeight <= el.clientHeight && el.scrollWidth <= el.clientWidth")
    page.get_by_role("tab", name="Raw Comparison", exact=True).focus()
    page.keyboard.press("End")
    assert page.get_by_role("tab", name="Evidence", exact=True).get_attribute("aria-selected") == "true"
    page.keyboard.press("Home")
    assert page.get_by_role("tab", name="Raw Comparison", exact=True).get_attribute("aria-selected") == "true"


def test_configmorph_conversion_success_and_project_export(page, live_server):
    open_result(page, live_server[0])
    assert page.get_by_role("img", name="60 percent of source lines converted").is_visible()
    assert page.locator(".donut b").inner_text() == "60%"
    assert page.get_by_role("link", name="Save", exact=True).is_visible()
    with page.expect_download() as download:
        page.get_by_role("link", name="Save", exact=True).click()
    assert download.value.suggested_filename == "ui-fixture.zip"


def test_configmorph_empty_shell_and_import(page, live_server):
    page.set_viewport_size({"width": 1440, "height": 900})
    page.goto(live_server[0])
    assert page.get_by_role("heading", name="ConfigMorph", exact=True).is_visible()
    assert page.get_by_label("Source Vendor", exact=True).input_value() == ""
    assert page.get_by_label("Target Vendor", exact=True).input_value() == ""
    assert page.get_by_role("button", name="Convert", exact=True).is_disabled()
    assert page.get_by_role("img", name="Conversion results unavailable until Convert completes").is_visible()
    for tab in ("Raw Comparison", "Semantic Diff", "Migration Plan", "Candidate Configuration", "Evidence"):
        assert page.get_by_role("tab", name=tab, exact=True).is_visible()
    page.get_by_role("button", name="Paste from Clipboard").click()
    page.get_by_role("textbox", name="Configuration", exact=True).fill(Path("examples/fortigate/basic.conf").read_text())
    page.get_by_role("button", name="Use Configuration", exact=True).click()
    assert not page.get_by_role("textbox", name="Configuration", exact=True).is_visible()
    assert page.get_by_role("button", name="Convert", exact=True).is_disabled()
    assert "config system interface" in page.get_by_label("Source Configuration", exact=True).text_content()


def test_configmorph_selectors_virtualization_and_stale_result(page, live_server):
    from playwright.sync_api import expect

    open_result(page, live_server[0])
    panes = page.locator(".locked-comparison .editor-lines")
    for pane in panes.all():
        assert pane.locator(".editor-line").count() <= 80
    page.get_by_role("button", name="Filters", exact=True).click()
    expect(page.get_by_label("Source Configuration (Palo Alto Networks)", exact=True)).to_contain_text("source-line-0")
    panes.first.evaluate("el => el.scrollTop = el.scrollHeight")
    expect(panes.first.locator(".editor-line").last).to_contain_text("source-line-1499")
    assert panes.first.locator(".editor-line").count() <= 80
    page.get_by_role("tab", name="Candidate Configuration", exact=True).click()
    page.get_by_label("Source Vendor", exact=True).select_option("PALO_ALTO")
    expect(page.locator(".workspace-empty")).to_contain_text("Previous results are stale.")
    assert page.get_by_role("button", name="Copy All READY", exact=True).count() == 0
    assert page.get_by_role("link", name="Download Candidate", exact=True).count() == 0
    expect(page.get_by_role("img", name="Conversion results unavailable until Convert completes")).to_be_visible()


def test_configmorph_detected_version_does_not_select_target(page, live_server):
    from playwright.sync_api import expect

    page.goto(live_server[0])
    config = '#config-version=FG39E8-7.0.13-FW-build0000-000000:opmode=0:vdom=0:user=admin\nconfig firewall address\n edit "WEB"\n  set subnet 192.0.2.1 255.255.255.255\n next\nend\nconfig firewall policy\nend\n'
    page.get_by_role("button", name="Paste from Clipboard", exact=True).click()
    page.get_by_role("textbox", name="Configuration", exact=True).fill(config)
    page.get_by_role("button", name="Use Configuration", exact=True).click()
    expect(page.get_by_label("Source OS Version", exact=True)).to_have_value("")
    expect(page.get_by_text("Configuration reports 7.0.13; selected version is empty.", exact=True)).to_be_visible()
    page.get_by_label("Source Vendor", exact=True).select_option("PALO_ALTO")
    page.get_by_label("Source Hardware", exact=True).select_option("paloalto-pa5220")
    page.get_by_role("button", name="Use detected version", exact=True).click()
    expect(page.get_by_label("Source OS Version", exact=True)).to_have_value("7.0.13")
    page.get_by_text("Evidence", exact=True).first.click()
    expect(page.get_by_text("Unknown software", exact=True)).to_be_visible()
    expect(page.get_by_label("Target Vendor", exact=True)).to_have_value("")
    expect(page.get_by_label("Target OS Version", exact=True)).to_have_value("")
    expect(page.get_by_role("button", name="Convert", exact=True)).to_be_disabled()
