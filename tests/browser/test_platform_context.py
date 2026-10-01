from pathlib import Path


def test_initial_manual_platform_context(page, live_server):
    page.goto(live_server[0])
    page.get_by_label("Domain", exact=True).select_option("FIREWALL")
    for side in ("Source", "Target"):
        for field in ("Vendor", "Hardware", "OS Version"):
            assert page.get_by_label(f"{side} {field}", exact=True).is_visible()
    assert page.get_by_text("Open File", exact=True).is_visible()
    assert page.get_by_role("button", name="Paste from Clipboard", exact=True).is_visible()
    assert page.get_by_role("button", name="Convert", exact=True).is_disabled()
    path = Path("artifacts/visual-qa/manual-platform-initial.png")
    path.parent.mkdir(parents=True, exist_ok=True)
    page.screenshot(path=str(path), full_page=True)
    page.get_by_label("Target Vendor", exact=True).select_option("PALO_ALTO")
    page.get_by_label("Target Hardware", exact=True).select_option("paloalto-pa5410")
    page.get_by_label("Source Vendor", exact=True).select_option("PALO_ALTO")
    page.get_by_label("Source Hardware", exact=True).select_option("paloalto-pa5220")
    page.get_by_role("button", name="Paste from Clipboard", exact=True).click()
    page.get_by_label("Configuration", exact=True).fill("#config-version=FG39E8-7.0.13-FW-build0566-\nconfig system global\nend")
    page.get_by_role("button", name="Use Configuration", exact=True).click()
    assert page.get_by_label("Source Hardware", exact=True).input_value() == "paloalto-pa5220"
    assert page.get_by_label("Target Hardware", exact=True).input_value() == "paloalto-pa5410"
    assert page.get_by_label("Source Vendor", exact=True).input_value() == "PALO_ALTO"
    page.get_by_label("Domain", exact=True).select_option("SWITCH")
    assert page.get_by_label("Source Hardware", exact=True).input_value() == ""
    assert page.get_by_label("Target Vendor", exact=True).input_value() == ""
    page.get_by_label("Source Vendor", exact=True).select_option("CISCO")
    page.get_by_label("Source Hardware", exact=True).select_option("cisco-c9300-48p")
    page.get_by_label("Domain", exact=True).select_option("ROUTER")
    assert page.get_by_label("Source Hardware", exact=True).input_value() == ""


def test_supported_context_runs_real_pipeline_and_invalidates_results(page, live_server):
    from playwright.sync_api import expect

    page.goto(live_server[0])
    page.get_by_label("Domain", exact=True).select_option("SWITCH")
    for side in ("Source", "Target"):
        page.get_by_label(f"{side} Vendor", exact=True).select_option("CISCO")
        page.get_by_label(f"{side} Hardware", exact=True).select_option("cisco-c9300-48p")
        page.get_by_label(f"{side} OS Version", exact=True).select_option("17.12.1")
    page.get_by_text("Evidence", exact=True).first.click()
    expect(page.get_by_role("link", name="Release Notes for Cisco Catalyst 9300 Series Switches, Cisco IOS XE Dublin 17.12.x", exact=True).first).to_be_visible()
    page.get_by_text("Evidence", exact=True).first.click()
    source = Path("tests/fixtures/iosxe/basic-switch.cfg").read_text(encoding="utf-8")
    page.get_by_role("button", name="Paste from Clipboard", exact=True).click()
    page.get_by_label("Configuration", exact=True).fill(source)
    page.get_by_role("button", name="Use Configuration", exact=True).click()
    convert = page.get_by_role("button", name="Convert", exact=True)
    expect(convert).to_be_enabled()

    with page.expect_request(lambda request: request.url.endswith("/api/workbench/operations") and request.method == "POST") as request_info:
        convert.click()
    body = request_info.value.post_data_json
    assert body["migration_context"] == {
        "domain": "SWITCH",
        "source": {"vendor": "CISCO", "hardware_id": "cisco-c9300-48p", "profile_id": "switch-cisco-iosxe", "os_version": "17.12.1"},
        "target": {"vendor": "CISCO", "hardware_id": "cisco-c9300-48p", "profile_id": "switch-cisco-iosxe", "os_version": "17.12.1"},
    }
    assert body["source_text"] == source

    candidate = page.get_by_label("Target Configuration (Cisco)", exact=True)
    expect(candidate).to_contain_text("vlan 10", timeout=15000)
    success = page.locator('[role="img"][aria-label*="percent of source lines converted"]')
    expect(success).to_be_visible()
    assert "82 percent" not in success.get_attribute("aria-label")
    expect(page.locator(".conversion-summary")).not_to_contain_text("12Added")

    page.get_by_role("tab", name="Candidate Configuration", exact=True).click()
    expect(page.get_by_role("link", name="Download Candidate", exact=True)).to_be_visible()
    expect(page.get_by_role("button", name="Copy All READY", exact=True)).to_be_enabled()
    page.get_by_role("tab", name="Migration Plan", exact=True).click()
    expect(page.locator(".figma-list")).to_contain_text("VLAN")
    page.get_by_role("tab", name="Evidence", exact=True).click()
    expect(page.get_by_role("heading", name="Platform Evidence", exact=True)).to_be_visible()
    expect(page.get_by_role("heading", name="Conversion Evidence", exact=True)).to_be_visible()
    expect(page.get_by_role("link", name="Release Notes for Cisco Catalyst 9300 Series Switches, Cisco IOS XE Dublin 17.12.x", exact=True).first).to_be_visible()

    page.get_by_label("Domain", exact=True).select_option("FIREWALL")
    expect(page.locator(".workspace-empty")).to_contain_text("Previous results are stale.")
    expect(page.get_by_role("img", name="Conversion results unavailable until Convert completes")).to_be_visible()


def test_operation_poll_failure_keeps_context_and_releases_convert(page, live_server):
    from playwright.sync_api import expect

    page.goto(live_server[0])
    page.get_by_label("Domain", exact=True).select_option("SWITCH")
    for side in ("Source", "Target"):
        page.get_by_label(f"{side} Vendor", exact=True).select_option("CISCO")
        page.get_by_label(f"{side} Hardware", exact=True).select_option("cisco-c9300-48p")
        page.get_by_label(f"{side} OS Version", exact=True).select_option("17.12.1")
    source = Path("tests/fixtures/iosxe/basic-switch.cfg").read_text(encoding="utf-8")
    page.get_by_role("button", name="Paste from Clipboard", exact=True).click()
    page.get_by_label("Configuration", exact=True).fill(source)
    page.get_by_role("button", name="Use Configuration", exact=True).click()
    page.route("**/api/operations/*", lambda route: route.abort())
    page.get_by_role("button", name="Convert", exact=True).click()
    expect(page.get_by_role("alert")).to_contain_text("Failed to fetch")
    expect(page.get_by_role("button", name="Convert", exact=True)).to_be_enabled()
    expect(page.get_by_label("Source Hardware", exact=True)).to_have_value("cisco-c9300-48p")
    expect(page.get_by_label("Source Configuration", exact=True)).to_contain_text("vlan 10")

PA_MAPPING_SOURCE = """<config version="11.1.0"><devices><entry name="localhost.localdomain">
<network><interface><ethernet><entry name="ethernet1/2"><layer3><ip><entry name="10.0.0.1/24"/></ip></layer3></entry></ethernet></interface></network>
<vsys><entry name="vsys1"><zone><entry name="trust"><network><layer3><member>ethernet1/2</member></layer3></network></entry></zone></entry></vsys>
</entry></devices></config>"""


def test_pa5220_to_pa5410_manual_mapping_golden_flow(page, live_server):
    from playwright.sync_api import expect

    page.set_viewport_size({"width": 1440, "height": 900})
    page.goto(live_server[0])
    for side, hardware in (("Source", "paloalto-pa5220"), ("Target", "paloalto-pa5410")):
        page.get_by_label(f"{side} Vendor", exact=True).select_option("PALO_ALTO")
        page.get_by_label(f"{side} Hardware", exact=True).select_option(hardware)
        page.get_by_label(f"{side} OS Version", exact=True).select_option("11.1")
    page.get_by_role("button", name="Paste from Clipboard", exact=True).click()
    page.get_by_label("Configuration", exact=True).fill(PA_MAPPING_SOURCE)
    page.get_by_role("button", name="Use Configuration", exact=True).click()

    convert = page.get_by_role("button", name="Convert", exact=True)
    expect(convert).to_be_disabled()
    mapping_trigger = page.get_by_role("button", name="Interface Mapping", exact=True)
    expect(mapping_trigger).to_be_visible()

    with page.expect_request(lambda request: request.url.endswith("/api/workbench/preflight") and request.method == "POST"):
        mapping_trigger.click()
    dialog = page.get_by_role("dialog", name="Interface Mapping", exact=True)
    expect(dialog).to_be_visible()
    target = dialog.get_by_label("Target interface", exact=True)
    expect(dialog.get_by_role("button", name="Close Interface Mapping", exact=True)).to_be_focused()
    expect(target).to_have_value("")
    for width in (1280, 1920, 1440):
        page.set_viewport_size({"width": width, "height": 900})
        bounds = dialog.bounding_box()
        assert bounds["x"] >= 0 and bounds["x"] + bounds["width"] <= width
        assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
    expect(dialog.get_by_text("RJ45", exact=True)).to_be_visible()
    expect(dialog.get_by_text("100M, 1G, 10G", exact=True)).to_be_visible()
    expect(dialog.get_by_text("ethernet1/2", exact=True)).to_be_visible()

    dialog.get_by_label("Show incompatible or unverified ports", exact=True).check()
    breakout = target.locator('option[value="ethernet1/25"]')
    expect(breakout).to_contain_text("UNVERIFIED")
    expect(breakout).to_be_disabled()
    dialog.get_by_label("Show incompatible or unverified ports", exact=True).uncheck()

    target.select_option("ethernet1/6")
    expect(dialog.get_by_text("Pending confirmation", exact=True)).to_be_visible()
    expect(convert).to_be_disabled()
    with page.expect_request(lambda request: request.url.endswith("/migration/interface-mappings") and request.method == "PUT"):
        dialog.get_by_role("button", name="Confirm", exact=True).click()
    expect(dialog.get_by_text("Ready", exact=True)).to_be_visible()
    with page.expect_request(lambda request: request.url.endswith("/migration/interface-mappings/validate") and request.method == "POST"):
        dialog.get_by_role("button", name="Validate Mapping", exact=True).click()
    dialog.get_by_role("button", name="Done", exact=True).click()
    ready_trigger = page.locator("button.interface-mapping-button")
    expect(ready_trigger).to_have_text("Interface Mapping: Ready")
    expect(ready_trigger).to_be_focused()
    ready_trigger.click()
    close_mapping = dialog.get_by_role("button", name="Close Interface Mapping", exact=True)
    expect(close_mapping).to_be_focused()
    page.keyboard.press("Shift+Tab")
    expect(dialog.get_by_role("button", name="Done", exact=True)).to_be_focused()
    page.keyboard.press("Tab")
    expect(close_mapping).to_be_focused()
    page.keyboard.press("Escape")
    expect(ready_trigger).to_be_focused()
    expect(convert).to_be_enabled()

    with page.expect_request(lambda request: request.url.endswith("/api/workbench/operations") and request.method == "POST") as request_info:
        convert.click()
    body = request_info.value.post_data_json
    mapping = body["mappings"]["interfaces"][0]
    assert mapping["source_interface"] == "ethernet1/2"
    assert mapping["target_interface"] == "ethernet1/6"
    assert mapping["confirmed_by_user"] is True

    candidate = page.get_by_label("Target Configuration (Palo Alto Networks)", exact=True)
    expect(candidate).to_contain_text("network interface ethernet ethernet1/6 layer3", timeout=15000)
    expect(candidate).not_to_contain_text("network interface ethernet ethernet1/2 layer3")
    page.get_by_role("tab", name="Semantic Diff", exact=True).click()
    expect(page.locator("#result-panel")).to_contain_text("ethernet1/6")
    page.get_by_role("tab", name="Migration Plan", exact=True).click()
    expect(page.locator("#result-panel")).to_contain_text("Interface")
    page.get_by_role("tab", name="Evidence", exact=True).click()
    expect(page.get_by_role("heading", name="Platform Evidence", exact=True)).to_be_visible()
    page.get_by_role("tab", name="Raw Comparison", exact=True).click()
    expect(candidate).to_contain_text("ethernet1/6")
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")


def test_mapping_pending_clear_reset_and_context_invalidation(page, live_server):
    from playwright.sync_api import expect

    page.goto(live_server[0])
    for side, hardware in (("Source", "paloalto-pa5220"), ("Target", "paloalto-pa5410")):
        page.get_by_label(f"{side} Vendor", exact=True).select_option("PALO_ALTO")
        page.get_by_label(f"{side} Hardware", exact=True).select_option(hardware)
        page.get_by_label(f"{side} OS Version", exact=True).select_option("11.1")
    page.get_by_role("button", name="Paste from Clipboard", exact=True).click()
    page.get_by_label("Configuration", exact=True).fill(PA_MAPPING_SOURCE.replace("localhost.localdomain", "lifecycle.localdomain"))
    page.get_by_role("button", name="Use Configuration", exact=True).click()
    page.get_by_role("button", name="Interface Mapping", exact=True).click()
    dialog = page.get_by_role("dialog", name="Interface Mapping", exact=True)
    target = dialog.get_by_label("Target interface", exact=True)
    target.select_option("ethernet1/6")
    expect(dialog.get_by_text("Pending confirmation", exact=True)).to_be_visible()
    dialog.get_by_role("button", name="Done", exact=True).click()
    mapping_trigger = page.locator("button.interface-mapping-button")
    expect(mapping_trigger).to_have_text("Interface Mapping: 0/1")
    mapping_trigger.click()
    expect(target).to_have_value("ethernet1/6")

    with page.expect_request(lambda request: request.url.endswith("/migration/interface-mappings") and request.method == "PUT") as clear_request:
        dialog.get_by_role("button", name="Clear", exact=True).click()
    assert clear_request.value.post_data_json["mappings"][0]["target_interface"] is None
    assert clear_request.value.post_data_json["mappings"][0]["confirmed_by_user"] is False
    expect(target).to_have_value("")

    target.select_option("ethernet1/6")
    dialog.get_by_role("button", name="Confirm", exact=True).click()
    expect(dialog.get_by_text("Ready", exact=True)).to_be_visible()
    dialog.get_by_role("button", name="Reset All", exact=True).click()
    expect(dialog.get_by_role("button", name="Confirm Reset All", exact=True)).to_be_visible()
    with page.expect_request(lambda request: request.url.endswith("/migration/interface-mappings") and request.method == "DELETE"):
        dialog.get_by_role("button", name="Confirm Reset All", exact=True).click()
    expect(dialog.get_by_text("0/1 confirmed", exact=True)).to_be_visible()
    dialog.get_by_role("button", name="Done", exact=True).click()

    page.get_by_label("Target Hardware", exact=True).select_option("paloalto-pa5420")
    expect(page.get_by_role("button", name="Interface Mapping", exact=False)).to_have_count(0)
    page.get_by_label("Target Hardware", exact=True).select_option("paloalto-pa5410")
    page.get_by_label("Target OS Version", exact=True).select_option("11.1")
    expect(page.get_by_role("button", name="Interface Mapping", exact=True)).to_be_visible()
    expect(page.get_by_role("button", name="Convert", exact=True)).to_be_disabled()
