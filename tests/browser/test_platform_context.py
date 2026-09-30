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
