from pathlib import Path
import re

import pytest
from playwright.sync_api import expect


@pytest.mark.parametrize("width,height", [(1920,1080),(1600,900),(1440,900),(1024,900)])
def test_canonical_locked_layout(page, live_server, width, height):
    errors = []
    page.on("pageerror", lambda error: errors.append(str(error)))
    page.set_viewport_size({"width": width, "height": height})
    page.goto(live_server[0] + "/?demo=locked")

    expect(page.get_by_role("heading", name="ConfigMorph", exact=True)).to_be_visible()
    expect(page.get_by_text("Network Configuration Migration", exact=True)).to_be_visible()
    expect(page.get_by_text("Translate. Validate. Migrate with Confidence.", exact=True)).to_be_visible()
    for name in ("Project: Firewall-Migration-01", "Save", "Load"):
        expect(page.get_by_role("button", name=name, exact=True)).to_be_visible()
    expect(page.locator('summary[aria-label="Project menu"]')).to_be_visible()
    assert page.locator(".sidebar").count() == 0
    assert page.get_by_role("button", name="Analyze", exact=False).count() == 0

    expect(page.get_by_role("group", name="Source Platform", exact=True)).to_be_visible()
    expect(page.get_by_role("group", name="Target Platform", exact=True)).to_be_visible()
    expect(page.get_by_label("Domain", exact=True)).to_have_value("FIREWALL")
    expect(page.get_by_label("Source Vendor", exact=True)).to_have_value("fixture")
    expect(page.get_by_label("Source Hardware", exact=True)).to_have_value("fixture")
    expect(page.get_by_label("Source OS Version", exact=True)).to_have_value("fixture")
    expect(page.get_by_label("Target Vendor", exact=True)).to_have_value("fixture")
    expect(page.get_by_label("Target Hardware", exact=True)).to_have_value("fixture")
    expect(page.get_by_label("Target OS Version", exact=True)).to_have_value("fixture")
    expect(page.get_by_test_id("source-target-arrow")).to_be_visible()
    source_brand = page.locator('.source-card .vendor-brand').first
    target_brand = page.locator('.target-card .vendor-brand').first
    source_brand_bounds = source_brand.bounding_box()
    target_brand_bounds = target_brand.bounding_box()
    assert abs(source_brand_bounds["width"] - target_brand_bounds["width"]) <= 1
    assert abs(source_brand_bounds["height"] - target_brand_bounds["height"]) <= 1
    for label in ("Palo Alto Networks", "Fortinet"):
        brand = page.locator(f'.platform-row .vendor-brand[aria-label="{label}"]').first
        expect(brand).to_be_visible()
        bounds = brand.bounding_box()
        icon_bounds = brand.locator(".vendor-brand-fallback > .ui-icon").bounding_box()
        text_bounds = brand.locator(".vendor-brand-fallback > b").bounding_box()
        assert icon_bounds["width"] >= 24
        assert bounds["x"] <= icon_bounds["x"]
        assert text_bounds["x"] + text_bounds["width"] <= bounds["x"] + bounds["width"] + 1
    for label in ("Palo Alto Networks", "Fortinet", "Cisco", "Check Point", "Juniper Networks", "HPE Aruba Networking", "F5"):
        source_brand.locator(".vendor-brand-fallback > b").evaluate("(node, value) => { node.textContent = value }", label)
        fallback = source_brand.locator(".vendor-brand-fallback")
        assert fallback.evaluate("node => node.scrollWidth <= node.clientWidth")
        bounds = source_brand.bounding_box()
        fallback_bounds = fallback.bounding_box()
        assert bounds["x"] <= fallback_bounds["x"] + 1
        assert fallback_bounds["x"] + fallback_bounds["width"] <= bounds["x"] + bounds["width"] + 1
    source_brand.locator(".vendor-brand-fallback > b").evaluate("node => { node.textContent = 'Palo Alto Networks' }")

    compact_brand = page.locator(".locked-editor .vendor-brand.compact").first
    for label in ("Palo Alto Networks", "Fortinet", "Cisco", "Check Point", "Juniper Networks", "HPE Aruba Networking", "F5"):
        compact_brand.locator("b").evaluate("(node, value) => { node.textContent = value }", label)
        assert compact_brand.locator(".vendor-brand-fallback").evaluate("node => node.scrollWidth <= node.clientWidth")
    compact_brand.locator("b").evaluate("node => { node.textContent = 'Palo Alto Networks' }")

    for card in (page.locator(".source-card"), page.locator(".target-card")):
        brand_bounds = card.locator(".vendor-brand").bounding_box()
        fields_bounds = card.locator(".platform-fields").bounding_box()
        assert brand_bounds["x"] + brand_bounds["width"] <= fields_bounds["x"] + 1
        for field in card.locator(".platform-fields label").all():
            assert field.evaluate("node => { const range = document.createRange(); range.selectNodeContents(node.firstChild); return range.getBoundingClientRect().right <= node.getBoundingClientRect().right + 1 }")

    expect(page.get_by_role("img", name="Visual fixture: 82 percent converted. Not compatibility or confidence.")).to_be_visible()
    for label, count in (("Converted", "1,776"), ("Modified", "420"), ("Needs Review", "183"), ("Removed", "62"), ("Unsupported", "36")):
        row = page.locator(".donut-legend").get_by_text(label, exact=True).locator("..")
        expect(row).to_contain_text(count)

    expect(page.get_by_role("heading", name="Source Configuration", exact=True)).to_be_visible()
    expect(page.get_by_text("Paste or upload the source configuration file", exact=True)).to_be_visible()
    expect(page.get_by_text("Open File", exact=True)).to_be_visible()
    expect(page.get_by_role("button", name="Paste from Clipboard", exact=True)).to_be_visible()

    tabs = ["Raw Comparison", "Semantic Diff", "Migration Plan", "Candidate Configuration", "Evidence"]
    expect(page.get_by_role("tab")).to_have_text(tabs)
    expect(page.get_by_role("tab", name="Raw Comparison", exact=True)).to_have_attribute("aria-selected", "true")
    expect(page.get_by_role("searchbox", name="Search configuration", exact=True)).to_be_visible()
    expect(page.get_by_role("button", name="Filters", exact=True)).to_be_visible()
    expect(page.get_by_role("button", name="Expanded", exact=True)).to_be_visible()
    expect(page.get_by_role("button", name="Copy All", exact=True)).to_be_visible()
    expect(page.get_by_label("Source Configuration (Palo Alto Networks)", exact=True)).to_be_visible()
    expect(page.get_by_label("Target Configuration (Fortinet)", exact=True)).to_be_visible()
    assert page.locator(".semantic-markers").count() == 0
    expect(page.get_by_role("heading", name="Conversion Summary", exact=True)).to_be_visible()
    for label, count in (("Added", "12"), ("Modified", "5"), ("Removed", "3"), ("Unsupported", "2"), ("Needs Review", "4")):
        row = page.locator(".conversion-summary").get_by_text(label, exact=True).locator("../..")
        expect(row).to_contain_text(count)

    source = page.locator(".source-card").bounding_box()
    target = page.locator(".target-card").bounding_box()
    success = page.locator(".conversion-success").bounding_box()
    assert abs(source["y"] - target["y"]) <= 2
    if width >= 1200:
        assert success["x"] > target["x"]
    else:
        assert abs(success["x"] - source["x"]) <= 2
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
    assert page.locator("main").evaluate("el => el.scrollWidth <= el.clientWidth")
    if width >= 1200:
        assert page.locator("main").evaluate("el => el.scrollHeight <= el.clientHeight")
    assert not errors

    output = Path("artifacts/visual-qa")
    output.mkdir(parents=True, exist_ok=True)
    page.screenshot(path=str(output / f"raw-comparison-{width}x{height}.png"), full_page=True)


def test_expanded_raw_comparison_restores_with_button_and_escape(page, live_server):
    page.set_viewport_size({"width": 1920, "height": 1080})
    page.goto(live_server[0] + "/?demo=locked")
    panes = page.locator(".locked-comparison .editor-lines")
    normal_height = panes.first.bounding_box()["height"]
    page.get_by_role("button", name="Expanded", exact=True).click()
    expect(page.locator(".locked-app")).to_have_class(re.compile("comparison-expanded"))
    expect(page.get_by_role("button", name="Restore", exact=True)).to_be_visible()
    expect(page.get_by_role("heading", name="Conversion Summary", exact=True)).to_be_visible()
    assert panes.first.bounding_box()["height"] > normal_height * 1.8
    Path("artifacts/visual-qa").mkdir(parents=True, exist_ok=True)
    page.screenshot(path="artifacts/visual-qa/raw-comparison-expanded-1920x1080.png", full_page=True)
    page.get_by_role("button", name="Restore", exact=True).click()

    page.get_by_role("searchbox", name="Search configuration", exact=True).fill("ethernet1/1")
    page.get_by_role("button", name="Filters", exact=True).click()
    source_text = page.get_by_label("Source Configuration (Palo Alto Networks)", exact=True).text_content()
    page.get_by_role("button", name="Expanded", exact=True).click()
    expect(page.locator(".locked-app")).to_have_class(re.compile("comparison-expanded"))
    expect(page.get_by_role("button", name="Restore", exact=True)).to_be_visible()
    expect(page.get_by_label("Source Configuration (Palo Alto Networks)", exact=True)).to_be_visible()
    expect(page.get_by_label("Target Configuration (Fortinet)", exact=True)).to_be_visible()
    assert page.locator(".semantic-markers").count() == 0
    expect(page.get_by_role("searchbox", name="Search configuration", exact=True)).to_have_value("ethernet1/1")
    expect(page.get_by_role("button", name="Filters", exact=True)).to_have_attribute("aria-pressed", "true")
    expect(page.get_by_role("button", name="Copy All", exact=True)).to_be_visible()
    assert page.get_by_label("Source Configuration (Palo Alto Networks)", exact=True).text_content() == source_text
    assert page.url.endswith("/?demo=locked")
    page.get_by_role("button", name="Restore", exact=True).click()
    expect(page.locator(".locked-app")).not_to_have_class(re.compile("comparison-expanded"))
    page.get_by_role("button", name="Expanded", exact=True).click()
    page.keyboard.press("Escape")
    expect(page.locator(".locked-app")).not_to_have_class(re.compile("comparison-expanded"))


def test_canonical_search_filter_scroll_and_copy(page, context, live_server):
    context.grant_permissions(["clipboard-read", "clipboard-write"])
    page.goto(live_server[0] + "/?demo=locked")
    page.get_by_role("searchbox", name="Search configuration", exact=True).fill("virtual-router")
    expect(page.get_by_label("Source Configuration (Palo Alto Networks)", exact=True)).to_contain_text("virtual-router")
    page.get_by_role("button", name="Filters", exact=True).click()
    expect(page.get_by_role("button", name="Filters", exact=True)).to_have_attribute("aria-pressed", "true")
    pane = page.get_by_label("Source Configuration (Palo Alto Networks)", exact=True).locator(".editor-lines")
    pane.evaluate("(el)=>el.scrollTop=el.scrollHeight")
    page.get_by_role("button", name="Copy All", exact=True).click()
    expect(page.get_by_role("status")).to_contain_text("READY commands copied")
    copied = page.evaluate("navigator.clipboard.readText()")
    assert "VISUAL FIXTURE ONLY" in copied
    assert "ENGINEER REVIEW REQUIRED" in copied


def test_raw_comparison_scrolls_both_editors_together(page, live_server):
    page.set_viewport_size({"width": 1440, "height": 900})
    page.goto(live_server[0] + "/?demo=locked")
    panes = page.locator(".locked-comparison .editor-lines")
    expect(panes).to_have_count(2)
    assert panes.first.evaluate("el => el.scrollHeight > el.clientHeight")
    assert panes.nth(1).evaluate("el => el.scrollHeight > el.clientHeight")

    def set_fraction(index, fraction):
        panes.nth(index).evaluate("(el, fraction) => { el.scrollTop = fraction * (el.scrollHeight - el.clientHeight); el.dispatchEvent(new Event('scroll')) }", fraction)
        page.wait_for_timeout(40)

    def ratio(index):
        return panes.nth(index).evaluate("el => { const max = el.scrollHeight - el.clientHeight; return max > 0 ? el.scrollTop / max : 0 }")

    for fraction in (0.2, 0.65, 0.15, 0.9):
        set_fraction(0, fraction)
        assert abs(ratio(0) - ratio(1)) < 0.02
    stable = [panes.nth(index).evaluate("el => el.scrollTop") for index in (0, 1)]
    page.wait_for_timeout(120)
    assert [panes.nth(index).evaluate("el => el.scrollTop") for index in (0, 1)] == stable

    for fraction in (0.75, 0.1, 0.55, 0.3):
        set_fraction(1, fraction)
        assert abs(ratio(0) - ratio(1)) < 0.02

    panes.first.evaluate("el => { for (const fraction of [0.1, 0.8, 0.25, 0.95]) { el.scrollTop = fraction * (el.scrollHeight - el.clientHeight); el.dispatchEvent(new Event('scroll')) } }")
    page.wait_for_timeout(120)
    assert abs(ratio(0) - ratio(1)) < 0.02

    for pane in panes.all():
        pane.evaluate("el => { el.firstElementChild.style.minWidth = `${el.clientWidth * 2}px` }")
    horizontal_max = [panes.nth(index).evaluate("el => el.scrollWidth - el.clientWidth") for index in (0, 1)]
    assert min(horizontal_max) > 0
    panes.first.evaluate("el => { el.scrollLeft = 0.6 * (el.scrollWidth - el.clientWidth); el.dispatchEvent(new Event('scroll')) }")
    page.wait_for_timeout(40)
    horizontal_ratio = [panes.nth(index).evaluate("el => el.scrollLeft / (el.scrollWidth - el.clientWidth)") for index in (0, 1)]
    assert abs(horizontal_ratio[0] - horizontal_ratio[1]) < 0.02

    page.set_viewport_size({"width": 1440, "height": 700})
    page.get_by_role("button", name="Filters", exact=True).click()
    assert min(panes.nth(index).evaluate("el => el.scrollHeight - el.clientHeight") for index in (0, 1)) > 0
    set_fraction(0, 0.6)
    assert abs(ratio(0) - ratio(1)) < 0.02
    set_fraction(1, 0.3)
    assert abs(ratio(0) - ratio(1)) < 0.02
    page.get_by_role("button", name="Filters", exact=True).click()
    page.set_viewport_size({"width": 1440, "height": 900})

    page.get_by_role("searchbox", name="Search configuration", exact=True).fill("fixture-")
    set_fraction(0, 0.6)
    assert abs(ratio(0) - ratio(1)) < 0.02
    page.get_by_role("searchbox", name="Search configuration", exact=True).fill("")

    set_fraction(0, 0.4)
    before_expand = [panes.nth(index).evaluate("el => el.scrollTop") for index in (0, 1)]
    normal_height = panes.first.bounding_box()["height"]
    page.get_by_role("button", name="Expanded", exact=True).click()
    expect(page.get_by_role("button", name="Restore", exact=True)).to_be_visible()
    assert panes.first.bounding_box()["height"] > normal_height * 1.8
    assert [panes.nth(index).evaluate("el => el.scrollTop") for index in (0, 1)] == before_expand
    set_fraction(1, 0.7)
    assert abs(ratio(0) - ratio(1)) < 0.02
    page.get_by_role("button", name="Restore", exact=True).click()
    set_fraction(0, 0.25)
    assert abs(ratio(0) - ratio(1)) < 0.02


def test_raw_comparison_uses_diff_colors_without_flow_icons(page, live_server):
    page.goto(live_server[0] + "/?demo=locked")
    assert page.locator(".semantic-markers").count() == 0
    panes = page.locator(".locked-comparison > .locked-editor")
    assert abs(panes.first.bounding_box()["height"] - panes.nth(1).bounding_box()["height"]) <= 1
    source_style = panes.first.locator(".editor-lines").evaluate("el => ({font:getComputedStyle(el).font, lineHeight:getComputedStyle(el).lineHeight})")
    target_style = panes.nth(1).locator(".editor-lines").evaluate("el => ({font:getComputedStyle(el).font, lineHeight:getComputedStyle(el).lineHeight})")
    assert source_style == target_style
    for status in ("converted", "modified", "review", "removed", "unsupported"):
        expect(page.locator(f".locked-comparison .editor-line.{status}").first).to_be_visible()


def test_default_route_keeps_real_empty_state(page, live_server):
    page.goto(live_server[0])
    expect(page.get_by_label("Domain", exact=True)).to_be_visible()
    expect(page.get_by_label("Source Vendor", exact=True)).to_have_value("")
    expect(page.get_by_role("button", name="Convert", exact=True)).to_be_disabled()
    expect(page.locator(".editor-lines").first).to_contain_text("Import a source configuration to begin.")
    expect(page.get_by_role("img", name="Conversion results unavailable until Convert completes")).to_be_visible()


@pytest.mark.parametrize("width", [390, 768, 1024])
def test_canonical_reflow(page, live_server, width):
    page.set_viewport_size({"width": width, "height": 900})
    page.goto(live_server[0] + "/?demo=locked")
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
    assert page.locator("main").evaluate("(el)=>el.scrollWidth<=el.clientWidth")
