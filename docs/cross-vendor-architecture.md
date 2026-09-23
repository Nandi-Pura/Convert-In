# Cross-vendor architecture

Convert-In selects source parsers and target renderers independently within one configuration domain.

```text
Source Parsers
      ↓
FirewallConfig | RouterConfig | SwitchConfig
      ↓
CP0 → CP1 → target-specific CP2
      ↓
      ┌→ PAN-OS 11.1 Renderer
Target├→ FortiOS 7.6.4 Renderer
      └→ Junos 23.4R2 Router Renderer
```

`VendorPlatformProfile` records domain, vendor, platform, exact versions, parser, renderer, evidence profile, and capability state. A registered platform is selectable even when its renderer does not exist. In that case the workbench runs analysis and emits no target commands.

Parser lookup uses the source profile. Renderer lookup uses domain, target vendor, target platform, and target version. No renderer lookup depends on source vendor identity. Conversion requires equal source and target domains.

Current target rendering is bounded: PAN-OS 11.1 and FortiOS 7.6.4 for firewall IR; Junos 23.4R2 for router IR. ASA and SRX firewall renderers remain unimplemented. CP2 remains target-specific and evidence-gated. Missing version evidence returns `VERSION_NOT_VERIFIED`; missing mappings or semantic context returns `MANUAL_REVIEW`.

Router interface mappings include source profile, source version, target profile, target version, source entity ID, target identity, and confirmation. Changing a target makes prior mappings inapplicable.