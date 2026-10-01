import { describe, expect, it } from "vitest";
import type { Profile } from "./types";
import {
  buildOperationRequest,
  initialSelection,
  resolveCompatibility,
  type PlatformRegistry,
  type PlatformSelection,
} from "./platformContext";

const profile: Profile = {
  id: "switch-cisco-iosxe",
  vendor: "CISCO",
  source_vendor: "cisco_iosxe",
  platform: "IOS_XE",
  domain: "SWITCH",
  os_family: "IOS-XE",
  supported_versions: ["17.12.1"],
  target_versions: ["17.12.1"],
  target_capability: "BOUNDED_RENDERER",
};
const registry: PlatformRegistry = {
  domains: [
    { id: "FIREWALL", label: "Firewall" },
    { id: "SWITCH", label: "Switching" },
    { id: "ROUTER", label: "Routing" },
  ],
  hardware_profiles: [
    {
      id: "cisco-c9300-48p",
      domain: "SWITCH",
      vendor: "CISCO",
      model: "C9300-48P",
      evidence_refs: ["CISCO-CATALYST-9300-DATASHEET"],
    },
  ],
  hardware_software_support: [
    {
      hardware_id: "cisco-c9300-48p",
      os_family: "IOS-XE",
      exact_version: "17.12.1",
      status: "SUPPORTED",
      evidence_refs: [
        "CISCO-CATALYST-9300-DATASHEET",
        "IOSXE-17.12.1-C9300-RELEASE",
      ],
    },
  ],
  identity_evidence: {},
  evidence: {
    "IOSXE-17.12.1-C9300-RELEASE": {
      id: "IOSXE-17.12.1-C9300-RELEASE",
      source: "Cisco",
      title: "Catalyst 9300 release notes",
      reference: "https://www.cisco.com/release-notes",
      revision: "17.12.1",
      section: "Supported Hardware",
      verified_at: "2026-09-29",
    },
  },
  interface_mapping_pairs: [],
};
const selection: PlatformSelection = {
  domain: "SWITCH",
  source: {
    vendor: "CISCO",
    hardwareId: "cisco-c9300-48p",
    profileId: profile.id,
    osVersion: "17.12.1",
  },
  target: {
    vendor: "CISCO",
    hardwareId: "cisco-c9300-48p",
    profileId: profile.id,
    osVersion: "17.12.1",
  },
};

describe("real migration context contract", () => {
  it("keeps the default context unselected", () => {
    expect(initialSelection.source.hardwareId).toBe("");
    expect(initialSelection.target.osVersion).toBe("");
  });

  it("resolves exact backend support without nearest-version matching", () => {
    expect(
      resolveCompatibility(registry, selection.source, [profile]).status,
    ).toBe("SUPPORTED");
    expect(
      resolveCompatibility(
        registry,
        { ...selection.source, osVersion: "17.12.2" },
        [profile],
      ).status,
    ).toBe("UNKNOWN_SOFTWARE");
    expect(
      resolveCompatibility(
        registry,
        { ...selection.source, hardwareId: "C9300" },
        [profile],
      ).status,
    ).toBe("UNKNOWN_HARDWARE");
  });

  it("preserves backend constraints for unsupported exact pairs", () => {
    const unsupported = {
      ...registry,
      hardware_software_support: [
        {
          ...registry.hardware_software_support[0],
          status: "UNSUPPORTED" as const,
          constraints: ["Pair is outside the vendor matrix."],
        },
      ],
    };
    expect(
      resolveCompatibility(unsupported, selection.source, [profile]),
    ).toEqual({
      status: "UNSUPPORTED",
      evidenceRefs: [
        "CISCO-CATALYST-9300-DATASHEET",
        "IOSXE-17.12.1-C9300-RELEASE",
      ],
      constraints: ["Pair is outside the vendor matrix."],
    });
  });

  it("submits domain, both exact endpoints, and source configuration", () => {
    expect(buildOperationRequest("vlan 10", selection, [profile])).toEqual({
      source_text: "vlan 10",
      source_vendor: "cisco_iosxe",
      source_version: "17.12.1",
      source_profile: "switch-cisco-iosxe",
      target_profile: "switch-cisco-iosxe",
      target_version: "17.12.1",
      mappings: {},
      migration_context: {
        domain: "SWITCH",
        source: {
          vendor: "CISCO",
          hardware_id: "cisco-c9300-48p",
          profile_id: "switch-cisco-iosxe",
          os_version: "17.12.1",
        },
        target: {
          vendor: "CISCO",
          hardware_id: "cisco-c9300-48p",
          profile_id: "switch-cisco-iosxe",
          os_version: "17.12.1",
        },
      },
    });
  });

  it("includes confirmed interface mappings only when supplied", () => {
    const mappings = {
      source_hardware_id: "paloalto-pa5220",
      target_hardware_id: "paloalto-pa5410",
      interfaces: [
        {
          source_interface: "ethernet1/2",
          target_interface: "ethernet1/6",
          confirmed_by_user: true,
        },
      ],
    };
    expect(
      buildOperationRequest("vlan 10", selection, [profile], mappings).mappings,
    ).toEqual(mappings);
  });
});
