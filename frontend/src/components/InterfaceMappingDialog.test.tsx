import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import type { InterfaceMappingContract } from "../types";
import {
  InterfaceMappingDialog,
  mappingStatusClass,
  visibleCandidates,
} from "./InterfaceMappingDialog";

const contract: InterfaceMappingContract = {
  source_hardware_id: "paloalto-pa5220",
  target_hardware_id: "paloalto-pa5410",
  interfaces: [
    {
      source_interface: "ethernet1/2",
      required: true,
      source_capability: {
        hardware_id: "paloalto-pa5220",
        interface_name: "ethernet1/2",
        physical_port_number: 2,
        interface_family: "ethernet",
        connector: "RJ45",
        media_capability: "COPPER",
        supported_speeds: ["1G"],
        supports_layer3: true,
        supports_subinterface: true,
        supports_aggregate_membership: true,
        breakout_capable: false,
        breakout_parent: null,
        evidence_refs: ["PA-5220-PORTS"],
        constraints: [],
      },
      mapping: {
        source_interface: "ethernet1/2",
        target_interface: null,
        confirmed: false,
        status: "UNMAPPED",
        compatibility_reasons: ["Select and confirm a target port."],
        confirmed_by_user: false,
        source_evidence_refs: [],
        target_evidence_refs: [],
      },
      target_candidates: [
        {
          target_interface: "ethernet1/6",
          status: "COMPATIBLE",
          reasons: ["Backend verified connector and speed capability."],
          already_assigned: false,
          evidence_refs: ["PA-5410-PORTS"],
        },
        {
          target_interface: "ethernet1/7",
          status: "INCOMPATIBLE",
          reasons: ["Connector is incompatible."],
          already_assigned: false,
          evidence_refs: ["PA-5410-PORTS"],
        },
        {
          target_interface: "ethernet1/8",
          status: "COMPATIBLE",
          reasons: ["Port is compatible."],
          already_assigned: true,
          evidence_refs: ["PA-5410-PORTS"],
        },
      ],
    },
  ],
  summary: {
    required: 1,
    mapped: 0,
    exact: 0,
    compatible: 0,
    unmapped: 1,
    incompatible: 0,
    unverified: 0,
  },
  valid_for_conversion: false,
  blocking_reasons: ["A target dataplane port must be selected and explicitly confirmed."],
  evidence_refs: [],
};

describe("InterfaceMappingDialog", () => {
  it("filters unavailable candidates without inventing or selecting a target", () => {
    expect(visibleCandidates(contract.interfaces[0], false).map((item) => item.target_interface)).toEqual([
      "ethernet1/6",
      "ethernet1/8",
    ]);
    expect(visibleCandidates(contract.interfaces[0], true)).toHaveLength(3);
    const html = renderToStaticMarkup(
      <InterfaceMappingDialog
        open
        contract={contract}
        loading={false}
        error=""
        onClose={vi.fn()}
        onSave={vi.fn()}
        onReset={vi.fn()}
        onValidate={vi.fn()}
        onPendingChange={vi.fn()}
      />,
    );
    expect(html).toContain("ethernet1/2");
    expect(html).toContain("RJ45");
    expect(html).toContain("Select target port");
    expect(html).not.toContain("ethernet1/7");
    expect(html).toContain("already assigned");
    expect(html).toContain("does not verify installed optics, cabling, or live link state");
  });

  it("uses the locked status color groups", () => {
    expect(mappingStatusClass("EXACT")).toBe("mapping-good");
    expect(mappingStatusClass("UNVERIFIED")).toBe("mapping-pending");
    expect(mappingStatusClass("INCOMPATIBLE")).toBe("mapping-bad");
  });

  it("handles a valid zero-row mapping contract", () => {
    const empty = {
      ...contract,
      interfaces: [],
      summary: { ...contract.summary, required: 0, unmapped: 0 },
      valid_for_conversion: true,
      blocking_reasons: [],
    };
    const html = renderToStaticMarkup(
      <InterfaceMappingDialog
        open
        contract={empty}
        loading={false}
        error=""
        onClose={vi.fn()}
        onSave={vi.fn()}
        onReset={vi.fn()}
        onValidate={vi.fn()}
        onPendingChange={vi.fn()}
      />,
    );
    expect(html).toContain("No physical interface mapping is required");
    expect(html).toContain("Ready");
  });
});