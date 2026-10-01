import { afterEach, describe, expect, it, vi } from "vitest";
import { api } from "./api";

afterEach(() => vi.unstubAllGlobals());

describe("interface mapping API helpers", () => {
  it("posts the workbench payload to preflight", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ project_id: "project", interface_mapping_required: false, interface_mapping: {} }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);
    await api.preflight({ source_text: "config" });
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/workbench/preflight",
      expect.objectContaining({ method: "POST", body: JSON.stringify({ source_text: "config" }) }),
    );
  });

  it("persists only the mappings supplied by the caller", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({}), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);
    const mappings = [{
      source_interface: "ethernet1/2",
      target_interface: "ethernet1/6",
      confirmed: true,
      status: "COMPATIBLE" as const,
      compatibility_reasons: [],
      confirmed_by_user: true,
      source_evidence_refs: [],
      target_evidence_refs: [],
    }];
    await api.saveInterfaceMappings("project id", mappings);
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/projects/project%20id/migration/interface-mappings",
      expect.objectContaining({ method: "PUT", body: JSON.stringify({ mappings }) }),
    );
  });
});