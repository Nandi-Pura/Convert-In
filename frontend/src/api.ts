import type {
  Evidence,
  InterfaceMapping,
  InterfaceMappingContract,
  InterfaceMappingPreflight,
  Manifest,
  MigrationPlan,
  Operation,
  Result,
} from "./types";
import type { PlatformRegistry } from "./platformContext";
async function json<T>(url: string, init?: RequestInit): Promise<T> {
  const r = await fetch(url, init);
  const data = await r.json();
  if (!r.ok) throw new Error(data.detail || `HTTP ${r.status}`);
  return data;
}
async function existingOrCreate<T>(url: string) {
  const response = await fetch(url);
  if (response.ok) return response.json() as Promise<T>;
  if (response.status !== 404) {
    const data = await response.json();
    throw new Error(data.detail || `HTTP ${response.status}`);
  }
  return json<T>(url, { method: "POST" });
}
const mappingUrl = (id: string) =>
  `/api/projects/${encodeURIComponent(id)}/migration/interface-mappings`;
export const api = {
  registry: (signal?: AbortSignal) =>
    json<PlatformRegistry>("/api/platform-registry", { signal }),
  detect: (source_text: string, signal?: AbortSignal) =>
    json<{ vendor: string; version?: string; domain: string }>(
      "/api/convert/detect",
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ source_text }),
        signal,
      },
    ),
  preflight: (body: object) =>
    json<InterfaceMappingPreflight>("/api/workbench/preflight", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }),
  start: (body: object) =>
    json<{ operation_id: string }>("/api/workbench/operations", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }),
  operation: (id: string, signal?: AbortSignal) =>
    json<Operation>(`/api/operations/${id}`, { signal }),
  project: (id: string, signal?: AbortSignal) =>
    json<{ manifest: Manifest; source_text: string; result: Result }>(
      `/api/projects/${id}`,
      { signal },
    ),
  importProject: (file: File) => {
    const b = new FormData();
    b.set("project", file);
    return json<Manifest>("/api/projects/import", { method: "POST", body: b });
  },
  interfaceMappings: (id: string, signal?: AbortSignal) =>
    json<InterfaceMappingContract>(mappingUrl(id), { signal }),
  saveInterfaceMappings: (id: string, mappings: InterfaceMapping[]) =>
    json<InterfaceMappingContract>(mappingUrl(id), {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ mappings }),
    }),
  resetInterfaceMappings: (id: string) =>
    json<InterfaceMappingContract>(mappingUrl(id), { method: "DELETE" }),
  validateInterfaceMappings: (id: string) =>
    json<InterfaceMappingContract>(`${mappingUrl(id)}/validate`, {
      method: "POST",
    }),
  plan: (id: string) =>
    existingOrCreate<MigrationPlan>(`/api/projects/${id}/migration/plan`),
  evidence: (id: string) =>
    existingOrCreate<Evidence>(`/api/projects/${id}/migration/evidence-pack`),
};
