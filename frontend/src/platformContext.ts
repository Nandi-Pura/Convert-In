import type { InterfaceMappingContract, Profile } from "./types";

export type PlatformCompatibilityStatus =
  | "SUPPORTED"
  | "UNSUPPORTED"
  | "VERSION_NOT_VERIFIED"
  | "UNKNOWN_HARDWARE"
  | "UNKNOWN_SOFTWARE";

export interface PlatformEndpointSelection {
  vendor: string;
  hardwareId: string;
  profileId: string;
  osVersion: string;
}

export interface PlatformSelection {
  domain: string;
  source: PlatformEndpointSelection;
  target: PlatformEndpointSelection;
}

export interface HardwareProfile {
  id: string;
  domain: string;
  vendor: string;
  model: string;
  product_family?: string;
  evidence_refs: string[];
}

export interface HardwareSoftwareSupport {
  hardware_id: string;
  os_family: string;
  exact_version: string;
  status: PlatformCompatibilityStatus;
  evidence_refs: string[];
  constraints?: string[];
}

export interface PlatformEvidence {
  id: string;
  source: string;
  title: string;
  reference: string;
  revision?: string;
  section?: string;
  verified_at?: string;
}

export interface PlatformRegistry {
  domains: { id: string; label: string }[];
  hardware_profiles: HardwareProfile[];
  hardware_software_support: HardwareSoftwareSupport[];
  identity_evidence: Record<string, string>;
  evidence: Record<string, PlatformEvidence>;
  interface_mapping_pairs: { source_hardware_id: string; target_hardware_id: string }[];
}

const emptyEndpoint = (): PlatformEndpointSelection => ({
  vendor: "",
  hardwareId: "",
  profileId: "",
  osVersion: "",
});
export const initialSelection: PlatformSelection = {
  domain: "FIREWALL",
  source: emptyEndpoint(),
  target: emptyEndpoint(),
};

export function resolveCompatibility(
  registry: PlatformRegistry | undefined,
  endpoint: PlatformEndpointSelection,
  profiles: Profile[],
) {
  if (
    !endpoint.hardwareId ||
    !registry?.hardware_profiles.some((item) => item.id === endpoint.hardwareId)
  )
    return {
      status: "UNKNOWN_HARDWARE" as const,
      evidenceRefs: [] as string[],
      constraints: [] as string[],
    };
  if (!endpoint.osVersion)
    return {
      status: "UNKNOWN_SOFTWARE" as const,
      evidenceRefs: [] as string[],
      constraints: [] as string[],
    };
  const exact = registry.hardware_software_support.find(
    (item) =>
      item.hardware_id === endpoint.hardwareId &&
      item.exact_version === endpoint.osVersion,
  );
  if (exact)
    return {
      status: exact.status,
      evidenceRefs: exact.evidence_refs,
      constraints: exact.constraints || [],
    };
  const profile = profiles.find((item) => item.id === endpoint.profileId);
  const known = Boolean(
    profile?.supported_versions.includes(endpoint.osVersion) ||
    profile?.version_profiles?.some(
      (item) => item.exact_version === endpoint.osVersion,
    ),
  );
  return {
    status: known
      ? ("VERSION_NOT_VERIFIED" as const)
      : ("UNKNOWN_SOFTWARE" as const),
    evidenceRefs: [] as string[],
    constraints: [] as string[],
  };
}

export function requiresInterfaceMapping(
  registry: PlatformRegistry | undefined,
  selection: PlatformSelection,
) {
  return Boolean(
    registry?.interface_mapping_pairs.some(
      (pair) =>
        pair.source_hardware_id === selection.source.hardwareId &&
        pair.target_hardware_id === selection.target.hardwareId,
    ),
  );
}

export function interfaceMappingPayload(
  contract: InterfaceMappingContract | undefined,
) {
  if (!contract) return {};
  return {
    source_hardware_id: contract.source_hardware_id,
    target_hardware_id: contract.target_hardware_id,
    interfaces: contract.interfaces.map((row) => row.mapping),
  };
}

export function buildOperationRequest(
  sourceText: string,
  selection: PlatformSelection,
  profiles: Profile[],
  mappings: object = {},
) {
  const sourceProfile = profiles.find(
    (profile) => profile.id === selection.source.profileId,
  );
  if (!sourceProfile) throw new Error("Select a valid source platform.");
  const endpoint = (value: PlatformEndpointSelection) => ({
    vendor: value.vendor,
    hardware_id: value.hardwareId,
    profile_id: value.profileId,
    os_version: value.osVersion,
  });
  return {
    source_text: sourceText,
    source_vendor: sourceProfile.source_vendor,
    source_version: selection.source.osVersion,
    source_profile: selection.source.profileId,
    target_profile: selection.target.profileId,
    target_version: selection.target.osVersion,
    mappings,
    migration_context: {
      domain: selection.domain,
      source: endpoint(selection.source),
      target: endpoint(selection.target),
    },
  };
}
