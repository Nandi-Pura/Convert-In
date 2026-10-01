export type Status = "READY" | "REVIEW REQUIRED" | "BLOCKED";
export interface VersionProfile {
  exact_version: string;
  release_line: string;
  version_status:
    "LATEST_VERIFIED" | "LEGACY_VERIFIED" | "VERSION_NOT_VERIFIED";
  target_renderer_available: boolean;
}
export interface Profile {
  id: string;
  vendor: string;
  source_vendor?: string;
  platform: string;
  domain: string;
  display_name?: string;
  os_family?: string;
  supported_versions: string[];
  target_versions?: string[];
  target_capability: string;
  version_profiles?: VersionProfile[];
}
export interface Entity {
  id: string;
  entity_type: string;
  source_title: string;
  source_snippet: string;
  source_lines: number[];
  target_title?: string;
  target_snippet: string;
  user_status: Status;
  detailed_status: string;
  copyable: boolean;
  findings: string[];
  commands: string[];
  evidence_ids?: string[];
}
export interface PropertyDiff {
  property: string;
  classification: string;
  source_value: unknown;
  target_value: unknown;
  reason: string;
  evidence_ids: string[];
  required_action?: string;
}
export interface SemanticEntity {
  entity_id?: string;
  source_identity: string;
  entity_type: string;
  overall_classification: string;
  property_diffs: PropertyDiff[];
}
export interface Finding {
  severity: string;
  title: string;
  domain: string;
  entity_type: string;
  entity_id?: string;
  description: string;
  suggested_action?: string;
}
export interface Accounting {
  total_analyzed_lines: number;
  converted_lines: number;
  review_lines: number;
  unsupported_lines: number;
  unchanged_lines: number;
  method: string;
}
export interface ResultSummary {
  added: number | null;
  modified: number | null;
  removed: number | null;
  unsupported: number | null;
  needs_review: number | null;
}
export interface ResultPlatformEndpoint {
  vendor: string;
  hardware_id: string;
  profile_id: string;
  os_version: string;
  compatibility_status: string;
  evidence_refs: string[];
}
export interface ResultPlatformContext {
  domain: string;
  source: ResultPlatformEndpoint;
  target: ResultPlatformEndpoint;
  evidence: Record<
    string,
    {
      id: string;
      source: string;
      title: string;
      reference: string;
      revision?: string;
      section?: string;
      verified_at?: string;
    }
  >;
}
export interface ConversionEvidence {
  entity_id: string;
  entity_type: string;
  decision: string;
  reasons: string[];
  evidence_ids: string[];
}
export interface Result {
  project_id: string;
  mode: "CONVERT" | "ANALYZE";
  renderer_available: boolean;
  source_profile: Profile & { version: string };
  target_profile: Profile & { version: string };
  source_text: string;
  candidate?: string;
  candidate_filename?: string;
  cp0_summary: Record<string, number>;
  cp1_summary: Record<string, number | unknown[]>;
  cp2_summary: Record<string, number> | null;
  entities: Entity[];
  lint_findings: Finding[];
  semantic_diff?: { entities: SemanticEntity[]; fingerprint?: string };
  line_accounting: Accounting;
  conversion_summary?: ResultSummary;
  migration_plan?: MigrationPlan;
  platform_context?: ResultPlatformContext;
  conversion_evidence?: ConversionEvidence[];
}
export interface Stage {
  name: string;
  status: string;
  counts: Record<string, number>;
  duration_ms?: number;
}
export interface Operation {
  operation_id: string;
  status: string;
  stage: string;
  stages: Stage[];
  elapsed_ms: number;
  completed?: boolean;
  error?: { message: string };
  result?: Result;
}
export interface ManifestEndpoint {
  domain?: string;
  vendor?: string;
  platform?: string;
  profile_id?: string;
  hardware_id?: string;
  exact_version: string;
}
export interface Manifest {
  project_id: string;
  source: ManifestEndpoint & {
    filename: string;
    size_bytes: number;
    line_count: number;
  };
  target: ManifestEndpoint;
  artifacts: Record<string, { status: string }>;
  fingerprint: string;
}
export interface PlanEntity {
  entity_id: string;
  entity_type: string;
  source_name: string;
  target_name?: string;
  compatibility_status: string;
  render_eligible: boolean;
  blocking: boolean;
  reasons: string[];
  required_mappings: string[];
  dependencies: string[];
}
export interface MigrationPlan {
  plan_id?: string;
  summary: Record<string, number>;
  entities: PlanEntity[];
  blocked: { entity_id?: string; reason: string }[];
  advisories: string[];
}
export interface Evidence {
  fingerprint: string;
  artifacts: { name: string; status: string; path?: string; sha256?: string }[];
  source?: { sha256?: string; profile_id?: string; exact_version?: string };
  target?: { profile_id?: string; exact_version?: string };
}

export type PortMappingStatus='EXACT'|'COMPATIBLE'|'REQUIRES_REMAP'|'UNMAPPED'|'UNVERIFIED'|'INCOMPATIBLE';
export interface PortCapability{hardware_id:string;interface_name:string;physical_port_number:number|string;interface_family:string;connector:string;media_capability:string;supported_speeds:string[];supports_layer3:boolean;supports_subinterface:boolean;supports_aggregate_membership:boolean;breakout_capable:boolean;breakout_parent:string|null;evidence_refs:string[];constraints:string[]}
export interface TargetPortCandidate{target_interface:string;status:PortMappingStatus;reasons:string[];already_assigned:boolean;evidence_refs:string[]}
export interface InterfaceMapping{source_interface:string;source_nameif?:string|null;target_interface:string|null;target_zone?:string|null;suggested_zone?:string|null;confirmed:boolean;source_profile?:string|null;source_version?:string|null;target_profile?:string|null;target_version?:string|null;source_entity_id?:string|null;source_hardware_id?:string|null;target_hardware_id?:string|null;status:PortMappingStatus;compatibility_reasons:string[];confirmed_by_user:boolean;source_evidence_refs:string[];target_evidence_refs:string[]}
export interface InterfaceMappingSummary{required:number;mapped:number;exact:number;compatible:number;unmapped:number;incompatible:number;unverified:number}
export interface InterfaceMappingRow{source_interface:string;required:boolean;source_capability:PortCapability|null;mapping:InterfaceMapping;target_candidates:TargetPortCandidate[]}
export interface InterfaceMappingContract{source_hardware_id:string;target_hardware_id:string;interfaces:InterfaceMappingRow[];summary:InterfaceMappingSummary;valid_for_conversion:boolean;blocking_reasons:string[];evidence_refs:string[]}
export interface InterfaceMappingPreflight{project_id:string;interface_mapping_required:boolean;interface_mapping:InterfaceMappingContract}
