import { useEffect, useState } from "react";
import { api } from "../api";
import {
  initialSelection,
  requiresInterfaceMapping,
  resolveCompatibility,
  type PlatformRegistry,
  type PlatformSelection,
} from "../platformContext";
import type { InterfaceMappingContract, Profile, Result } from "../types";
import { Icon } from "./Icon";
import { CodeEditor, ConversionSuccess } from "./LockedPanels";
import { VendorBrand, vendorDisplayName } from "./VendorBrand";

export interface ContextProps {
  profiles: Profile[];
  max: number;
  text: string;
  name: string;
  selection: PlatformSelection;
  detectedVersion: string;
  running: boolean;
  stale: boolean;
  onLoad: (t: string, n: string) => void;
  onRun: () => void;
  onRemove: () => void;
  onSelection: (v: PlatformSelection) => void;
  onUseDetected: () => void;
  onReadinessChange?: (ready: boolean) => void;
  interfaceMapping?: InterfaceMappingContract;
  mappingLoading: boolean;
  mappingPending: boolean;
  onOpenMapping: () => void;
  onMappingAvailability: (available: boolean) => void;
  demo?: boolean;
  result?: Result;
  onExitDemo?: () => void;
}

const exactVersion = (value: string) =>
  /^\d+\.\d+\.\d+(?:[-a-z0-9.]*)?$/i.test(value) ||
  /^\d+\.\d+R\d+$/i.test(value);
const statusLabel = {
  SUPPORTED: "Supported",
  UNSUPPORTED: "Unsupported",
  VERSION_NOT_VERIFIED: "Version not verified",
  UNKNOWN_HARDWARE: "Unknown hardware",
  UNKNOWN_SOFTWARE: "Unknown software",
} as const;

export function MigrationContext(props: ContextProps) {
  const [registry, setRegistry] = useState<PlatformRegistry>(),
    [error, setError] = useState(""),
    [paste, setPaste] = useState(false),
    [value, setValue] = useState(""),
    [detectedDismissed, setDetectedDismissed] = useState(false);
  useEffect(() => {
    const controller = new AbortController();
    api
      .registry(controller.signal)
      .then(setRegistry)
      .catch((reason) => {
        if (!controller.signal.aborted) setError(String(reason));
      });
    return () => controller.abort();
  }, []);
  useEffect(() => setDetectedDismissed(false), [props.detectedVersion]);

  function domainChanged(domain: string) {
    props.onSelection({ ...initialSelection, domain });
  }
  function endpointChanged(
    side: "source" | "target",
    changes: Partial<PlatformSelection["source"]>,
  ) {
    props.onSelection({
      ...props.selection,
      [side]: { ...props.selection[side], ...changes },
    });
  }
  const sourceCompatibility = resolveCompatibility(
    registry,
    props.selection.source,
    props.profiles,
  );
  const targetCompatibility = resolveCompatibility(
    registry,
    props.selection.target,
    props.profiles,
  );
  const target = props.profiles.find(
    (profile) => profile.id === props.selection.target.profileId,
  );
  const targetRenderer = Boolean(
    target?.target_versions?.includes(props.selection.target.osVersion) ||
    target?.version_profiles?.some(
      (version) =>
        version.exact_version === props.selection.target.osVersion &&
        version.target_renderer_available,
    ),
  );
  const mappingAvailable = Boolean(
    !props.demo && requiresInterfaceMapping(registry, props.selection),
  );
  const mappingReady = Boolean(
    !mappingAvailable ||
      (props.interfaceMapping?.valid_for_conversion && !props.mappingPending),
  );
  const platformReady = Boolean(
    props.text &&
      sourceCompatibility.status === "SUPPORTED" &&
      targetCompatibility.status === "SUPPORTED" &&
      targetRenderer,
  );
  const canConvert = platformReady && mappingReady;
  let mappingButtonLabel = "Interface Mapping";
  if (props.mappingLoading) mappingButtonLabel = "Preparing Mapping...";
  else if (props.interfaceMapping?.valid_for_conversion && !props.mappingPending)
    mappingButtonLabel = "Interface Mapping: Ready";
  else if (props.interfaceMapping)
    mappingButtonLabel = `Interface Mapping: ${props.interfaceMapping.summary.mapped}/${props.interfaceMapping.summary.required}`;
  useEffect(() => {
    props.onReadinessChange?.(canConvert);
  }, [canConvert, props.onReadinessChange]);
  useEffect(() => {
    props.onMappingAvailability(mappingAvailable);
  }, [mappingAvailable, props.onMappingAvailability]);

  async function loadFile(file?: File) {
    if (!file) return;
    if (file.size > props.max) {
      setError("Configuration exceeds the 100 MiB limit.");
      return;
    }
    try {
      props.onLoad(await file.text(), file.name);
    } catch {
      setError("Configuration could not be read.");
    }
  }

  function endpoint(side: "Source" | "Target") {
    const source = side === "Source",
      key = source ? "source" : "target",
      selected = props.selection[key];
    if (props.demo) {
      const vendor = source ? "Palo Alto Networks" : "Fortinet",
        hardware = source ? "PA-5220" : "FortiGate 6000F",
        version = source ? "PAN-OS 10.2.6" : "FortiOS 7.4.3";
      return (
        <fieldset
          className={source ? "source-card" : "target-card"}
          data-testid={source ? "source-context" : "target-context"}
        >
          <legend>{side} Platform</legend>
          {source && (
            <label className="domain-control">
              Domain
              <span className="select-control">
                <Icon name="shield" />
                <select
                  aria-label="Domain"
                  value="FIREWALL"
                  onChange={() => props.onExitDemo?.()}
                >
                  <option value="FIREWALL">Firewall</option>
                </select>
                <Icon name="chevron" />
              </span>
            </label>
          )}
          <VendorBrand vendor={vendor} />
          <div className="platform-fields">
            <label>
              Vendor
              <span className="select-control">
                <select
                  aria-label={`${side} Vendor`}
                  value="fixture"
                  onChange={() => props.onExitDemo?.()}
                >
                  <option value="fixture">{vendor}</option>
                </select>
                <Icon name="chevron" />
              </span>
            </label>
            <label>
              Hardware
              <span className="select-control">
                <select
                  aria-label={`${side} Hardware`}
                  value="fixture"
                  onChange={() => props.onExitDemo?.()}
                >
                  <option value="fixture">{hardware}</option>
                </select>
                <Icon name="chevron" />
              </span>
            </label>
            <label>
              OS Version
              <span className="select-control">
                <select
                  aria-label={`${side} OS Version`}
                  value="fixture"
                  onChange={() => props.onExitDemo?.()}
                >
                  <option value="fixture">{version}</option>
                </select>
                <Icon name="chevron" />
              </span>
            </label>
          </div>
          <button className="evidence-link" onClick={() => {}}>
            <Icon name="file" />
            Evidence
          </button>
        </fieldset>
      );
    }

    const profiles = props.profiles.filter(
      (profile) => profile.domain === props.selection.domain,
    );
    const vendors = [
      ...new Set(
        (registry?.hardware_profiles || [])
          .filter((hardware) => hardware.domain === props.selection.domain)
          .map((hardware) => hardware.vendor),
      ),
    ];
    const models =
      registry?.hardware_profiles.filter(
        (hardware) =>
          hardware.domain === props.selection.domain &&
          hardware.vendor === selected.vendor,
      ) || [];
    const profile = props.profiles.find(
      (item) => item.id === selected.profileId,
    );
    const pairs =
      registry?.hardware_software_support.filter(
        (item) => item.hardware_id === selected.hardwareId,
      ) || [];
    const versions = [
      ...new Set([
        ...pairs.map((item) => item.exact_version),
        ...(profile?.version_profiles?.map((item) => item.exact_version) || []),
        ...(profile?.supported_versions.filter(exactVersion) || []),
        ...(source && props.detectedVersion ? [props.detectedVersion] : []),
        ...(selected.osVersion ? [selected.osVersion] : []),
      ]),
    ];
    const compatibility = source ? sourceCompatibility : targetCompatibility;
    const mismatch =
      source &&
      props.detectedVersion &&
      props.detectedVersion !== selected.osVersion &&
      !detectedDismissed;
    return (
      <fieldset
        className={source ? "source-card" : "target-card"}
        data-testid={source ? "source-context" : "target-context"}
        disabled={props.running}
      >
        <legend>{side} Platform</legend>
        {source && (
          <label className="domain-control">
            Domain
            <span className="select-control">
              <Icon name="shield" />
              <select
                aria-label="Domain"
                value={props.selection.domain}
                disabled={!registry || props.running}
                onChange={(event) => domainChanged(event.target.value)}
              >
                {registry?.domains.map((domain) => (
                  <option key={domain.id} value={domain.id}>
                    {domain.label}
                  </option>
                ))}
              </select>
              <Icon name="chevron" />
            </span>
          </label>
        )}
        <VendorBrand vendor={selected.vendor || "Vendor"} />
        <div className="platform-fields">
          <label>
            Vendor
            <span className="select-control">
              <select
                aria-label={`${side} Vendor`}
                value={selected.vendor}
                onChange={(event) =>
                  endpointChanged(key, {
                    vendor: event.target.value,
                    hardwareId: "",
                    profileId: "",
                    osVersion: "",
                  })
                }
              >
                <option value="">Select vendor</option>
                {vendors.map((vendor) => (
                  <option key={vendor} value={vendor}>
                    {vendorDisplayName(vendor)}
                  </option>
                ))}
              </select>
              <Icon name="chevron" />
            </span>
          </label>
          <label>
            Hardware
            <span className="select-control">
              <select
                aria-label={`${side} Hardware`}
                value={selected.hardwareId}
                disabled={!selected.vendor}
                onChange={(event) => {
                  const hardwareId = event.target.value,
                    candidates = profiles.filter(
                      (item) => item.vendor === selected.vendor,
                    ),
                    osFamilies = new Set(
                      registry?.hardware_software_support
                        .filter((item) => item.hardware_id === hardwareId)
                        .map((item) => item.os_family) || [],
                    ),
                    matching = candidates.filter(
                      (item) =>
                        item.os_family && osFamilies.has(item.os_family),
                    ),
                    nextProfile = hardwareId
                      ? matching.length === 1
                        ? matching[0]
                        : candidates.length === 1
                          ? candidates[0]
                          : undefined
                      : undefined;
                  endpointChanged(key, {
                    hardwareId,
                    profileId: nextProfile?.id || "",
                    osVersion: "",
                  });
                }}
              >
                <option value="">Select hardware</option>
                {models.map((hardware) => (
                  <option key={hardware.id} value={hardware.id}>
                    {hardware.model}
                  </option>
                ))}
              </select>
              <Icon name="chevron" />
            </span>
          </label>
          <label>
            OS Version
            <span className="select-control">
              <select
                aria-label={`${side} OS Version`}
                value={selected.osVersion}
                disabled={!selected.hardwareId}
                onChange={(event) =>
                  endpointChanged(key, { osVersion: event.target.value })
                }
              >
                <option value="">Select version</option>
                {versions.map((version) => (
                  <option key={version}>{version}</option>
                ))}
              </select>
              <Icon name="chevron" />
            </span>
          </label>
        </div>
        {mismatch && (
          <div className="detected-version" role="status">
            <span>
              Configuration reports {props.detectedVersion}; selected version is{" "}
              {selected.osVersion || "empty"}.
            </span>
            <button onClick={props.onUseDetected}>Use detected version</button>
            {selected.osVersion && (
              <button onClick={() => setDetectedDismissed(true)}>
                Keep selected version
              </button>
            )}
          </div>
        )}
        <details className="evidence-details">
          <summary>
            <Icon name="file" />
            Evidence
          </summary>
          <p role="status">
            <b>
              {selected.hardwareId && selected.osVersion
                ? statusLabel[compatibility.status]
                : "Not verified"}
            </b>
          </p>
          {compatibility.evidenceRefs.length ? (
            compatibility.evidenceRefs.map((referenceId) => {
              const evidence = registry?.evidence[referenceId];
              return evidence ? (
                <p key={referenceId}>
                  <a href={evidence.reference} target="_blank" rel="noreferrer">
                    {evidence.title}
                  </a>
                </p>
              ) : (
                <p key={referenceId}>{referenceId}</p>
              );
            })
          ) : (
            <p>No exact hardware/OS support evidence captured.</p>
          )}
        </details>
      </fieldset>
    );
  }

  return (
    <section className="manual-context">
      {error && <p role="alert">{error}</p>}
      <div className="platform-row">
        {endpoint("Source")}
        <span className="platform-arrow" data-testid="source-target-arrow">
          <Icon name="arrowRight" />
        </span>
        {endpoint("Target")}
        <ConversionSuccess demo={props.demo} result={props.result} />
      </div>
      <section className="source-config-section">
        <header>
          <div>
            <h2>Source Configuration</h2>
            <p>Paste or upload the source configuration file</p>
          </div>
          <div className="source-actions">
            <label className="file">
              <Icon name="folder" />
              Open File
              <input
                aria-label="Open File"
                type="file"
                accept=".cfg,.conf,.txt,.xml"
                onChange={async (event) => {
                  await loadFile(event.target.files?.[0]);
                  event.target.value = "";
                }}
              />
            </label>
            <button className="primary" onClick={() => setPaste(true)}>
              <Icon name="file" />
              Paste from Clipboard
            </button>
            {!props.demo && mappingAvailable && (
              <button
                className="interface-mapping-button"
                disabled={!platformReady || props.running || props.mappingLoading}
                onClick={props.onOpenMapping}
              >
                <Icon name="branch" />
                {mappingButtonLabel}
              </button>
            )}
            {!props.demo && (
              <button
                className="convert-button"
                disabled={!canConvert || props.running}
                onClick={props.onRun}
                title={
                  mappingAvailable && !mappingReady
                    ? "Complete required interface mappings before conversion."
                    : "Exact platform support must be verified before conversion."
                }
              >
                <Icon name="play" />
                {props.running ? "Converting..." : "Convert"}
              </button>
            )}
          </div>
        </header>
        {props.stale && (
          <strong className="stale-note">
            Migration context changed. Previous results are stale.
          </strong>
        )}
        <CodeEditor
          text={props.text}
          title="Source Configuration"
          showHeader={false}
        />
      </section>
      {paste && (
        <div className="paste-editor">
          <label>
            Configuration
            <textarea
              aria-label="Configuration"
              value={value}
              onChange={(event) => setValue(event.target.value)}
              autoFocus
            />
          </label>
          <div>
            <button onClick={() => setPaste(false)}>Cancel</button>
            <button
              disabled={
                !value.trim() ||
                new TextEncoder().encode(value).length > props.max
              }
              onClick={() => {
                props.onLoad(value, "Pasted configuration");
                setPaste(false);
                setValue("");
              }}
            >
              Use Configuration
            </button>
          </div>
        </div>
      )}
    </section>
  );
}
