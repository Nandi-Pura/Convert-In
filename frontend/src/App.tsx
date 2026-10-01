import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api } from "./api";
import { Workbench } from "./components/Workbench";
import {
  buildOperationRequest,
  initialSelection,
  interfaceMappingPayload,
  type PlatformSelection,
} from "./platformContext";
import type {
  InterfaceMapping,
  InterfaceMappingContract,
  Manifest,
  Operation,
  Profile,
  Result,
} from "./types";

const boot = JSON.parse(
  document.getElementById("configmorph-bootstrap")?.textContent ||
    '{"profiles":[],"maxConfigBytes":104857600}',
) as { profiles: Profile[]; maxConfigBytes: number };

export default function App() {
  const [sourceText, setSourceText] = useState("");
  const [sourceName, setSourceName] = useState("");
  const [selection, setSelection] = useState<PlatformSelection>(initialSelection);
  const [detectedVersion, setDetectedVersion] = useState("");
  const [result, setResult] = useState<Result>();
  const [manifest, setManifest] = useState<Manifest>();
  const [operation, setOperation] = useState<Operation>();
  const [error, setError] = useState("");
  const [stale, setStale] = useState(false);
  const [preflightProjectId, setPreflightProjectId] = useState<string>();
  const [interfaceMapping, setInterfaceMapping] = useState<InterfaceMappingContract>();
  const [mappingOpen, setMappingOpen] = useState(false);
  const [mappingLoading, setMappingLoading] = useState(false);
  const [mappingError, setMappingError] = useState("");
  const [mappingPending, setMappingPending] = useState(false);
  const [mappingAvailable, setMappingAvailable] = useState(false);
  const mappingGeneration = useRef(0);
  const closeMapping = useCallback(() => setMappingOpen(false), []);

  const running = Boolean(
    operation && !operation.completed && operation.status !== "FAILED",
  );
  const selectedSource = useMemo(
    () => boot.profiles.find((profile) => profile.id === selection.source.profileId),
    [selection.source.profileId],
  );
  const selectedTarget = useMemo(
    () => boot.profiles.find((profile) => profile.id === selection.target.profileId),
    [selection.target.profileId],
  );

  useEffect(() => {
    if (!operation || operation.completed || operation.status === "FAILED") return;
    const controller = new AbortController();
    const timer = setTimeout(async () => {
      try {
        const next = await api.operation(operation.operation_id, controller.signal);
        setOperation(next);
        if (next.result) {
          setResult(next.result);
          setManifest(undefined);
          setStale(false);
        }
        if (next.status === "FAILED")
          setError(
            `${next.stage.replaceAll("_", " ")} failed: ${next.error?.message || "Operation failed"}`,
          );
      } catch (reason) {
        if (!controller.signal.aborted) {
          const message = String(reason);
          setError(message);
          setOperation((current) =>
            current
              ? {
                  ...current,
                  status: "FAILED",
                  completed: true,
                  error: { message },
                }
              : current,
          );
        }
      }
    }, 300);
    return () => {
      clearTimeout(timer);
      controller.abort();
    };
  }, [operation]);

  function clearMappingState() {
    mappingGeneration.current += 1;
    setPreflightProjectId(undefined);
    setInterfaceMapping(undefined);
    setMappingOpen(false);
    setMappingLoading(false);
    setMappingError("");
    setMappingPending(false);
  }

  async function load(text: string, name: string) {
    if (new TextEncoder().encode(text).length > boot.maxConfigBytes) {
      setError("Configuration exceeds the 100 MiB limit.");
      return;
    }
    clearMappingState();
    setSourceText(text);
    setSourceName(name);
    setResult(undefined);
    setManifest(undefined);
    setStale(false);
    setError("");
    try {
      const detected = await api.detect(text);
      const version = detected.version || "";
      setDetectedVersion(version);
      if (version && selection.source.hardwareId && !selection.source.osVersion)
        setSelection((current) => ({
          ...current,
          source: { ...current.source, osVersion: version },
        }));
    } catch (reason) {
      setError(String(reason));
    }
  }

  function hydrate(data: { manifest: Manifest; source_text: string; result: Result }) {
    clearMappingState();
    const nextResult = { ...data.result, project_id: data.manifest.project_id };
    const source = data.manifest.source;
    const target = data.manifest.target;
    setManifest(data.manifest);
    setResult(nextResult);
    setSourceText(data.source_text);
    setSourceName(source.filename);
    setDetectedVersion(source.exact_version);
    setSelection({
      domain: source.domain || nextResult.source_profile.domain,
      source: {
        vendor: source.vendor || nextResult.source_profile.vendor,
        hardwareId: source.hardware_id || "",
        profileId: source.profile_id || nextResult.source_profile.id,
        osVersion: source.exact_version,
      },
      target: {
        vendor: target.vendor || nextResult.target_profile.vendor,
        hardwareId: target.hardware_id || "",
        profileId: target.profile_id || nextResult.target_profile.id,
        osVersion: target.exact_version,
      },
    });
    setOperation(undefined);
    setStale(false);
    setError("");
    const generation = mappingGeneration.current;
    setPreflightProjectId(data.manifest.project_id);
    setMappingLoading(true);
    api
      .interfaceMappings(data.manifest.project_id)
      .then((contract) => {
        if (generation === mappingGeneration.current) setInterfaceMapping(contract);
      })
      .catch(() => {
        if (generation === mappingGeneration.current) {
          setPreflightProjectId(undefined);
          setInterfaceMapping(undefined);
        }
      })
      .finally(() => {
        if (generation === mappingGeneration.current) setMappingLoading(false);
      });
  }

  async function openProject(id: string) {
    try {
      hydrate(await api.project(id));
    } catch (reason) {
      setError(String(reason));
    }
  }

  async function importProject(file: File) {
    try {
      const imported = await api.importProject(file);
      hydrate(await api.project(imported.project_id));
    } catch (reason) {
      setError(String(reason));
    }
  }

  function contextChanged(next: PlatformSelection) {
    clearMappingState();
    setSelection(next);
    if (result) setStale(true);
  }

  async function openInterfaceMapping() {
    setMappingOpen(true);
    setMappingError("");
    if (preflightProjectId && interfaceMapping) return;
    const generation = mappingGeneration.current;
    setMappingLoading(true);
    try {
      const prepared = await api.preflight(
        buildOperationRequest(sourceText, selection, boot.profiles),
      );
      if (generation !== mappingGeneration.current) return;
      setPreflightProjectId(prepared.project_id);
      setInterfaceMapping(prepared.interface_mapping);
      setMappingPending(false);
    } catch (reason) {
      if (generation === mappingGeneration.current) setMappingError(String(reason));
    } finally {
      if (generation === mappingGeneration.current) setMappingLoading(false);
    }
  }

  async function saveInterfaceMappings(mappings: InterfaceMapping[]) {
    if (!preflightProjectId) return;
    setMappingLoading(true);
    setMappingError("");
    try {
      setInterfaceMapping(
        await api.saveInterfaceMappings(preflightProjectId, mappings),
      );
      setMappingPending(false);
      if (result) setStale(true);
    } catch (reason) {
      setMappingError(String(reason));
    } finally {
      setMappingLoading(false);
    }
  }

  async function resetInterfaceMappings() {
    if (!preflightProjectId) return;
    setMappingLoading(true);
    setMappingError("");
    try {
      setInterfaceMapping(await api.resetInterfaceMappings(preflightProjectId));
      setMappingPending(false);
      if (result) setStale(true);
    } catch (reason) {
      setMappingError(String(reason));
    } finally {
      setMappingLoading(false);
    }
  }

  async function validateInterfaceMappings() {
    if (!preflightProjectId) return;
    setMappingLoading(true);
    setMappingError("");
    try {
      setInterfaceMapping(await api.validateInterfaceMappings(preflightProjectId));
    } catch (reason) {
      setMappingError(String(reason));
    } finally {
      setMappingLoading(false);
    }
  }

  async function run() {
    if (!selectedSource || !selectedTarget) {
      setError("Select source and target profiles.");
      return;
    }
    if (
      mappingAvailable &&
      (!interfaceMapping?.valid_for_conversion || mappingPending)
    ) {
      setError("Complete required interface mappings before conversion.");
      return;
    }
    setError("");
    setResult(undefined);
    setManifest(undefined);
    setStale(false);
    try {
      const started = await api.start(
        buildOperationRequest(
          sourceText,
          selection,
          boot.profiles,
          interfaceMappingPayload(interfaceMapping),
        ),
      );
      setOperation({
        operation_id: started.operation_id,
        status: "RUNNING",
        stage: "VALIDATING_SOURCE",
        stages: [],
        elapsed_ms: 0,
      });
    } catch (reason) {
      setError(String(reason));
    }
  }

  return (
    <Workbench
      profiles={boot.profiles}
      maxConfigBytes={boot.maxConfigBytes}
      sourceText={sourceText}
      sourceName={sourceName}
      selection={selection}
      detectedVersion={detectedVersion}
      result={result}
      manifest={manifest}
      operation={operation}
      error={error}
      stale={stale}
      running={running}
      interfaceMapping={interfaceMapping}
      mappingOpen={mappingOpen}
      mappingLoading={mappingLoading}
      mappingError={mappingError}
      mappingPending={mappingPending}
      onLoad={load}
      onRun={run}
      onOpen={openProject}
      onImportProject={importProject}
      onRemove={() => {
        clearMappingState();
        setSourceText("");
        setSourceName("");
        setDetectedVersion("");
        setResult(undefined);
        setManifest(undefined);
        setOperation(undefined);
        setStale(false);
      }}
      onSelection={contextChanged}
      onUseDetected={() =>
        contextChanged({
          ...selection,
          source: { ...selection.source, osVersion: detectedVersion },
        })
      }
      onOpenMapping={openInterfaceMapping}
      onCloseMapping={closeMapping}
      onSaveMappings={saveInterfaceMappings}
      onResetMappings={resetInterfaceMappings}
      onValidateMappings={validateInterfaceMappings}
      onMappingPending={setMappingPending}
      onMappingAvailability={setMappingAvailable}
    />
  );
}