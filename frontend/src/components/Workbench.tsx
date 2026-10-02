import { useEffect, useRef, useState } from "react";
import { api } from "../api";
import { MigrationContext } from "./PlatformContext";
import { InterfaceMappingDialog } from "./InterfaceMappingDialog";
import { CodeEditor, ConversionSummary } from "./LockedPanels";
import { Icon } from "./Icon";
import { visualFixture, visualFixtureEnabled } from "../visualFixture";
import type { PlatformSelection } from "../platformContext";
import type {
  Evidence,
  InterfaceMapping,
  InterfaceMappingContract,
  Manifest,
  MigrationPlan,
  Operation,
  Profile,
  Result,
} from "../types";
import FigmaHeader from "./Header";
import InvestigationTabs, { tabNames, type TabName } from "./InvestigationTabs";
import SafetyFooter from "./SafetyFooter";
import { vendorDisplayName } from "./VendorBrand";

const fmt = (n: number) => n.toLocaleString(),
  text = (v: unknown) =>
    v == null ? "—" : typeof v === "string" ? v : JSON.stringify(v);
type Props = {
  profiles: Profile[];
  maxConfigBytes: number;
  sourceText: string;
  sourceName: string;
  selection: PlatformSelection;
  detectedVersion: string;
  result?: Result;
  manifest?: Manifest;
  operation?: Operation;
  error: string;
  stale: boolean;
  running: boolean;
  interfaceMapping?: InterfaceMappingContract;
  mappingOpen: boolean;
  mappingLoading: boolean;
  mappingError: string;
  mappingPending: boolean;
  onLoad: (t: string, n: string) => void;
  onRun: () => void;
  onOpen: (id: string) => void;
  onImportProject: (file: File) => void;
  onRemove: () => void;
  onSelection: (v: PlatformSelection) => void;
  onUseDetected: () => void;
  onOpenMapping: () => void;
  onCloseMapping: () => void;
  onSaveMappings: (mappings: InterfaceMapping[]) => Promise<void>;
  onResetMappings: () => Promise<void>;
  onValidateMappings: () => Promise<void>;
  onMappingPending: (pending: boolean) => void;
  onMappingAvailability: (available: boolean) => void;
};
function Empty({ title, detail }: { title: string; detail: string }) {
  return (
    <div className="figma-empty workspace-empty">
      <b>{title}</b>
      <span>{detail}</span>
    </div>
  );
}
function SemanticDiff({ result }: { result: Result }) {
  const entities = result.semantic_diff?.entities || [],
    [selected, setSelected] = useState(0),
    item = entities[selected];
  if (!entities.length)
    return (
      <Empty
        title="No semantic diff"
        detail="This operation did not produce property-level semantic differences."
      />
    );
  return (
    <div className="figma-split">
      <nav>
        {entities.map((e, i) => (
          <button
            className={i === selected ? "selected" : ""}
            onClick={() => setSelected(i)}
            key={e.entity_id || `${e.source_identity}-${i}`}
          >
            <small>{e.entity_type}</small>
            <b>{e.source_identity}</b>
            <span>{e.overall_classification}</span>
          </button>
        ))}
      </nav>
      <section>
        <header>
          <b>
            {item.entity_type}: {item.source_identity}
          </b>
          <span>{item.overall_classification}</span>
        </header>
        <table>
          <thead>
            <tr>
              <th>Property</th>
              <th>Classification</th>
              <th>Source</th>
              <th>Target</th>
              <th>Reason</th>
            </tr>
          </thead>
          <tbody>
            {item.property_diffs.map((p, i) => (
              <tr key={`${p.property}-${i}`}>
                <td>{p.property}</td>
                <td>
                  <strong>{p.classification}</strong>
                </td>
                <td>{text(p.source_value)}</td>
                <td>{text(p.target_value)}</td>
                <td>{p.reason || "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </div>
  );
}
function Plan({
  plan,
  loading,
}: {
  plan?: MigrationPlan | null;
  loading: boolean;
}) {
  if (loading)
    return (
      <Empty
        title="Loading migration plan"
        detail="Reading the project artifact."
      />
    );
  if (!plan)
    return (
      <Empty
        title="No migration plan"
        detail="No migration-plan artifact exists for this project."
      />
    );
  const groups = plan.entities.reduce<Record<string, typeof plan.entities>>(
    (a, x) => {
      (a[x.entity_type] ??= []).push(x);
      return a;
    },
    {},
  );
  return (
    <div className="figma-list">
      <header>
        {fmt(plan.summary.total_entities || plan.entities.length)} entities ·
        ordered by artifact entity type
      </header>
      {Object.entries(groups).map(([name, items], i) => (
        <details key={name}>
          <summary>
            <span>
              <b>
                {i + 1}. {name.replaceAll("_", " ")}
              </b>
              <small>
                {items.filter((x) => x.render_eligible).length} ready ·{" "}
                {items.filter((x) => x.blocking).length} blocked
              </small>
            </span>
            <strong>{items.length}</strong>
          </summary>
          {items.map((x) => (
            <article key={x.entity_id}>
              <b>{x.source_name}</b>
              <span>
                {x.compatibility_status} ·{" "}
                {x.reasons.join("; ") || "No additional action"}
              </span>
              {x.dependencies.length > 0 && (
                <small>Dependencies: {x.dependencies.join(", ")}</small>
              )}
            </article>
          ))}
        </details>
      ))}
    </div>
  );
}
function EvidenceView({
  evidence,
  result,
  loading,
}: {
  evidence?: Evidence | null;
  result: Result;
  loading: boolean;
}) {
  const platform = result.platform_context,
    decisions = result.conversion_evidence || [];
  if (loading && !platform && !decisions.length)
    return (
      <Empty
        title="Loading evidence"
        detail="Reading platform and conversion provenance."
      />
    );
  if (!platform && !decisions.length && !evidence)
    return (
      <Empty
        title="No evidence"
        detail="This operation did not return platform or conversion evidence."
      />
    );
  return (
    <div className="figma-evidence">
      <header>
        <div>
          <b>Evidence</b>
          <span>Platform compatibility and conversion decisions</span>
        </div>
        {evidence && (
          <a
            href={
              "/api/projects/" +
              result.project_id +
              "/migration/download/evidence-pack"
            }
          >
            Download Evidence Pack
          </a>
        )}
      </header>
      <section>
        <h3>Platform Evidence</h3>
        {platform ? (
          <>
            {(["source", "target"] as const).map((side) => (
              <article key={side}>
                <b>
                  {side === "source" ? "Source" : "Target"}:{" "}
                  {platform[side].hardware_id} + {platform[side].os_version}
                </b>
                <span>{platform[side].compatibility_status}</span>
                {platform[side].evidence_refs.map((id) => {
                  const item = platform.evidence[id];
                  return item ? (
                    <p key={id}>
                      <a href={item.reference} target="_blank" rel="noreferrer">
                        {item.title}
                      </a>{" "}
                      · {item.section || item.revision || id}
                    </p>
                  ) : (
                    <p key={id}>{id}</p>
                  );
                })}
              </article>
            ))}
          </>
        ) : (
          <p>Platform evidence was not stored for this older project.</p>
        )}
      </section>
      <section>
        <h3>Conversion Evidence</h3>
        {decisions.length ? (
          <table>
            <thead>
              <tr>
                <th>Entity</th>
                <th>Decision</th>
                <th>Evidence</th>
              </tr>
            </thead>
            <tbody>
              {decisions.map((item) => (
                <tr key={item.entity_id}>
                  <td>
                    {item.entity_type}: {item.entity_id}
                  </td>
                  <td>
                    {item.decision}
                    {item.reasons.length ? " · " + item.reasons.join("; ") : ""}
                  </td>
                  <td>
                    {item.evidence_ids.join(", ") ||
                      "No document reference recorded"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p>No conversion decisions were returned.</p>
        )}
      </section>
      {evidence && (
        <section>
          <h3>Evidence Pack Manifest</h3>
          <dl>
            <dt>Manifest fingerprint</dt>
            <dd>{evidence.fingerprint}</dd>
            <dt>Source inclusion</dt>
            <dd>Raw source intentionally excluded</dd>
          </dl>
        </section>
      )}
    </div>
  );
}

export function Workbench(props: Props) {
  const [tab, setTab] = useState<TabName>("Raw Comparison"),
    [demo, setDemo] = useState(visualFixtureEnabled);
  const [plan, setPlan] = useState<MigrationPlan | null>(),
    [evidence, setEvidence] = useState<Evidence | null>(),
    [artifactError, setArtifactError] = useState(""),
    [copyMessage, setCopyMessage] = useState("");
  const [search, setSearch] = useState(""),
    [changesOnly, setChangesOnly] = useState(false),
    [expanded, setExpanded] = useState(false);
  const file = useRef<HTMLInputElement>(null);
  const sourceEditor = useRef<HTMLDivElement>(null),
    targetEditor = useRef<HTMLDivElement>(null),
    syncingEditor = useRef<HTMLDivElement | null>(null);
  const result = props.stale ? undefined : props.result;
  const isDemo = Boolean(demo && !props.result && !props.stale);
  const sourceText = isDemo ? visualFixture.source : props.sourceText;
  const candidate = isDemo ? visualFixture.candidate : result?.candidate || "";
  const readyCommands =
    result?.entities
      .filter(
        (e) =>
          e.copyable &&
          e.user_status === "READY" &&
          ["EXACT", "SUPPORTED"].includes(
            e.detailed_status.replace(/^CP2:\s*/, ""),
          ),
      )
      .flatMap((e) => e.commands)
      .join("\n") || "";
  useEffect(() => {
    setPlan(undefined);
    setEvidence(undefined);
    setCopyMessage("");
  }, [props.result?.project_id, props.stale]);
  useEffect(() => {
    if (!expanded) return;
    const restore = (event: KeyboardEvent) => {
      if (event.key === "Escape") setExpanded(false);
    };
    window.addEventListener("keydown", restore);
    return () => window.removeEventListener("keydown", restore);
  }, [expanded]);
  useEffect(() => {
    const id = props.result?.project_id;
    if (!id || props.stale) return;
    if (
      tab === "Migration Plan" &&
      !result?.migration_plan &&
      plan === undefined
    )
      api
        .plan(id)
        .then(setPlan)
        .catch((e) => {
          setPlan(null);
          setArtifactError(String(e));
        });
    if (tab === "Evidence" && evidence === undefined)
      api
        .evidence(id)
        .then(setEvidence)
        .catch((e) => {
          setEvidence(null);
          if (!result?.platform_context && !result?.conversion_evidence?.length)
            setArtifactError(String(e));
        });
  }, [tab, props.result?.project_id, props.stale, plan, evidence]);
  const open = () => {
    const id = prompt("Project ID");
    if (id?.trim()) {
      setDemo(false);
      props.onOpen(id.trim());
    }
  };
  async function copyCandidate() {
    const commands = isDemo ? visualFixture.candidate : readyCommands;
    if (!commands) return;
    try {
      await navigator.clipboard.writeText(
        `# CANDIDATE CONFIGURATION — ENGINEER REVIEW REQUIRED\n${isDemo ? "# VISUAL FIXTURE ONLY — NOT A CONVERSION RESULT\n" : ""}${commands}`,
      );
      setCopyMessage("READY commands copied.");
    } catch {
      setCopyMessage(
        "Clipboard access failed. Use Download Candidate for a real project.",
      );
    }
  }
  function syncEditorScroll(
    source: HTMLDivElement,
    target: HTMLDivElement | null,
  ) {
    if (!target) return;
    if (syncingEditor.current === source) {
      syncingEditor.current = null;
      return;
    }
    const sourceVertical = Math.max(
        0,
        source.scrollHeight - source.clientHeight,
      ),
      targetVertical = Math.max(0, target.scrollHeight - target.clientHeight);
    const sourceHorizontal = Math.max(
        0,
        source.scrollWidth - source.clientWidth,
      ),
      targetHorizontal = Math.max(0, target.scrollWidth - target.clientWidth);
    syncingEditor.current = target;
    target.scrollTop = sourceVertical
      ? (source.scrollTop / sourceVertical) * targetVertical
      : 0;
    target.scrollLeft = sourceHorizontal
      ? (source.scrollLeft / sourceHorizontal) * targetHorizontal
      : 0;
    requestAnimationFrame(() => {
      if (syncingEditor.current === target) syncingEditor.current = null;
    });
  }
  function renderResult() {
    if (!result && !isDemo)
      return (
        <Empty
          title={
            props.stale
              ? "Previous results are stale."
              : "Results appear after Convert."
          }
          detail="Open a source configuration and select verified platforms to begin."
        />
      );
    if (tab === "Raw Comparison") {
      const sourceVendor = isDemo
        ? "Palo Alto Networks"
        : vendorDisplayName(result?.source_profile.vendor || "Source");
      const targetVendor = isDemo
        ? "Fortinet"
        : vendorDisplayName(result?.target_profile.vendor || "Target");
      return (
        <div className="locked-comparison">
          <CodeEditor
            text={sourceText}
            title={`Source Configuration (${sourceVendor})`}
            vendor={sourceVendor}
            lineCount={isDemo ? 1776 : sourceText.split("\n").length}
            statuses={isDemo ? visualFixture.sourceStatuses : []}
            search={search}
            changesOnly={changesOnly}
            scrollRef={(element) => {
              sourceEditor.current = element;
            }}
            onEditorScroll={(element) =>
              syncEditorScroll(element, targetEditor.current)
            }
          />
          <CodeEditor
            text={candidate}
            title={`Target Configuration (${targetVendor})`}
            vendor={targetVendor}
            candidate
            lineCount={isDemo ? 1684 : candidate.split("\n").length}
            statuses={isDemo ? visualFixture.targetStatuses : []}
            search={search}
            changesOnly={changesOnly}
            scrollRef={(element) => {
              targetEditor.current = element;
            }}
            onEditorScroll={(element) =>
              syncEditorScroll(element, sourceEditor.current)
            }
            emptyMessage="Candidate configuration unavailable for this operation."
          />
        </div>
      );
    }
    if (tab === "Candidate Configuration")
      return candidate ? (
        <div className="candidate-result">
          <div className="candidate-actions">
            <button
              disabled={!isDemo && !readyCommands}
              onClick={copyCandidate}
            >
              <Icon name="copy" />
              Copy All READY
            </button>
            {!isDemo && result?.renderer_available && (
              <a
                href={`/api/projects/${result.project_id}/migration/download/config`}
                download={result.candidate_filename || "candidate-pan-os.set"}
              >
                <Icon name="download" />
                Download Candidate
              </a>
            )}
          </div>
          {copyMessage && <p role="status">{copyMessage}</p>}
          <CodeEditor
            text={candidate}
            title="Generated Candidate Configuration"
            candidate
          />
        </div>
      ) : (
        <Empty
          title="Candidate configuration unavailable"
          detail="The selected renderer did not produce safe candidate commands for this operation."
        />
      );
    if (tab === "Semantic Diff")
      return result ? (
        <SemanticDiff result={result} />
      ) : (
        <Empty
          title="Visual fixture only"
          detail="Semantic differences are available for actual project results."
        />
      );
    if (tab === "Migration Plan")
      return (
        <Plan
          plan={result?.migration_plan || plan}
          loading={!isDemo && !result?.migration_plan && plan === undefined}
        />
      );
    return result ? (
      <EvidenceView
        evidence={evidence}
        result={result}
        loading={evidence === undefined}
      />
    ) : (
      <Empty
        title="Visual fixture only"
        detail="Evidence is available for actual project results."
      />
    );
  }
  return (
    <main className={`app locked-app ${expanded ? "comparison-expanded" : ""}`}>
      <FigmaHeader
        projectId={props.result?.project_id}
        saved={Boolean(props.manifest)}
        demo={isDemo}
        onOpen={open}
        onImport={() => file.current?.click()}
      />
      <input
        ref={file}
        hidden
        type="file"
        accept=".zip,.configmorph.zip"
        onChange={(e) => {
          const f = e.target.files?.[0];
          if (f) {
            setDemo(false);
            props.onImportProject(f);
          }
          e.currentTarget.value = "";
        }}
      />
      <MigrationContext
        demo={isDemo}
        result={result}
        onExitDemo={() => setDemo(false)}
        profiles={props.profiles}
        max={props.maxConfigBytes}
        text={sourceText}
        name={isDemo ? "Visual fixture" : props.sourceName}
        selection={props.selection}
        detectedVersion={props.detectedVersion}
        running={props.running}
        stale={props.stale}
        onLoad={(text, name) => {
          setDemo(false);
          props.onLoad(text, name);
        }}
        onRun={props.onRun}
        interfaceMapping={props.interfaceMapping}
        mappingLoading={props.mappingLoading}
        mappingPending={props.mappingPending}
        onOpenMapping={props.onOpenMapping}
        onMappingAvailability={props.onMappingAvailability}
        onRemove={() => {
          setDemo(false);
          props.onRemove();
        }}
        onSelection={props.onSelection}
        onUseDetected={props.onUseDetected}
      />
      <InterfaceMappingDialog
        open={props.mappingOpen && !isDemo}
        contract={props.interfaceMapping}
        loading={props.mappingLoading}
        error={props.mappingError}
        onClose={props.onCloseMapping}
        onSave={props.onSaveMappings}
        onReset={props.onResetMappings}
        onValidate={props.onValidateMappings}
        onPendingChange={props.onMappingPending}
      />
      {(props.error || artifactError) && (
        <div className="error" role="alert">
          {props.error || artifactError}
        </div>
      )}
      <section className="workspace locked-results">
        <div className="results-main">
          <div className="results-navigation">
            <InvestigationTabs
              active={tab}
              onChange={(next) => {
                setArtifactError("");
                setTab(next);
              }}
            />
            {tab === "Raw Comparison" && (
              <div className="results-toolbar">
                <label>
                  <Icon name="search" />
                  <input
                    type="search"
                    aria-label="Search configuration"
                    placeholder="Search configuration..."
                    value={search}
                    onChange={(event) => setSearch(event.target.value)}
                  />
                </label>
                <button
                  aria-pressed={changesOnly}
                  onClick={() => setChangesOnly((value) => !value)}
                >
                  <Icon name="filter" />
                  Filters
                  <Icon name="chevron" />
                </button>
                <button onClick={() => setExpanded((value) => !value)}>
                  <Icon name={expanded ? "restore" : "expand"} />
                  {expanded ? "Restore" : "Expanded"}
                </button>
                <button
                  disabled={!isDemo && !readyCommands}
                  onClick={copyCandidate}
                >
                  <Icon name="copy" />
                  Copy All
                </button>
              </div>
            )}
          </div>
          {props.running && (
            <div className="processing" role="status">
              <b>
                {props.operation?.stage.replaceAll("_", " ") ||
                  "VALIDATING SOURCE"}
              </b>
              <span>
                {((props.operation?.elapsed_ms || 0) / 1000).toFixed(1)}s
                elapsed
              </span>
            </div>
          )}
          <div
            id="result-panel"
            role="tabpanel"
            aria-labelledby={`result-tab-${tabNames.indexOf(tab)}`}
            tabIndex={0}
          >
            {renderResult()}
          </div>
          {copyMessage && tab === "Raw Comparison" && (
            <p className="copy-status" role="status">
              {copyMessage}
            </p>
          )}
        </div>
        <ConversionSummary demo={isDemo} result={result} />
      </section>
      <SafetyFooter projectId={props.result?.project_id} demo={isDemo} />
    </main>
  );
}
