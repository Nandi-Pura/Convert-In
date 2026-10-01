import { useEffect, useMemo, useRef, useState } from "react";
import type {
  InterfaceMapping,
  InterfaceMappingContract,
  InterfaceMappingRow,
  PortMappingStatus,
  TargetPortCandidate,
} from "../types";
import { Icon } from "./Icon";

const compatibleStatuses = new Set<PortMappingStatus>(["EXACT", "COMPATIBLE"]);

export function visibleCandidates(
  row: InterfaceMappingRow,
  showUnavailable: boolean,
) {
  if (showUnavailable) return row.target_candidates;
  return row.target_candidates.filter(
    (candidate) =>
      compatibleStatuses.has(candidate.status) ||
      candidate.target_interface === row.mapping.target_interface,
  );
}

export function mappingStatusClass(status: PortMappingStatus) {
  if (compatibleStatuses.has(status)) return "mapping-good";
  if (status === "INCOMPATIBLE") return "mapping-bad";
  return "mapping-pending";
}

type Draft = { targetInterface: string; confirmed: boolean };
type Props = {
  open: boolean;
  contract?: InterfaceMappingContract;
  loading: boolean;
  error: string;
  onClose: () => void;
  onSave: (mappings: InterfaceMapping[]) => Promise<void>;
  onReset: () => Promise<void>;
  onValidate: () => Promise<void>;
  onPendingChange: (pending: boolean) => void;
};

export function InterfaceMappingDialog({
  open,
  contract,
  loading,
  error,
  onClose,
  onSave,
  onReset,
  onValidate,
  onPendingChange,
}: Props) {
  const [drafts, setDrafts] = useState<Record<string, Draft>>({});
  const [showUnavailable, setShowUnavailable] = useState(false);
  const [resetArmed, setResetArmed] = useState(false);
  const dialog = useRef<HTMLElement>(null);
  const closeButton = useRef<HTMLButtonElement>(null);
  const returnFocus = useRef<HTMLElement | null>(null);

  useEffect(() => {
    if (!contract) return;
    setDrafts(
      Object.fromEntries(
        contract.interfaces.map((row) => [
          row.source_interface,
          {
            targetInterface: row.mapping.target_interface || "",
            confirmed: row.mapping.confirmed_by_user,
          },
        ]),
      ),
    );
    setResetArmed(false);
  }, [contract]);

  const pending = useMemo(
    () =>
      Boolean(
        contract?.interfaces.some((row) => {
          const draft = drafts[row.source_interface];
          return Boolean(
            draft &&
              (draft.targetInterface !== (row.mapping.target_interface || "") ||
                draft.confirmed !== row.mapping.confirmed_by_user),
          );
        }),
      ),
    [contract, drafts],
  );

  useEffect(() => onPendingChange(pending), [onPendingChange, pending]);
  useEffect(() => {
    if (!open) return;
    if (!returnFocus.current?.isConnected) {
      returnFocus.current = document.activeElement as HTMLElement | null;
    }
    closeButton.current?.focus();
    const keydown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        onClose();
        return;
      }
      if (event.key !== "Tab" || !dialog.current) return;
      const focusable = Array.from(
        dialog.current.querySelectorAll<HTMLElement>(
          'button:not([disabled]), select:not([disabled]), input:not([disabled]), summary, [tabindex]:not([tabindex="-1"])',
        ),
      ).filter((element) => !element.hasAttribute("hidden"));
      if (!focusable.length) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };
    window.addEventListener("keydown", keydown);
    return () => {
      window.removeEventListener("keydown", keydown);
      returnFocus.current?.focus();
    };
  }, [open, onClose]);

  if (!open) return null;

  function mappingsWith(
    sourceInterface: string,
    targetInterface: string,
    confirmed: boolean,
  ) {
    return (contract?.interfaces || []).map((row) => {
      const draft =
        row.source_interface === sourceInterface
          ? { targetInterface, confirmed }
          : drafts[row.source_interface] || {
              targetInterface: row.mapping.target_interface || "",
              confirmed: row.mapping.confirmed_by_user,
            };
      return {
        ...row.mapping,
        target_interface: draft.targetInterface || null,
        confirmed: draft.confirmed,
        confirmed_by_user: draft.confirmed,
      };
    });
  }

  function candidateFor(row: InterfaceMappingRow, targetInterface: string) {
    return row.target_candidates.find(
      (candidate) => candidate.target_interface === targetInterface,
    );
  }

  return (
    <div
      className="mapping-dialog-backdrop"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <section
        ref={dialog}
        className="mapping-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="mapping-dialog-title"
      >
        <header>
          <div>
            <h2 id="mapping-dialog-title">Interface Mapping</h2>
            <p>
              Map required physical interfaces from {contract?.source_hardware_id || "source hardware"} to {contract?.target_hardware_id || "target hardware"}.
            </p>
          </div>
          <div className="mapping-dialog-heading-actions">
            {contract && (
              <span className={contract.valid_for_conversion && !pending ? "mapping-ready" : "mapping-count"}>
                {contract.valid_for_conversion && !pending
                  ? "Ready"
                  : `${contract.summary.mapped}/${contract.summary.required} confirmed`}
              </span>
            )}
            <button ref={closeButton} onClick={onClose} aria-label="Close Interface Mapping">
              Close
            </button>
          </div>
        </header>

        <div className="mapping-dialog-body">
          {error && <p className="mapping-error" role="alert">{error}</p>}
          {loading && !contract && <p role="status">Preparing source interfaces and target candidates...</p>}
          {contract && (
            <>
              <div className="mapping-summary" aria-label="Interface mapping summary">
                <span><b>{contract.summary.required}</b> Required</span>
                <span><b>{contract.summary.mapped}</b> Mapped</span>
                <span><b>{contract.summary.unmapped}</b> Unmapped</span>
                <span><b>{contract.summary.incompatible}</b> Incompatible</span>
                <span><b>{contract.summary.unverified}</b> Unverified</span>
                <label>
                  <input
                    type="checkbox"
                    checked={showUnavailable}
                    onChange={(event) => setShowUnavailable(event.target.checked)}
                  />
                  Show incompatible or unverified ports
                </label>
              </div>

              {!contract.interfaces.length && (
                <div className="mapping-empty">
                  <b>No physical interface mapping is required for this configuration.</b>
                  <p>The selected source does not reference physical dataplane interfaces that require remapping.</p>
                </div>
              )}

              <div className="mapping-rows">
                {contract.interfaces.map((row) => {
                  const draft = drafts[row.source_interface] || {
                    targetInterface: row.mapping.target_interface || "",
                    confirmed: row.mapping.confirmed_by_user,
                  };
                  const changed =
                    draft.targetInterface !== (row.mapping.target_interface || "") ||
                    draft.confirmed !== row.mapping.confirmed_by_user;
                  const candidate = candidateFor(row, draft.targetInterface);
                  const currentAssignment = draft.targetInterface === row.mapping.target_interface;
                  const confirmable = Boolean(
                    candidate &&
                      compatibleStatuses.has(candidate.status) &&
                      (!candidate.already_assigned || currentAssignment) &&
                      !draft.confirmed,
                  );
                  const status = changed ? "UNMAPPED" : row.mapping.status;
                  return (
                    <article className="mapping-row" key={row.source_interface}>
                      <div className="mapping-source">
                        <small>Source interface</small>
                        <b>{row.source_interface}</b>
                        {row.source_capability ? (
                          <dl>
                            <div><dt>Connector</dt><dd>{row.source_capability.connector}</dd></div>
                            <div><dt>Media</dt><dd>{row.source_capability.media_capability}</dd></div>
                            <div><dt>Speeds</dt><dd>{row.source_capability.supported_speeds.join(", ") || "Unverified"}</dd></div>
                            <div><dt>Layer 3</dt><dd>{row.source_capability.supports_layer3 ? "Supported" : "Unavailable"}</dd></div>
                          </dl>
                        ) : (
                          <span className="mapping-capability-missing">Source port capability is unverified.</span>
                        )}
                      </div>

                      <span className="mapping-row-arrow" aria-hidden="true"><Icon name="arrowRight" /></span>

                      <div className="mapping-target">
                        <label htmlFor={`mapping-${row.source_interface}`}>Target interface</label>
                        <select
                          id={`mapping-${row.source_interface}`}
                          value={draft.targetInterface}
                          disabled={loading}
                          onChange={(event) =>
                            setDrafts((current) => ({
                              ...current,
                              [row.source_interface]: {
                                targetInterface: event.target.value,
                                confirmed: false,
                              },
                            }))
                          }
                        >
                          <option value="">Select target port</option>
                          {visibleCandidates(row, showUnavailable).map((option) => {
                            const isCurrent = option.target_interface === row.mapping.target_interface;
                            return (
                              <option
                                key={option.target_interface}
                                value={option.target_interface}
                                disabled={
                                  (!compatibleStatuses.has(option.status) || option.already_assigned) &&
                                  !isCurrent
                                }
                              >
                                {option.target_interface} · {option.status}
                                {option.already_assigned && !isCurrent ? " · already assigned" : ""}
                              </option>
                            );
                          })}
                        </select>
                        {candidate && (
                          <p className="mapping-candidate-note">
                            {candidate.already_assigned && !currentAssignment
                              ? "This target port is already assigned."
                              : candidate.reasons.join(" ")}
                          </p>
                        )}
                        <div className="mapping-row-actions">
                          <button
                            className="mapping-confirm"
                            disabled={!confirmable || loading}
                            onClick={() => onSave(mappingsWith(row.source_interface, draft.targetInterface, true))}
                          >
                            <Icon name="check" /> Confirm
                          </button>
                          <button
                            disabled={loading || (!draft.targetInterface && !draft.confirmed)}
                            onClick={() => onSave(mappingsWith(row.source_interface, "", false))}
                          >
                            Clear
                          </button>
                        </div>
                      </div>

                      <div className="mapping-status-cell">
                        <span className={`mapping-status ${mappingStatusClass(status)}`}>{status}</span>
                        {changed && <small>Pending confirmation</small>}
                      </div>

                      <details className="mapping-row-details">
                        <summary>Reasons and evidence</summary>
                        {(changed ? candidate?.reasons || [] : row.mapping.compatibility_reasons).map((reason) => (
                          <p key={reason}>{reason}</p>
                        ))}
                        {[...(row.source_capability?.evidence_refs || []), ...(candidate?.evidence_refs || row.mapping.target_evidence_refs)].map((reference) => (
                          <code key={reference}>{reference}</code>
                        ))}
                      </details>
                    </article>
                  );
                })}
              </div>

              {contract.blocking_reasons.length > 0 && (
                <section className="mapping-blockers" aria-labelledby="mapping-blockers-title">
                  <h3 id="mapping-blockers-title">Conversion blockers</h3>
                  <ul>{contract.blocking_reasons.map((reason) => <li key={reason}>{reason}</li>)}</ul>
                </section>
              )}
              <p className="mapping-disclaimer">
                Port capability validation does not verify installed optics, cabling, or live link state.
              </p>
            </>
          )}
        </div>

        <footer>
          <div>
            <button
              className={resetArmed ? "mapping-reset-armed" : ""}
              disabled={!contract || loading}
              onClick={async () => {
                if (!resetArmed) {
                  setResetArmed(true);
                  return;
                }
                await onReset();
                setResetArmed(false);
              }}
            >
              {resetArmed ? "Confirm Reset All" : "Reset All"}
            </button>
            {resetArmed && <button onClick={() => setResetArmed(false)}>Cancel reset</button>}
          </div>
          <div>
            <button disabled={!contract || loading || pending} onClick={onValidate}>
              Validate Mapping
            </button>
            <button className="primary" onClick={onClose}>Done</button>
          </div>
        </footer>
      </section>
    </div>
  );
}