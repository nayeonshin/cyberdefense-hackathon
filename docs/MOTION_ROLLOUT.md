# Defense in motion

The read-only overview adds a rotating particle field, moving orbital signals, scan visualization,
and receipt reveal to the existing Streamlit dashboard. The investigation table, adapter interfaces,
workers, exact event contract, and proof validation are unchanged.

## Evidence and motion

- Ambient animation is explicitly labeled; it is not a geographic threat map or activity counter.
- Four recorded stages come from ingestion/scan metadata and matching, non-dry-run Actor receipts.
- Replay saved evidence is a browser-only, 15-second presentation of a complete ordered Semgrep run.
  It cannot dispatch, rescan, suspend, write records, or change timestamps. The displayed duration is
  the actual recorded duration, not the animation duration.
- Fixtures never enable replay or become execution evidence. Negative, failed, skipped, test-message,
  submitted, historical, and confirmed states remain distinct.
- Pause persists across refreshes. Reduced-motion preferences disable animation and replay.
- Unhealthy runtime data stops motion. A browser watchdog stops it after eight seconds without a
  successful component delivery and labels the remaining information as saved evidence.
- All event-derived text uses textContent. No target or receipt URL is inserted as an HTML link by
  the component. The existing validated receipt links remain in the investigation panel.

## Validation

Local browser checks cover desktop and 390px layouts, persistent pause and component identity across
two-second updates, negative/pending deep links, keyboard table selection, and server disconnect.
The disconnect correctly shows “Live updates unavailable” and “Motion stopped.” No frontend errors
were observed. Focused presentation/regression tests: 36 passed.

The rollout updates the existing deployment 1791578237742, retaining run `akash-controlled-001` and
its persistent volume. Immediate rollback image:
`ghcr.io/nayeonshin/cyberdefense-hackathon:94e119886ab8f82e24148ea19bb4d69421f0de57`.
Final CI, deployed image, and receipt-preservation results are recorded after verification.
