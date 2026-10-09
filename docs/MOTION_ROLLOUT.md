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
were observed. Focused presentation/regression tests: 36 passed. The full local and Linux CI suites
both passed all **78 tests**. [CI run 38000700100](https://github.com/nayeonshin/cyberdefense-hackathon/actions/runs/38000700100)
built and published the Linux/AMD64 image, executed an actual ClickHouse/Semgrep/Actor run in **12.279
seconds**, and passed persistent-volume restart, database outage/recovery, and forced worker-failure
checks. The local Docker engine was unavailable, so container validation ran in Linux CI.

The rollout updates the existing deployment 1791578237742, retaining run `akash-controlled-001` and
its persistent volume. Immediate rollback image:
`ghcr.io/nayeonshin/cyberdefense-hackathon:94e119886ab8f82e24148ea19bb4d69421f0de57`.
Published image: `ghcr.io/nayeonshin/cyberdefense-hackathon:495ea49ea4f1a1a3ed5aa31fdeba78dffb38e434`.
Digest: `sha256:f0780a7535a0789a717ccbafd618088576efb88bcf9ddbbb23e4110f8ed54533`.
The registry manifest was readable anonymously. The image is running on the existing
[public dashboard](https://rlts1sj4jhcur9q89cjbfn8omk.ingress.h6i-dedicated.eu-se-1.digitalfrontier.so/).
The brief single-container replacement returned HTTP 503 before reconnecting normally. Desktop and
mobile reconnects loaded the animation, escaped Semgrep evidence, receipt details and live updates.
The component instance remained stable across refreshes and saved-evidence playback returned to the
recorded confirmation without dispatching. The ledger still contains **3 receipts / 1 SENT** and its
SHA-256 remains `3040f630e6fbc91d530967214e40514659e63b8b41817353b0e553c5526fb6ce`.
Worker restart: `2026-10-09T22:46:45.707219Z`; fresh HTTP 410 check: `2026-10-09T22:47:22.380248Z`.
The original controlled run duration remains **15.054 seconds**. The existing sponsor-funded lease,
run ID, resources, and persistent volume were retained. No new paid resources were created.

Cloud data still uses files; the ClickHouse execution cited above is a separate CI environment.
Guild AI evidence, final recording, team details, prize selections and final submission remain pending.
