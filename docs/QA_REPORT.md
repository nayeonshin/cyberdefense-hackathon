# Member 4 QA — October 9, 2026

## Verdict

The controlled Member 4 application is working and the QA fixes are deployed. **All 67 tests pass in Linux CI**, including actual Semgrep execution. The full local run passed 66 tests; the final connection-retry regression then passed separately. QA found and fixed defects rather than merely rerunning the previous checks. The final submission is still incomplete: external ClickHouse connectivity, Guild AI evidence if claimed, the video, team identity, prize selection and submission confirmation remain pending.

The active deployment is [Digital Frontier / 1791578237742](https://console.akash.network/deployments/1791578237742). Its [public dashboard](https://rlts1sj4jhcur9q89cjbfn8omk.ingress.h6i-dedicated.eu-se-1.digitalfrontier.so/) uses files, not ClickHouse. Existing sponsor credits fund a 24-hour deployment, ending approximately October 10 at 1:39 PM PDT. No new paid resources were created for QA.

## Fixed findings

| Finding | Resolution and evidence |
|---|---|
| Private proof URLs could pass validation using alternate hostname spellings, such as `localhost.` | Normalize IDNA/DNS root dots, reject escaped hostnames and ambiguous numeric DNS forms. Eight URL regression cases pass. No URL is fetched by validation. |
| Malformed status JSON, invalid timestamps or incorrect object types could crash the dashboard | Status files now fail visibly and retain the event display. Corrupt heartbeat, supervisor, pipeline and target-check tests pass. Future heartbeat timestamps are stale. |
| Private SDL renderer omitted `TEAM_PIPELINE_COMMAND_JSON` | Preserve the combined team command and continue forcing external reporting flags off. Renderer regression passes. |
| Future ingestion timestamps inflated current throughput | Bound the one-minute window at the current time in both file and ClickHouse adapters; clock-skew regression added. |
| An interruption after saving a submitted receipt but before saving Actor recheck state left verification unscheduled | Coordinator reconstructs missing recheck state from the same event's saved receipt without another report. Fault-injection test confirms one ticket, one SENT and one confirmation. Original Actor files remain unchanged. |
| Worker error heartbeat lacked its process start identifier | Degraded heartbeat retains process identity, allowing the dashboard to identify the current failing worker. |
| Acceptance probe could use unrelated/stale evidence or exit during database restart | Scope receipts to event and target, bound freshness, require a running worker, and retry temporary dependency failures within the requested timeout. Integrity failures still fail immediately. |
| `clickhouse.env` was Git-ignored but could enter the Docker build context | Excluded it and local Actor stop/state files from the context. No such credential file was present during QA. |
| Submission notes linked to the closed Palmito lease and stale timings | Updated current provider, URL, measured cloud/CI timings and the distinction between cloud file storage and ClickHouse CI. |

## Validation matrix

| Area | Result |
|---|---|
| Exact eight-field JSON contract, types and metadata separation | Pass; invalid contracts fail rather than being converted to simulated records. |
| Fixtures, files and ClickHouse adapter interfaces | Pass; no silent fixture fallback; fixtures persistently labeled and non-dispatching. |
| Actor tests, private registrar, serial dispatch/recheck and bounded retries | Pass; original Actor tests included in full suite. External reporting remains disabled. |
| Real controlled pipeline | Pass locally and in prior Linux/container/cloud runs. The cloud run recorded 15.054 seconds; prior full ClickHouse CI recorded 12.649 seconds. |
| Fresh database bootstrap, receipt projection, restart and duplicate suppression | Pass in the final Linux container. Actual ClickHouse/Semgrep/Actor run: **14.298 seconds**. Restart and real database outage recovery retained one submission. |
| Interrupted recheck-state write | Pass; resumes verification without resubmission. |
| Backup restore | Pass using the actual downloaded cloud backup in an isolated directory. Historical check was stale before restart; fresh check returned 410; receipt SHA-256 unchanged and one ticket retained. |
| Queue selection, arrival/reordering, disappearance, deep link and rerun | Pass in regression tests. Browser arrow keys followed by Shift+Space selected the negative event and updated `?event=`. |
| Pending, negative, detected, scan failure, dispatch failure, submitted, saved test message, historical confirmation | Pass; separate labels and evidence-based timeline; no “Safe” label or fabricated advancement. |
| Evidence escaping, proof links and read-only browser behavior | Pass; evidence is code/text; unsafe links use saved dashboard receipt details; no dispatch call on reruns. |
| Dependency failure, cached data, empty state, worker failure and corrupt runtime files | Pass in application tests. Errors remain visible; prior successful event data is retained. A hard worker exit intentionally fails the container; it is not silently restarted inside the dashboard. |
| Desktop and 390px viewport | Pass visual/manual review; queue and detail stack at 390px with no page overflow (document width 390px). |
| Typography and contrast | Browser computed styles confirm Inter family, weight 400, 40px title, 24px section titles and 12px captions at full opacity. Caption contrast 4.69:1; red 6.52:1; amber 5.85:1; metric labels 11.72:1; primary-link text 16.02:1. Reduced-motion CSS present. Not a formal accessibility certification. |
| Frontend loading and live reconnect | Updated public page refreshes with a fresh worker heartbeat, one submission and three receipts. Brief 503/disconnect errors occurred while its single container was replaced; no errors were captured after the completed reconnect at 21:55:50 UTC, and no dynamic-module loading error occurred. |
| Dependencies | `pip check` passes. pip-audit 2.10.1 found **0 known vulnerabilities in 95 installed packages** on this machine. This does not constitute an OS-image or future vulnerability guarantee. |
| Credentials/configuration | 75 tracked files and 135 historical file versions checked for high-confidence credential patterns, no hits. Private configs are ignored. YAML/TOML parse successfully; no credential values included in evidence. |
| Git | Changes pushed to `member4-shipper`; `main` remains the empty initial commit and default branch. Public repository and draft PR branch/base verified. Integrated team files match their recorded source commits. |

## Test environment notes

The initial native Windows run passed 47 tests and failed the actual Semgrep test with a Windows `VirtualProtect` allocation error. Docker Desktop also could not finish starting while available virtual memory was nearly exhausted. The QA-started Docker startup was stopped. With `OPENBLAS_NUM_THREADS=1`, the final complete local run passed **66 tests in 98.11 seconds**, including the actual scan; the subsequently added connection-retry regression passed separately. One intermediate overlapping test invocation contended for the private registrar port; final full suites ran sequentially. No test was skipped to obtain a pass. Final Linux CI passed **67 tests in 6.84 seconds**.

Local Docker execution remains unavailable on this laptop during this audit. Linux CI is the container validation environment. Retain the previous tested image until the new image passes all checks and public reconnect verification.

## Remaining boundaries and delivery work

- Member 1's localhost ClickHouse is not reachable from Akash. Cloud uses persistent files; ClickHouse usage is verified in a separate real CI container. Do not claim a fully connected cloud ClickHouse pipeline.
- Guild AI execution traces are still pending. Do not count a planned integration as sponsor usage.
- Final video, team names/emails, submitter, sponsor-prize selections and submission confirmation are still absent. The script/package is preparation, not proof of submission.
- Tests cover the controlled harmless target. Public threat-feed authenticity, real abuse-provider APIs, external takedowns, scanner false-positive rates and Guild evaluation quality have not been validated by Member 4. External channels are disabled.
- The integrated scanner is not yet approved here for unrestricted hostile-web crawling. DNS rebinding resistance, redirect/script origin policies and incomplete Semgrep-result handling warrant review by Member 2 before expanding beyond the owned target.
- Graceful restart, a saved-receipt/state-write interruption and application backup restore are covered. This is not a guarantee against arbitrary disk corruption, provider-volume loss or multi-replica writers. Keep one replica and retain backups.
- The Python base image is now pinned by verified digest; direct dependencies are version-pinned, but transitive dependencies are not a hash-locked environment. No OS-package CVE scan was completed in this audit.
- Proof-link checks validate syntax and known private/local host forms without DNS lookup; they cannot prove that an otherwise valid public hostname will always resolve publicly.

## QA revision rollout

- [Successful final workflow](https://github.com/nayeonshin/cyberdefense-hackathon/actions/runs/37995734232): 67 tests, Linux/AMD64 build, actual ClickHouse/Semgrep/Actor run, persistent-volume restart, database outage/recovery, forced worker exit and image publication.
- Image: `ghcr.io/nayeonshin/cyberdefense-hackathon:94e119886ab8f82e24148ea19bb4d69421f0de57`.
- Digest: `sha256:1094b817920ab96217384a5d19361f8976addb4cccbdee66977c7485b7c99d57`. Anonymous registry/config access confirms Linux/AMD64.
- Updated existing DSEQ `1791578237742` without creating another deployment. Retained `RUN_ID=akash-controlled-001` and the existing persistent volume.
- Cloud worker restarted at **21:53:26.064782 UTC**. Acceptance check at **21:55:52.619445 UTC** confirmed HTTP 410, one submitted report, and the original 15.054-second run evidence.
- All three receipts are byte-for-byte unchanged; SHA-256 `3040f630e6fbc91d530967214e40514659e63b8b41817353b0e553c5526fb6ce` matches the pre-update backup. The deployed code's private-hostname validation fix was also directly checked.
- Rollback retained: image `e940bebe6ddb283c697ef19da69525900f626830`, digest `sha256:91714aed78a3d7a056a255ad102faea5715274425dd4ba408a77a6ad4a074c35`.
- Local package includes the final CI receipts/findings, outage heartbeat, forced-exit status, cloud verification, backup-restore result, dependency audit, image metadata and fresh screenshots. It remains a draft package without a video or submission confirmation.

Initial QA CI attempts passed Python tests but hit repeated Docker Hub authorization timeouts/504 responses while fetching the base image or BuildKit. CI now uses Docker's built-in builder and Google's [documented public Docker Hub cache](https://docs.cloud.google.com/artifact-registry/docs/pull-cached-dockerhub-images). The Python base digest was checked against both the official registry and cache; the ClickHouse digest is unchanged. Only the ephemeral CI daemon configuration changes.
