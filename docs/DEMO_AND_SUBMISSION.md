# Three-minute recording and submission

**Do not record the final sponsor demo from the simulated dashboard.** Supplied-verdict unit tests are
not sponsor execution evidence. The real controlled pipeline and its Linux CI verification execute
Semgrep; the latest CI run also writes and queries a real ClickHouse container.

## Current evidence (October 9)

- Live: <https://j37o2jgnu9bq57cesbda28htdc.ingress.akash-palmito.org/>
- Akash DSEQ `1791574764504`, provider Akash Palmito, sponsor credits only, 24-hour runtime limit.
- Actual cloud Semgrep-to-Actor run: **12.238 seconds**, one mock-registrar submission, HTTP 410.
- [42 tests and real ClickHouse container run](https://github.com/nayeonshin/cyberdefense-hackathon/actions/runs/37982475135):
  **12.947 seconds**, persisted ledger, new worker and fresh check after restart, one submitted receipt.
- The cloud dashboard currently uses file storage. Member 1's localhost database is not reachable from Akash.
- Guild AI sponsor execution is not yet independently verified. No final recording or submission exists yet.
- Team identity and submitter fields remain intentionally unfilled until the team supplies them.

## Recording script (180 seconds)

| Time | Show | Say |
|---|---|---|
| 0:00–0:20 | Dashboard overview | “Detection is only the start. Our orchestrator follows a signal through inspection, action, and a verifiable receipt.” |
| 0:20–0:45 | Verified Akash deployment and architecture | “The worker runs independently of this browser on Akash. ClickHouse connects the stages. Semgrep supplies code evidence; Guild AI supplies the evaluation evidence shown here.” Only say the final clause if verified. |
| 0:45–1:15 | Automatic ingestion of the owned target | “This harmless, team-owned page is our controlled target. No outside website is being taken down in this demonstration.” |
| 1:15–1:45 | Actual Member 2 scan output | “This is the actual Semgrep rule, matched code, and confidence returned for this event.” |
| 1:45–2:15 | Mock receipt and fresh HTTP 410 check | “The agent submitted an evidence-hashed report to our private mock registrar. Two rechecks observed suspension. No person moved it between stages.” |
| 2:15–2:40 | Receipt view, timestamps, state across refresh | “Each action has a durable receipt. A browser refresh cannot dispatch again. A submitted report and a confirmed unavailable target remain separate states.” |
| 2:40–3:00 | Sponsor proof and outcome | State only measured timing. Show each verified integration. End with “From signal to evidence to action, with a trace you can inspect.” |

Before recording: create a fresh RUN_ID; confirm worker and real team commands; begin capture before automatic
ingestion; wait for the end-to-end result without changing data or clicking action controls. Keep the simulated
preview out of the final cut. If cloud or team integration is pending, make a clearly labeled rehearsal instead
and do not submit it as a completed autonomous sponsor demo.

## Verified form requirements (October 9)

Submission page: <https://tokensand.com/cyberhack/submit>. One person submits for the whole team; maximum 4.
Required: project name, one-sentence description (300 characters), project description (1,500 characters),
team size and other members, tools used, shareable demo video URL, GitHub repository URL.
Working URL and public screenshot are optional. Supported video links include YouTube, Loom, and Google Drive.
The form states **4:30 PM PT** and recommends around three minutes.

## Copy draft — update to reflect only completed integrations

**Name:** Takedown Orchestrator

**One sentence:** An autonomous defense pipeline that turns threat signals into scan evidence, controlled response actions, and inspectable receipts.

**Description draft:**

Takedown Orchestrator connects threat ingestion, payload inspection, action dispatch, and verification in one
observable workflow. ClickHouse stores events and receipts; Member 2’s Semgrep integration supplies matched
code evidence. A separate worker invokes Member 3’s dispatcher and rechecks the target without browser-driven
action controls. Streamlit presents ingestion timing, scan results, and per-event action receipts. The container
runs on Akash with persistent dispatch history. The cloud run completed in 12.238 seconds; a separate actual
ClickHouse container run completed in 12.947 seconds and preserved one submission across restart. The cloud
currently uses file storage while a reachable external ClickHouse endpoint is pending. Our demo uses a harmless
team-owned target and a private mock registrar; it does not claim that an external provider performed a real-world
takedown. Guild AI usage is not claimed without Member 2's execution evidence.

**Repository:** <https://github.com/nayeonshin/cyberdefense-hackathon/tree/member4-shipper>

## Final checklist

- [x] Real Member 1 / Member 2 integrations; Semgrep, ClickHouse and Akash have working evidence across cloud and CI environments.
- [x] Akash DSEQ, provider, public URL, image digest, and screenshot saved.
- [ ] Reachable external ClickHouse configured for the final cloud recording.
- [ ] Three-minute recording uploaded and accessible to judges without an unexpected sign-in.
- [ ] Team member names/emails confirmed by team; exactly one submitter.
- [ ] Each applicable sponsor prize selected separately according to the actual rules; confirm with Andy if unclear.
- [ ] Submitted by 4:00 PM PDT target; 4:30 PM deadline.
- [ ] Confirmation captured; repository/video access verified.

This file is a preparation package, not a submission confirmation.
