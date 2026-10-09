# Deployment runbook

## Build and publish

The `container.yml` workflow tests on Linux, builds `linux/amd64`, smoke-tests Streamlit, checks the `/data`
volume across restart, runs actual controlled Semgrep-to-Actor verification, and pushes
`ghcr.io/nayeonshin/cyberdefense-hackathon:<full-commit-sha>`. It saves a controlled-pipeline-evidence artifact.
Set the GHCR package to **public** after the first successful push. Verify an unauthenticated image pull
before deploying; a public GitHub repository does not automatically make its first GHCR package public.

Local equivalent:

```powershell
docker build --platform linux/amd64 -t cyberdefense:test .
docker compose up --build
```

Do not deploy until the workflow or local image smoke test has passed. The base Python version and direct
dependencies are pinned. Team Python dependencies are included in `requirements-team.txt`.

## Akash Console

1. Sign in at <https://console.akash.network>. Redeem the sponsor code under Billing. Use **sponsor credits only**.
2. Confirm credit availability. Do not enable card auto-reload or add paid funding.
3. Render the private SDL with the published image tag:

   `python -m shipper.render_deploy --image ghcr.io/nayeonshin/cyberdefense-hackathon:<full-commit-sha>`

4. In New deployment, use the custom SDL editor and the contents of `deploy.private.yaml`.
5. Review the provider quote and credit balance. Use one replica and preserve the named persistent volume.
   The SDL bid is an upper bidding bound, not a promised price. Console's actual quote is authoritative.
6. The default SDL starts a labeled preview. For the real owned-target run, use the integrated image,
   DATA_SOURCE=files, RUN_MODE=controlled, a new RUN_ID, and
   `TEAM_PIPELINE_COMMAND_JSON=["python","-m","shipper.team_pipeline"]`.
   File mode demonstrates actual Semgrep and Actor execution but not ClickHouse.
7. Save DSEQ, provider, public URL, image digest, and deployment screenshot. Put nonsecret metadata in
   `DATA_DIR/deployment.json` using keys `dseq`, `provider`, `url`, `image_digest`, `verified_at`.
8. Verify public `/_stcore/health`, two live refresh cycles, browser reconnect, worker heartbeat, and a real
   controlled pipeline run. Docker HEALTHCHECK is not a claim that Akash performs application readiness checks.

Resources: 2 vCPU, 4 GiB RAM, 5 GiB root disk, 1 GiB persistent `/data`, one replica. ClickHouse remains
external. Only port 8501 is exposed as HTTP 80; the mock registrar stays on loopback. No public reset route.

Plain SDL environment variables are visible to the provider and anyone reading the manifest. Never commit
the private manifest, `.env`, tokens, or the sponsor code. Use the minimum credential privileges for the demo.
The dashboard is public and read-only: do not ingest sensitive private evidence into this deployment.

## Controlled mode

For a reachable external database, set `DATA_SOURCE=clickhouse`, `EVENTS_TABLE=shipper_events`,
`RUN_MODE=controlled`, a unique `RUN_ID`, ClickHouse variables and the combined team command above
(or the separately provided ingestion/scanning commands, never both). The supervisor launches the team
pipeline, worker and UI independently; all integrations must
retry startup dependencies. External action flags are forced off. The private registrar's state survives restarts.

To stop dispatch, create the Actor's `STOP` file or set `ACTOR_STOP=1` and restart. Stopping the supervisor
stops its child processes. A new demo uses a new run ID; do not delete another run's state.

After judging, close this deployment in Console to stop credit consumption. Leave unrelated deployments alone.

## References

- <https://akash.network/docs/developers/deployment/akash-sdl/syntax-reference/>
- <https://akash.network/docs/learn/core-concepts/environment-secrets/>
- <https://docs.streamlit.io/deploy/tutorials/docker>
