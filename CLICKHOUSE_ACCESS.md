# Shared ClickHouse access

Get the current credentials from the team through a private channel. Store them in the ignored `clickhouse.env` or `.env` file, or set environment variables; never commit the password.

The integration dashboard reads these settings:

```dotenv
CLICKHOUSE_HOST=<team ClickHouse host>
CLICKHOUSE_PORT=8443
CLICKHOUSE_SECURE=1
CLICKHOUSE_USER=<read-only dashboard user>
CLICKHOUSE_PASSWORD=<set locally>
CLICKHOUSE_DATABASE=default
DATA_SOURCE=backend
RUN_MODE=preview
THREATS_TABLE=akash_threats
VERDICTS_TABLE=akash_events
ACTIONS_TABLE=akash_actions
```

Use the actual table names for the backend instance; the defaults are `incoming_threats`, `events`, and `actions`. The dashboard needs SELECT access only. Start it with `streamlit run dashboard.py` after loading the environment. Backend workers are managed separately.

The password previously committed in PR #3 must be rotated: removing it from the current tree does not remove it from upstream Git history.
