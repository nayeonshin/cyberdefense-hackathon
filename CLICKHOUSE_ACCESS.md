# ClickHouse access for the team

The shared ClickHouse Cloud service of this project. Reachable from anywhere, so the Akash
deployment and every laptop can use it. Put these lines into `.env` or the deployment settings:

```
CLICKHOUSE_HOST=el8hqe4ato.us-east-2.aws.clickhouse.cloud
CLICKHOUSE_PORT=8443
CLICKHOUSE_SECURE=1
CLICKHOUSE_USER=team_dashboard
CLICKHOUSE_PASSWORD=3Uoo44YpMs3ILD6ugoRp-Kd7
CLICKHOUSE_DATABASE=default
DATA_SOURCE=clickhouse
EVENTS_TABLE=incoming_threats
```

This login is made for the team: it can read, insert, create tables, update rows and change
columns in the `default` database. It cannot drop or truncate tables, so nobody who finds this
file can wipe the data before the demo. It will be removed after the event.

## What is in there

| Table | Rows | Written by |
|---|---|---|
| `incoming_threats` | pending and handled threat rows | Member 1, ingestion |
| `events` | one current version per event: VERIFIED, PUBLISHED_TAKEDOWN, TAKEN_DOWN | Member 2's scanner and the Actor |
| `actions` | one receipt per action with proof link and evidence hash | the Actor |
| `threat_history` | 822,439 real threat URLs | the Actor's history lookup |
| `threat_history_scale` | 1,000,085,824 rows, scale test with synthetic hosts | scale test |

Current state of an event: `SELECT * FROM events FINAL WHERE event_id = '...'`.
Receipts of an event: `SELECT * FROM actions WHERE event_id = '...' ORDER BY created_at`.
