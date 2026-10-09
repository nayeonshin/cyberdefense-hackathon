"""What the threat history in ClickHouse tells the Actor, block by block.

    python -m actor.insights

Read only. Every block names the time its query took on the server and the rows it read.
threat_history_scale is a scale test: the real rows plus synthetic sibling hosts.
"""
import os
import re
import sys
import textwrap
import time
from types import SimpleNamespace

from . import config, history, policy as policy_module
from .ledger import clickhouse_client

WIDTH = 96
BAR = 44
SOURCES = "arrayStringConcat(arraySort(groupUniqArray(source)), ', ')"
TABLES = {"threat_history": "real threat URLs from three public feeds",
          "threat_history_scale": "a scale test, the real rows plus synthetic sibling hosts"}
OUTCOMES = {"act": "the host itself is the offender: public feed and reports",
            "act, URL only": "shared platform: the URL is reported, nothing else",
            "withheld": "the rules of engagement said no",
            "refused": "not a usable http(s) URL",
            "crash": "the Actor fell over"}
BUCKETS = {1: "1", 2: "2", 3: "3 to 9", 10: "10 to 99", 100: "100 or more"}
_server_ms = []     # one entry per query, for the closing line


def ask(client, sql: str, parameters: dict = None):
    result = client.query(sql, parameters=parameters)
    _server_ms.append(int(result.summary.get("elapsed_ns", 0)) / 1e6)
    return result


def title(text: str, result=None) -> None:
    cost = ""
    if result is not None:
        cost = (f"{int(result.summary.get('elapsed_ns', 0)) / 1e6:.1f} ms on the server, "
                f"{int(result.summary.get('read_rows', 0)):,} rows read")
    print()
    if len(text) + len(cost) + 2 > WIDTH:
        print(text)
        text = ""
    print(f"{text:<{WIDTH - len(cost)}}{cost}".rstrip())
    print("-" * WIDTH)


def share(part: int, whole: int) -> str:
    percent = 100 * part / whole if whole else 0
    return "<0.1 %" if 0 < percent < 0.05 else f"{percent:.1f} %"


def defang(host: str) -> str:
    return host.replace(".", "[.]")


def platform_pattern(policy: dict) -> str:
    """The allowlist rule as one expression: the host is an entry or ends with "." + entry."""
    return r"(?:^|\.)(" + "|".join(re.escape(d) for d in policy["allowlist"]) + ")$"


def scale(client) -> dict:
    result = ask(client,
                 "SELECT table, sum(rows), formatReadableSize(sum(bytes_on_disk)), "
                 "formatReadableSize(sum(data_uncompressed_bytes)), "
                 "sum(data_uncompressed_bytes) / sum(bytes_on_disk), count() "
                 "FROM system.parts WHERE active AND database = currentDatabase() "
                 "AND table IN {tables:Array(String)} GROUP BY table ORDER BY table",
                 {"tables": list(TABLES)})
    title("1. Scale: what is stored", result)
    print(f"   {'table':<22}{'rows':>13}{'on disk':>12}{'uncompressed':>14}{'ratio':>8}{'parts':>7}")
    for table, rows, disk, raw, ratio, parts in result.result_rows:
        print(f"   {table:<22}{rows:>13,}{disk:>12}{raw:>14}{ratio:>7.1f}x{parts:>7}")
    for table, _, _, _, _, _ in result.result_rows:
        print(f"   {table}: {TABLES[table]}.")
    return {row[0]: row[1] for row in result.result_rows}


def offenders(client, policy: dict):
    return ask(client,
               f"SELECT host, count() AS n, {SOURCES} FROM threat_history GROUP BY host "
               "HAVING n >= {least:UInt32} AND NOT match(host, {platforms:String}) "
               "ORDER BY n DESC, host LIMIT 10",
               {"least": policy["history"]["corroborates_at"], "platforms": platform_pattern(policy)})


def lookup(client, table: str, host: str) -> tuple:
    """The Actor's own history query on one table: its answer, its text, the server's summary."""
    seen = []

    def query(sql, parameters=None):
        seen.append((sql, ask(client, sql, parameters)))
        return seen[-1][1]

    os.environ["HISTORY_TABLE"] = table
    found = history.host_history(SimpleNamespace(query=query), host)
    return found, seen[-1][0], seen[-1][1].summary


def deciding_lookup(client, sizes: dict, host: str, policy: dict) -> None:
    usual = history.history_table()
    answers = [(table,) + lookup(client, table, host) for table in sizes]
    os.environ["HISTORY_TABLE"] = usual
    least = policy["history"]["corroborates_at"]
    title("2. The lookup that decides an action")
    print("   Before the Actor mails a hosting provider it asks what is on record for the host.")
    print("   Its query, as sent, here for the host " + defang(host) + ":")
    print(textwrap.fill(answers[0][2], WIDTH - 6, initial_indent="      ", subsequent_indent="      "))
    print()
    print(f"   {'table':<22}{'rows in table':>15}{'URLs on record':>16}{'rows read':>11}"
          f"{'server':>10}{'round trip':>13}")
    for table, found, _, summary in answers:
        print(f"   {table:<22}{sizes[table]:>15,}{found['urls_on_record']:>16,}"
              f"{int(summary.get('read_rows', 0)):>11,}"
              f"{int(summary.get('elapsed_ns', 0)) / 1e6:>7.1f} ms{found['lookup_ms']:>10.1f} ms")
    records = {(found["urls_on_record"], found["sources"]) for _, found, _, _ in answers}
    found = answers[0][1]
    table, _, _, summary = answers[-1]
    print()
    print("   " + ("The same answer from each table." if len(records) == 1 else "The tables disagree.")
          + " The sort key (host, first_seen) leads straight to the host:")
    print(f"   {int(summary.get('read_rows', 0)):,} of the {sizes[table]:,} rows in {table} read, "
          f"{int(summary.get('elapsed_ns', 0)) / 1e6:.1f} ms on the server.")
    if found["urls_on_record"] >= least:
        print(f"   {found['urls_on_record']:,} URLs on record ({found['sources']}) is at or above "
              f"history.corroborates_at = {least}:")
        print("   the history counts as the independent second source the provider mail requires.")


def repeat_offenders(client, policy: dict) -> None:
    result = ask(client,
                 "SELECT multiIf(n = 1, 1, n = 2, 2, n < 10, 3, n < 100, 10, 100) AS bucket, "
                 "count(), sum(n), countIf(n >= {least:UInt32}), sumIf(n, n >= {least:UInt32}) "
                 "FROM (SELECT host, count() AS n FROM threat_history GROUP BY host) "
                 "GROUP BY bucket ORDER BY bucket", {"least": policy["history"]["corroborates_at"]})
    rows = result.result_rows
    hosts, urls = sum(r[1] for r in rows), sum(r[2] for r in rows)
    repeat_hosts, repeat_urls = sum(r[3] for r in rows), sum(r[4] for r in rows)
    least = policy["history"]["corroborates_at"]
    title("3. Repeat offenders: how concentrated the threat is", result)
    print(f"   {'URLs on record':<16}{'hosts':>10}{'of all hosts':>15}{'URLs':>11}{'of all URLs':>14}")
    for bucket, bucket_hosts, bucket_urls, _, _ in rows:
        print(f"   {BUCKETS[bucket]:<16}{bucket_hosts:>10,}{share(bucket_hosts, hosts):>15}"
              f"{bucket_urls:>11,}{share(bucket_urls, urls):>14}")
    print()
    print(f"   {hosts:,} hosts carry {urls:,} URLs. {repeat_hosts:,} hosts ({share(repeat_hosts, hosts)}) "
          f"have {least} or more URLs on record")
    print(f"   and they carry {share(repeat_urls, urls)} of all URLs.")
    print("   For the Actor: on those hosts the history alone is the second source.")


def top_offenders(result) -> None:
    title("4. Top 10 repeat offenders, shared platforms excluded", result)
    print(f"   {'':>2}  {'host (defanged)':<48}{'URLs':>7}   sources")
    for rank, (host, n, sources) in enumerate(result.result_rows, start=1):
        print(f"   {rank:>2}  {defang(host):<48}{n:>7,}   {sources}")


def platforms(client, policy: dict, urls: int) -> int:
    result = ask(client,
                 "SELECT extract(host, {platforms:String}) AS platform, count() AS n, uniqExact(host) "
                 "FROM threat_history GROUP BY platform HAVING platform != '' ORDER BY n DESC",
                 {"platforms": platform_pattern(policy)})
    rows = result.result_rows
    on_platforms = sum(r[1] for r in rows)
    title("5. Shared platforms the Actor must not block", result)
    print(f"   {on_platforms:,} URLs ({share(on_platforms, urls)} of all) sit on {len(rows)} of the "
          f"{len(policy['allowlist'])} allowlisted platforms. The top 5:")
    print(f"   {'platform':<26}{'URLs':>8}{'of all URLs':>14}{'hosts under it':>17}")
    for platform, n, hosts in rows[:5]:
        print(f"   {platform:<26}{n:>8,}{share(n, urls):>14}{hosts:>17,}")
    print("   The Actor reports these per URL and never blocks or mails the platform.")
    return on_platforms


def replayed(client, on_platforms: int) -> None:
    result = ask(client,
                 "SELECT run_id, outcome, count() FROM replay_decisions "
                 "WHERE run_id = (SELECT max(run_id) FROM replay_decisions) GROUP BY run_id, outcome")
    counts = {outcome: n for _, outcome, n in result.result_rows}
    total = sum(counts.values())
    title("6. What the Actor would do with every real URL", result)
    if not counts:
        print("   no replay on record: python -m actor.history replay")
        return
    print(f"   Replay run {result.result_rows[0][0]}: {total:,} URLs through the Actor's parser and rules.")
    print(f"   {'outcome':<16}{'URLs':>9}{'share':>9}   meaning")
    for outcome in list(OUTCOMES) + sorted(set(counts) - set(OUTCOMES)):
        n = counts.get(outcome, 0)
        print(f"   {outcome:<16}{n:>9,}{share(n, total):>9}   {OUTCOMES.get(outcome, '')}")
    if counts.get("act, URL only") == on_platforms:
        print(f"   {on_platforms:,} is also the platform count of block 5: SQL there, the Actor's rules here.")


def daily(client, policy: dict) -> None:
    result = ask(client,
                 "SELECT day, sum(n), argMax(host, n), max(n), max(last) FROM ("
                 "SELECT toDate(first_seen) AS day, host, count() AS n, max(first_seen) AS last "
                 "FROM threat_history WHERE source = 'urlhaus' GROUP BY day, host) "
                 "GROUP BY day ORDER BY day DESC LIMIT 30")
    days = result.result_rows[::-1]
    title("7. New malicious URLs per day, last 30 days", result)
    print("   URLhaus rows only: the one source that carries a real date.")
    if len(days) < 7:
        print(f"   skipped: the URLhaus rows cover only {len(days)} days")
        return
    # One huge day must not flatten every other bar, so bars stop at four times the median day.
    full = 4 * sorted(row[1] for row in days)[len(days) // 2]
    for day, n, _, _, last in days:
        bar = "#" * max(1, round(BAR * min(n, full) / full)) + (" >>" if n > full else "")
        note = f"  (until {last:%H:%M} UTC)" if day == days[-1][0] else ""
        print(f"   {day:%a %Y-%m-%d}{n:>8,}  {bar}{note}")
    print(f"   One # is about {full / BAR:,.0f} URLs. >> marks a bar cut off at {full:,}.")
    day, n, host, host_urls, _ = max(days, key=lambda row: row[1])
    print(f"   Busiest day {day:%Y-%m-%d}: {n:,} URLs, {host_urls:,} of them on one host, "
          + (host if policy_module.is_allowlisted(host, policy) else defang(host)) + ".")
    if policy_module.is_allowlisted(host, policy):
        print("   That host is a shared platform: every URL is reported, the platform is never blocked.")


def report(client) -> None:
    started = time.perf_counter()
    policy = policy_module.load()
    print(f"Threat history on ClickHouse {client.server_version}: what the Actor reads from it")
    sizes = scale(client)
    if not sizes.get("threat_history"):
        sys.exit("threat_history is empty: python -m actor.history load <files>")
    worst = offenders(client, policy)
    if worst.result_rows:
        deciding_lookup(client, sizes, worst.result_rows[0][0], policy)
    repeat_offenders(client, policy)
    top_offenders(worst)
    on_platforms = platforms(client, policy, sizes["threat_history"])
    replayed(client, on_platforms)
    daily(client, policy)
    print()
    print(f"{len(_server_ms)} queries, {sum(_server_ms):.0f} ms on the server in total, "
          f"{time.perf_counter() - started:.1f} s on the clock with the network round trips.")


def main() -> None:
    try:
        client = clickhouse_client()
        if client is None:
            sys.exit("ClickHouse is not configured: set CLICKHOUSE_HOST and CLICKHOUSE_PASSWORD in .env")
        report(client)
    except Exception as exc:
        # The message of a failed connection names the service, which does not belong on a projector.
        text = " ".join(str(exc).split()).replace(config.get("CLICKHOUSE_HOST"), "<host>")
        sys.exit(f"ClickHouse did not answer: {type(exc).__name__}: {text[:200]}")


if __name__ == "__main__":
    main()
