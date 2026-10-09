"""Run with: python -m unittest discover -s tests -v"""
import json
import os
import tempfile
import threading
import unittest
from pathlib import Path

from actor import evidence, policy as policy_module
from actor.actions import Context, feed, xarf_email
from actor.contract import Verdict
from actor.dispatch import dispatch
from actor.enrich import Enrichment
from actor.ledger import Ledger
from actor.mock_registrar_server import make_server
from actor.recheck import recheck_once

POLICY = policy_module.load()


def verdict(**overrides) -> Verdict:
    base = {"event_id": "evt-1", "target_url": "https://bad.example/login",
            "timestamp": "2026-10-09T18:00:00Z", "semgrep_detected": True,
            "confidence_score": 0.96, "evidence": "rule matched", "corroborated": True}
    return Verdict.from_dict({**base, **overrides})


def hosted(**overrides) -> Enrichment:
    base = {"domain": "bad.example", "ips": ["203.0.113.7"], "registrar": "Example Registrar",
            "registrar_abuse": ["abuse@registrar.example"], "host_network": "SMALLHOST-NET",
            "host_abuse": ["abuse@smallhost.example"]}
    return Enrichment(**{**base, **overrides})


class PolicyTests(unittest.TestCase):
    def test_full_ladder_for_confident_corroborated_verdict(self):
        decision = policy_module.decide(verdict(), hosted(), POLICY)
        self.assertEqual(decision.actions(),
                         ["feed", "urlscan", "netcraft", "abuseipdb", "notify_host"])
        self.assertEqual(decision.plans[-1].recipient, "abuse@smallhost.example")

    def test_medium_confidence_only_protects(self):
        decision = policy_module.decide(verdict(confidence_score=0.85), hosted(), POLICY)
        self.assertEqual(decision.actions(), ["feed"])

    def test_low_confidence_and_non_detection_do_nothing(self):
        self.assertEqual(policy_module.decide(
            verdict(confidence_score=0.62), hosted(), POLICY).actions(), [])
        self.assertEqual(policy_module.decide(
            verdict(semgrep_detected=False), hosted(), POLICY).actions(), [])

    def test_host_is_not_notified_without_second_source(self):
        decision = policy_module.decide(verdict(corroborated=False), hosted(), POLICY)
        self.assertNotIn("notify_host", decision.actions())

    def test_allowlisted_platform_gets_url_level_reports_only(self):
        decision = policy_module.decide(
            verdict(target_url="https://sites.google.com/view/fake"), hosted(), POLICY)
        self.assertEqual(decision.actions(), ["feed", "urlscan", "netcraft"])

    def test_shared_infrastructure_ip_is_never_reported(self):
        decision = policy_module.decide(
            verdict(), hosted(host_network="CLOUDFLARENET"), POLICY)
        self.assertNotIn("abuseipdb", decision.actions())

    def test_duplicates_are_suppressed(self):
        decision = policy_module.decide(
            verdict(), hosted(), POLICY, frozenset({"feed", "netcraft"}))
        self.assertEqual(decision.actions(), ["urlscan", "abuseipdb", "notify_host"])

    def test_controlled_target_only_reaches_the_mock_registrar(self):
        decision = policy_module.decide(
            verdict(target_url="http://localhost:8099/site"), hosted(), POLICY)
        self.assertEqual(decision.actions(), ["mock_registrar", "notify_host"])

    def test_escalation_needs_a_prior_host_notice(self):
        self.assertEqual(policy_module.escalation(
            verdict(), hosted(), POLICY).actions(), [])
        decision = policy_module.escalation(
            verdict(), hosted(), POLICY, frozenset({"notify_host"}))
        self.assertEqual(decision.plans[0].recipient, "abuse@registrar.example")


class EvidenceTests(unittest.TestCase):
    def test_defang(self):
        self.assertEqual(evidence.defang("https://bad.example/x"), "hxxps://bad[.]example/x")

    def test_digest_is_stable_and_sensitive(self):
        first = evidence.digest(evidence.build(verdict(), hosted()))
        again = evidence.digest(evidence.build(verdict(), hosted()))
        changed = evidence.digest(evidence.build(verdict(evidence="other"), hosted()))
        self.assertEqual(first, again)
        self.assertNotEqual(first, changed)
        self.assertEqual(len(first), 64)


class ChannelTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.env = dict(os.environ)
        self.addCleanup(lambda: (os.environ.clear(), os.environ.update(self.env)))
        os.environ["OUTBOX_DIR"] = str(self.dir / "outbox")
        os.environ["SMTP_PORT"] = "1"            # nothing listens: mail lands in the outbox
        os.environ["LIVE_EMAIL"] = "0"
        self.ledger = Ledger(self.dir / "ledger" / "actions.jsonl", use_clickhouse=False)

    def ctx(self, v=None, action="notify_host") -> Context:
        v, e = v or verdict(), hosted()
        bundle = evidence.build(v, e)
        return Context(v, e, bundle, evidence.digest(bundle), "abuse@smallhost.example",
                       POLICY, action)

    def test_abuse_mail_goes_to_the_sink_not_the_real_recipient(self):
        message = xarf_email.build(self.ctx(), xarf_email.SINK_ADDRESS)
        self.assertEqual(message["To"], xarf_email.SINK_ADDRESS)
        self.assertEqual(message["X-Intended-Recipient"], "abuse@smallhost.example")
        body = message.get_body(preferencelist=("plain",)).get_content()
        self.assertIn("hxxps://bad[.]example/login", body)
        self.assertNotIn("https://bad.example", body)
        attachment = next(message.iter_attachments())
        self.assertEqual(json.loads(attachment.get_content())["Report"]["Domain"], "bad.example")

        outcome = xarf_email.execute(self.ctx())
        self.assertEqual(outcome.status, "SINK")
        self.assertTrue((self.dir / "outbox" / "evt-1-host.eml").exists())

    def test_feed_publishes_and_resolves(self):
        repo = self.dir / "threat-feed"
        repo.mkdir()
        os.environ["FEED_REPO_DIR"] = str(repo)
        os.environ["FEED_PUBLIC_URL"] = "https://feed.example"
        outcome = feed.execute(self.ctx(action="feed"))
        self.assertEqual(outcome.status, "SENT")
        self.assertEqual(outcome.proof_url, "https://feed.example/incidents/evt-1.md")
        self.assertIn("bad.example\n", (repo / "blocklist.txt").read_text())
        self.assertIn("0.0.0.0 bad.example\n", (repo / "hosts.txt").read_text())
        self.assertNotIn("https://bad.example", (repo / "incidents" / "evt-1.md").read_text())

        platform = verdict(event_id="evt-2", target_url="https://sites.google.com/view/fake")
        feed.execute(self.ctx(platform, action="feed"))
        self.assertNotIn("google", (repo / "blocklist.txt").read_text())
        self.assertEqual(len(json.loads((repo / "feed.json").read_text())["indicators"]), 2)

        self.assertEqual(feed.resolve("evt-1").status, "SENT")
        self.assertNotIn("bad.example", (repo / "blocklist.txt").read_text())

    def test_dry_run_sends_nothing_and_simulated_verdicts_never_go_live(self):
        receipts = dispatch(verdict(), live=False, offline=True, ledger=self.ledger)
        self.assertTrue(all(r.status in ("PLANNED", "SKIPPED") for r in receipts))
        self.assertTrue(all(r.dry_run for r in receipts))

        receipts = dispatch(verdict(simulated=True), live=True, offline=True, ledger=self.ledger)
        self.assertTrue(all(r.status in ("PLANNED", "SKIPPED") for r in receipts))
        self.assertEqual(self.ledger.done_actions("bad.example"), frozenset())

    def test_kill_switch_stops_everything(self):
        os.environ["ACTOR_STOP"] = "1"
        receipts = dispatch(verdict(controlled=True), live=True, ledger=self.ledger)
        self.assertTrue(all(r.status == "SKIPPED" for r in receipts))

    def test_controlled_target_full_loop(self):
        server = make_server(0)
        port = server.server_address[1]
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        os.environ["MOCK_REGISTRAR_URL"] = f"http://localhost:{port}"
        target = verdict(event_id="evt-c", controlled=True,
                         target_url=f"http://localhost:{port}/site")

        receipts = dispatch(target, live=True, ledger=self.ledger)
        by_action = {r.action: r for r in receipts}
        self.assertEqual(by_action["mock_registrar"].status, "SENT")
        self.assertIn("/tickets/T-0001", by_action["mock_registrar"].proof_url)
        self.assertEqual(by_action["notify_host"].status, "SINK")
        self.assertTrue(server.suspended)

        again = dispatch(target, live=True, ledger=self.ledger)              # open incident: no duplicates
        self.assertTrue(all(r.status == "SKIPPED" for r in again))

        self.assertEqual(recheck_once(self.ledger, POLICY, live=True), [])   # first failed check
        confirmed = recheck_once(self.ledger, POLICY, live=True)             # second confirms
        self.assertEqual([r.status for r in confirmed], ["CONFIRMED_DOWN"])
        self.assertEqual(recheck_once(self.ledger, POLICY, live=True), [])   # nothing left

        back = dispatch(target, live=True, ledger=self.ledger)               # a returning site is a new case
        self.assertEqual({r.action: r.status for r in back}["mock_registrar"], "SENT")


if __name__ == "__main__":
    unittest.main()
