"""Decide which rungs of the ladder fire for a verdict. Pure logic, no I/O."""
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .contract import Verdict
from .enrich import Enrichment

POLICY_PATH = Path(__file__).with_name("policy.yaml")


@dataclass
class Plan:
    action: str
    rung: int
    recipient: str


@dataclass
class Decision:
    plans: list = field(default_factory=list)
    skipped: list = field(default_factory=list)   # (action, reason)

    def actions(self) -> list:
        return [p.action for p in self.plans]


def load(path: Path = POLICY_PATH) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def is_allowlisted(host: str, policy: dict) -> bool:
    return any(host == d or host.endswith("." + d) for d in policy["allowlist"])


def is_controlled(verdict: Verdict, policy: dict) -> bool:
    return verdict.controlled or verdict.host in policy["controlled_hosts"]


def is_shared_infra(enrichment: Enrichment, policy: dict) -> bool:
    network = enrichment.host_network.upper()
    return any(word in network for word in policy["shared_infra_networks"])


def decide(verdict: Verdict, enrichment: Enrichment, policy: dict,
           already_done: frozenset = frozenset()) -> Decision:
    decision = Decision()
    limits = policy["thresholds"]
    confidence = verdict.confidence_score

    def add(action, rung, recipient):
        if action in already_done:
            decision.skipped.append((action, "already done for this domain"))
        else:
            decision.plans.append(Plan(action, rung, recipient))

    if not verdict.semgrep_detected:
        decision.skipped.append(("all", "verdict is not a detection"))
        return decision
    if not verdict.host:
        decision.skipped.append(("all", "no host in target_url"))
        return decision

    if is_controlled(verdict, policy):
        add("mock_registrar", 2, "mock-registrar")
        add("notify_host", 2, "abuse@mock-registrar.test")
        return decision

    allowlisted = is_allowlisted(verdict.host, policy)

    if confidence < limits["protect"]:
        decision.skipped.append(("all", f"confidence {confidence:.2f} below {limits['protect']}"))
        return decision
    add("feed", 0, "public-feed")

    if confidence < limits["report"]:
        decision.skipped.append(("report", f"confidence {confidence:.2f} below {limits['report']}"))
        return decision
    add("urlscan", 1, "urlscan.io")
    add("netcraft", 1, "netcraft")
    if allowlisted:
        decision.skipped.append(("abuseipdb", "allowlisted platform, URL-level reports only"))
    elif not enrichment.ips:
        decision.skipped.append(("abuseipdb", "host does not resolve"))
    elif is_shared_infra(enrichment, policy):
        decision.skipped.append(("abuseipdb", f"shared infrastructure ({enrichment.host_network})"))
    else:
        add("abuseipdb", 1, enrichment.ips[0])

    if allowlisted:
        decision.skipped.append(("notify_host", "allowlisted platform, URL-level reports only"))
    elif confidence < limits["notify_host"]:
        decision.skipped.append(("notify_host", f"confidence {confidence:.2f} below {limits['notify_host']}"))
    elif not verdict.corroborated:
        decision.skipped.append(("notify_host", "no second source confirms the threat"))
    elif not enrichment.host_abuse:
        decision.skipped.append(("notify_host", "no abuse contact found for the host"))
    else:
        add("notify_host", 2, enrichment.host_abuse[0])
    return decision


def escalation(verdict: Verdict, enrichment: Enrichment, policy: dict,
               already_done: frozenset = frozenset()) -> Decision:
    """Rung 3: the target is still up after the window, so the registrar is told."""
    decision = Decision()
    if is_controlled(verdict, policy) or is_allowlisted(verdict.host, policy):
        decision.skipped.append(("notify_registrar", "not applicable for this target"))
    elif "notify_registrar" in already_done:
        decision.skipped.append(("notify_registrar", "already done for this domain"))
    elif "notify_host" not in already_done:
        decision.skipped.append(("notify_registrar", "host was never notified"))
    elif not enrichment.registrar_abuse:
        decision.skipped.append(("notify_registrar", "no registrar abuse contact found"))
    else:
        decision.plans.append(Plan("notify_registrar", 3, enrichment.registrar_abuse[0]))
    return decision
