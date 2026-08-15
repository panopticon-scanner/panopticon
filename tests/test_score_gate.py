import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "skill", "scripts"))
import score_gate as sg

def _f(sev, conf="POSSIBLE", status="unverified"):
    return {"severity": sev, "confidence": conf, "evidence": {"status": status}}

def test_anchor_twenty_lows_never_summon():
    findings = [_f("LOW")] * 20
    assert sg.score(findings) == 0.0
    assert sg.should_summon_backup(findings) is False
    assert sg.should_engage_primary(findings) is False  # all-LOW cell → below F_p

def test_anchor_one_high_four_med_summons():
    findings = [_f("HIGH")] + [_f("MEDIUM")] * 4
    assert sg.score(findings) == 10.4          # 5*.8 + 4*(2*.8)
    assert sg.should_summon_backup(findings) is True

def test_anchor_lone_critical_summons():
    assert sg.score([_f("CRITICAL")]) == 16.0  # 20*.8
    assert sg.should_summon_backup([_f("CRITICAL")]) is True

def test_lone_high_engages_but_no_backup():
    assert sg.score([_f("HIGH")]) == 4.0
    assert sg.should_summon_backup([_f("HIGH")]) is False
    assert sg.should_engage_primary([_f("HIGH")]) is True

def test_rejected_finding_drops_to_zero():
    assert sg.finding_score(_f("CRITICAL", status="rejected")) == 0.0

def test_corroborated_lifts_confirmed_cluster():
    findings = [_f("HIGH", status="corroborated")] + [_f("MEDIUM", status="corroborated")] * 4
    assert sg.score(findings) == 15.6          # 1.5 × 10.4

def test_unknown_values_fall_to_safe_defaults():
    # unknown severity → INFO(0); unknown confidence → POSSIBLE(.8); no evidence → unverified(1.0)
    assert sg.finding_score({"severity": "BOGUS"}) == 0.0
    assert sg.finding_score({"severity": "MEDIUM"}) == 1.6   # 2 * .8 * 1.0
