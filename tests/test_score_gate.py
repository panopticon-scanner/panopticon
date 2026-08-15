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

def test_non_dict_evidence_falls_to_unverified():
    # non-dict evidence must not raise; falls to unverified factor 1.0
    assert sg.finding_score({"severity": "MEDIUM", "evidence": "oops"}) == 1.6

def test_backup_floor_boundary_exactly_summons():
    # exactly F_b (8.0): 4 x MEDIUM/CERTAIN/unverified = 4*(2*1.0*1.0)
    findings = [_f("MEDIUM", conf="CERTAIN")] * 4
    assert sg.score(findings) == 8.0
    assert sg.should_summon_backup(findings) is True   # >= boundary

def test_just_below_backup_floor_does_not_summon():
    findings = [_f("MEDIUM", conf="CERTAIN")] * 3     # 6.0 < 8.0
    assert sg.score(findings) == 6.0
    assert sg.should_summon_backup(findings) is False
    assert sg.should_engage_primary(findings) is True  # 6.0 >= F_p 1.5

def test_below_primary_floor_does_not_engage():
    # MEDIUM/POSSIBLE/needs_more_info = 2*0.8*0.5 = 0.8 < 1.5
    f = _f("MEDIUM", conf="POSSIBLE", status="needs_more_info")
    assert sg.finding_score(f) == 0.8
    assert sg.should_engage_primary([f]) is False
