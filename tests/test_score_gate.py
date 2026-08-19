import math
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "skill", "scripts"))
import score_gate as sg


def _f(sev, conf="POSSIBLE", status="unverified"):
    return {"severity": sev, "confidence": conf, "evidence": {"status": status}}


def test_anchor_twenty_lows_never_summon():
    findings = [_f("LOW")] * 20
    if not (sg.score(findings) == 0.0): raise AssertionError()
    if sg.should_summon_backup(findings) is not False: raise AssertionError()
    if sg.should_engage_primary(findings) is not False: raise AssertionError()  # all-LOW cell → below F_p


def test_anchor_one_high_four_med_summons():
    findings = [_f("HIGH")] + [_f("MEDIUM")] * 4
    if not (math.isclose(sg.score(findings), 10.4, rel_tol=1e-5)): raise AssertionError()  # 5*.8 + 4*(2*.8)
    if sg.should_summon_backup(findings) is not True: raise AssertionError()


def test_anchor_lone_critical_summons():
    if not (sg.score([_f("CRITICAL")]) == 16.0): raise AssertionError()  # 20*.8
    if sg.should_summon_backup([_f("CRITICAL")]) is not True: raise AssertionError()


def test_lone_high_engages_but_no_backup():
    if not (sg.score([_f("HIGH")]) == 4.0): raise AssertionError()
    if sg.should_summon_backup([_f("HIGH")]) is not False: raise AssertionError()
    if sg.should_engage_primary([_f("HIGH")]) is not True: raise AssertionError()


def test_rejected_finding_drops_to_zero():
    if not (sg.finding_score(_f("CRITICAL", status="rejected")) == 0.0): raise AssertionError()


def test_corroborated_lifts_confirmed_cluster():
    findings = [_f("HIGH", status="corroborated")] + [_f("MEDIUM", status="corroborated")] * 4
    if not (math.isclose(sg.score(findings), 15.6, rel_tol=1e-5)): raise AssertionError()  # 1.5 × 10.4


def test_unknown_values_fall_to_safe_defaults():
    # unknown severity → INFO(0); unknown confidence → POSSIBLE(.8); no evidence → unverified(1.0)
    if not (sg.finding_score({"severity": "BOGUS"}) == 0.0): raise AssertionError()
    if not (sg.finding_score({"severity": "MEDIUM"}) == 1.6): raise AssertionError()   # 2 * .8 * 1.0


def test_non_dict_evidence_falls_to_unverified():
    # non-dict evidence must not raise; falls to unverified factor 1.0
    if not (sg.finding_score({"severity": "MEDIUM", "evidence": "oops"}) == 1.6): raise AssertionError()


def test_backup_floor_boundary_exactly_summons():
    # exactly F_b (8.0): 4 x MEDIUM/CERTAIN/unverified = 4*(2*1.0*1.0)
    findings = [_f("MEDIUM", conf="CERTAIN")] * 4
    if not (sg.score(findings) == 8.0): raise AssertionError()
    if sg.should_summon_backup(findings) is not True: raise AssertionError()   # >= boundary


def test_just_below_backup_floor_does_not_summon():
    findings = [_f("MEDIUM", conf="CERTAIN")] * 3     # 6.0 < 8.0
    if not (sg.score(findings) == 6.0): raise AssertionError()
    if sg.should_summon_backup(findings) is not False: raise AssertionError()
    if sg.should_engage_primary(findings) is not True: raise AssertionError()  # 6.0 >= F_p 1.5


def test_below_primary_floor_does_not_engage():
    # MEDIUM/POSSIBLE/needs_more_info = 2*0.8*0.5 = 0.8 < 1.5
    f = _f("MEDIUM", conf="POSSIBLE", status="needs_more_info")
    if not (sg.finding_score(f) == 0.8): raise AssertionError()
    if sg.should_engage_primary([f]) is not False: raise AssertionError()
