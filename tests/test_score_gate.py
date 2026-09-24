import math

import scripts.evidence as evidence
import scripts.score_gate as sg


def test_the_evidence_module_is_the_package_one_not_a_second_copy():
    # #1679: score_gate imported `evidence` FLAT-first, and the driver puts
    # both the package root and the flat scripts dir on PYTHONPATH -- so every
    # real run held two distinct `evidence` module objects. Harmless while the
    # module is stateless; a single module-level datum would silently split,
    # and the EVIDENCE_FACTOR/EVIDENCE_STATUSES check at import time would then
    # be comparing one copy against the other. Package first, flat fallback:
    # the pattern host_disclosure.py and model_resolver.py already use.
    assert sg.evidence is evidence


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


def test_every_evidence_status_has_its_expected_numeric_weight():
    # HIGH/CERTAIN has weight 5. These are contract values, independent of
    # EVIDENCE_FACTOR, so a changed status cannot rewrite the oracle.
    expected = (
        ("rejected", 0.0),
        ("needs_more_info", 2.5),
        ("unverified", 5.0),
        ("tool_reported", 5.0),
        ("corroborated", 7.5),
        ("advisor_confirmed", 7.5),
        ("tool_confirmed", 7.5),
        ("backup_scope_limited", 7.5),
    )
    for status, value in expected:
        assert sg.finding_score(_f("HIGH", "CERTAIN", status)) == value, status


def test_every_confidence_multiplier_and_material_severity_weight():
    for confidence, expected in (("CERTAIN", 5.0), ("LIKELY", 4.5),
                                 ("POSSIBLE", 4.0), ("NOTE", 2.0)):
        assert sg.finding_score(_f("HIGH", confidence)) == expected, confidence
    for severity, expected in (("CRITICAL", 20.0), ("HIGH", 5.0),
                               ("MEDIUM", 2.0), ("LOW", 0.0), ("INFO", 0.0)):
        assert sg.finding_score(_f(severity, "CERTAIN")) == expected, severity


def test_primary_and_backup_boundaries_use_scores_even_for_confirmed_statuses():
    # Confirmation is a score factor, not a bypass around either floor.
    below_primary = _f("MEDIUM", "NOTE", "corroborated")  # 2 * .4 * 1.5
    near_primary = [_f("HIGH", "NOTE", "needs_more_info"),
                    _f("MEDIUM", "NOTE", "needs_more_info")]
    above_primary = _f("MEDIUM", "POSSIBLE", "tool_reported")
    below_backup = _f("HIGH", "CERTAIN", "backup_scope_limited")
    at_backup = [_f("MEDIUM", "CERTAIN", "unverified")] * 4
    assert sg.finding_score(below_primary) == 1.2
    assert sg.should_engage_primary([below_primary]) is False
    assert sg.score(near_primary) == 1.4
    assert sg.should_engage_primary(near_primary) is False, "1.4 is below the 1.5 primary floor"
    assert sg.finding_score(above_primary) == 1.6
    assert sg.should_engage_primary([above_primary]) is True
    assert sg.finding_score(below_backup) == 7.5
    assert sg.should_engage_primary([below_backup]) is True
    assert sg.should_summon_backup([below_backup]) is False
    assert sg.score(at_backup) == 8.0
    assert sg.should_summon_backup(at_backup) is True
    assert sg.should_summon_backup([_f("CRITICAL", "CERTAIN", "needs_more_info")]) is True
