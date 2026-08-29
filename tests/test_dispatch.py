import contextlib
import io
import json
import os
import tempfile
import unittest
from unittest import mock

import scripts.dispatch as dispatch
import scripts.evidence as evidence


class TestDetectHost(unittest.TestCase):
    def _detect(self, env):
        with mock.patch.dict(os.environ, env, clear=True):
            return dispatch._detect_host()

    def _detect_with_stderr(self, env):
        with contextlib.redirect_stderr(io.StringIO()) as err:
            with mock.patch.dict(os.environ, env, clear=True):
                host = dispatch._detect_host()
        return host, err.getvalue()

    def test_warns_when_inferred_from_kimi_env(self):
        host, err = self._detect_with_stderr({"KIMI_CODE_VERSION": "1.0"})
        self.assertEqual(host, "kimi")
        self.assertIn("WARNING", err)
        self.assertIn("--host", err)

    def test_warns_when_inferred_from_codex_sandbox(self):
        host, err = self._detect_with_stderr({"CODEX_SANDBOX": "seatbelt"})
        self.assertEqual(host, "codex")
        self.assertIn("WARNING", err)

    def test_codex_wins_over_other_host_markers(self):
        self.assertEqual(self._detect({"CODEX_SANDBOX": "seatbelt",
                                      "KIMI_SESSION_ID": "x",
                                      "CLAUDECODE": "1"}), "codex")

    def test_warns_when_inferred_from_claude_env(self):
        # clear=True matters: _detect_host checks Kimi first, so an ambient
        # KIMI_* var on the runner would otherwise decide this test.
        host, err = self._detect_with_stderr({"CLAUDECODE": "1"})
        self.assertEqual(host, "claude")
        self.assertIn("WARNING", err)
        self.assertIn("--host", err)

    def test_kimi_env(self):
        self.assertEqual(self._detect({"KIMI_CODE_VERSION": "1"}), "kimi")
        self.assertEqual(self._detect({"KIMI_SESSION_ID": "x"}), "kimi")

    def test_claude_env(self):
        self.assertEqual(self._detect({"CLAUDECODE": "1"}), "claude")
        self.assertEqual(self._detect({"CLAUDE_CODE_SESSION_ID": "abc"}), "claude")

    def test_no_env_is_generic_not_kimi(self):
        self.assertEqual(self._detect({}), "generic")

    def test_kimi_wins_over_claude_when_both(self):
        self.assertEqual(
            self._detect({"KIMI_SESSION_ID": "x", "CLAUDECODE": "1"}), "kimi")


class TestRenderPrompt(unittest.TestCase):
    def _entry_mapping(self):
        # #run10: retargeted from the retired panel-review.md to the live 5.x
        # matrix template. render_prompt itself is unchanged and still live.
        return {
            "domain": "SEC", "group": "g1",
            "file_list": "a.py, b.py", "security_mode": "standard",
            "tests": "t.py", "menu": "SEC-A1A x", "criteria": "c",
            "tool_hits": "", "run_id": "R",
            "out_file": ".panopticon/findings-g1-SEC.json",
        }

    def test_rendered_panel_prompt_properties(self):
        p = dispatch.render_prompt("domain-panel.md", self._entry_mapping())
        self.assertNotIn("---\nname:", p)               # frontmatter stripped
        self.assertIn("SEC", p)                          # {domain} filled
        self.assertIn("a.py, b.py", p)                   # {file_list} filled
        self.assertIn(".panopticon/findings-g1-SEC.json", p)
        # tool-policy line injected, naming allowed and forbidden tools
        self.assertIn("Read", p)
        self.assertIn("must not use", p.lower())
        # no known placeholder tokens survive; JSON/regex braces in the body do
        for tok in dispatch.PLACEHOLDER_RE.findall(p):
            self.assertNotIn(tok, self._entry_mapping(), tok)

    def test_unfilled_placeholder_fails_fast(self):
        mapping = self._entry_mapping()
        del mapping["menu"]
        with self.assertRaises(ValueError) as ctx:
            dispatch.render_prompt("domain-panel.md", mapping)
        self.assertIn("menu", str(ctx.exception))
        self.assertIn("domain-panel.md", str(ctx.exception))

    def test_brace_safety_value_containing_placeholder_syntax(self):
        mapping = self._entry_mapping()
        mapping["file_list"] = "weird-{menu}-name.py"   # value contains {menu}
        p = dispatch.render_prompt("domain-panel.md", mapping)
        self.assertIn("weird-{menu}-name.py", p)        # survives literally

class TestRenderGoldens(unittest.TestCase):
    def test_rendered_output_matches_goldens(self):
        base = {"panel": "security", "group": "g1", "file_list": "a.py, b.py",
                "security_mode": "standard", "depth": "standard",
                "lenses": "- known_vulns\n- novel", "lens": "injection"}
        # #run10: the panel-review / lens-sweep goldens retired with their
        # templates; scout is the remaining rendered golden.
        out_files = {"scout.md": ".panopticon/scout-g1.json"}
        gdir = os.path.join(os.path.dirname(__file__), "goldens")
        for role, out_file in out_files.items():
            m = dict(base, out_file=out_file)
            with open(os.path.join(gdir, role[:-3] + ".rendered.txt"), encoding="utf-8") as fh:
                expected = fh.read()
            self.assertEqual(dispatch.render_prompt(role, m), expected, role)


class TestRenderAdvisor(unittest.TestCase):
    # 16 hex chars: shape of evidence.finding_fingerprint's output (#443).
    # Hand-picked here (rather than computed) because this class tests
    # dispatch's rendering behavior in isolation from evidence -- the
    # TestQueueIdContractWithEvidence class below wires the two together.
    QID_1 = "a1b2c3d4e5f60001"
    QID_2 = "a1b2c3d4e5f60002"

    def _queue(self, tmp):
        queue = {"version": "4.2.0", "run_id": "run-test",
             "cut_by_max_verify": 0, "entries": [
            {"queue_id": self.QID_1, "priority": 1,
             "finding": {"id": "SEC-001", "title": "sqli", "severity": "HIGH",
                          "panel": "security", "category": "injection",
                          "location": {"file": "app.py", "line_start": 10},
                          "description": "raw query with {code_context} text"}},
            {"queue_id": self.QID_2, "priority": 3,
             "finding": {"id": "CD-002", "title": "leak", "severity": "LOW",
                          "panel": "code", "category": "correctness",
                          "location": {"file": "b.py", "line_start": 4}}},
        ]}
        qpath = os.path.join(tmp, "verify-queue.json")
        with open(qpath, "w", encoding="utf-8") as fh:
            json.dump(queue, fh)
        return qpath

    def test_writes_one_prompt_per_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            qpath = self._queue(tmp)
            outdir = os.path.join(tmp, "advisor-prompts")
            written = dispatch.render_advisor_prompts(qpath, outdir)
            self.assertEqual([os.path.basename(p) for p in written],
                             [self.QID_1 + ".md", self.QID_2 + ".md"])
            with open(written[0], encoding="utf-8") as fh:
                text = fh.read()
            self.assertIn('"id": "SEC-001"', text)        # claim embedded
            self.assertIn("{code_context}", text)          # brace-safe: survives
            self.assertNotIn("{claim_json}", text)         # placeholder filled
            self.assertNotIn("---\nname:", text)           # frontmatter stripped

    def test_malformed_queue_fails_fast(self):
        with tempfile.TemporaryDirectory() as tmp:
            qpath = os.path.join(tmp, "bad.json")
            with open(qpath, "w", encoding="utf-8") as fh:
                fh.write("{not json")
            with self.assertRaises(ValueError):
                dispatch.render_advisor_prompts(qpath, tmp)

    def test_cli_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            qpath = self._queue(tmp)
            outdir = os.path.join(tmp, "out")
            rc = dispatch.main(["--render-advisor", qpath, "--out", outdir])
            self.assertEqual(rc, 0)
            self.assertTrue(os.path.isfile(
                os.path.join(outdir, self.QID_1 + ".md")))

    def test_non_dict_queue_fails_fast(self):
        with tempfile.TemporaryDirectory() as tmp:
            qpath = os.path.join(tmp, "array.json")
            with open(qpath, "w") as fh:
                json.dump([], fh)
            with self.assertRaises(ValueError):
                dispatch.render_advisor_prompts(qpath, tmp)

    def test_non_dict_entry_fails_fast(self):
        with tempfile.TemporaryDirectory() as tmp:
            queue = {"version": "4.0.0", "run_id": "run-test",
                     "cut_by_max_verify": 0, "entries": [None]}
            qpath = os.path.join(tmp, "bad-entry.json")
            with open(qpath, "w") as fh:
                json.dump(queue, fh)
            with self.assertRaises(ValueError):
                dispatch.render_advisor_prompts(qpath, tmp)

    def test_unsafe_queue_id_fails_fast(self):
        # queue_id is OUR artifact (built by evidence.build_verify_queue), but
        # render_advisor_prompts validates it anyway: a corrupt/tampered queue
        # file with a path-shaped queue_id must not reach os.path.join. The
        # fingerprint contract (#443) makes the check strictly tighter than
        # before -- no separators or dots survive it at all, not just the
        # traversal-shaped ones.
        with tempfile.TemporaryDirectory() as tmp:
            queue = {"version": "4.2.0", "run_id": "run-test",
                     "cut_by_max_verify": 0, "entries": [
                {"queue_id": "../escape", "priority": 1,
                 "finding": {"id": "SEC-001", "title": "x", "severity": "HIGH",
                              "panel": "security", "category": "injection",
                              "location": {"file": "app.py", "line_start": 1}}},
            ]}
            qpath = os.path.join(tmp, "unsafe-queue.json")
            with open(qpath, "w") as fh:
                json.dump(queue, fh)
            with self.assertRaises(ValueError) as ctx:
                dispatch.render_advisor_prompts(qpath, tmp)
            self.assertIn("unsafe queue_id", str(ctx.exception))


class TestQueueIdResiduals(unittest.TestCase):
    """Round-2 parked residuals, updated for the fingerprint contract (#443).
    The old positional id's only unbounded-width component was the zero-padded
    position (`%03d` grows past 3 digits at 1000+ entries); under the new
    contract the only unbounded-width component is the collision suffix
    (evidence.build_verify_queue's `-<n>`), which can also grow past one
    digit. Non-string ids must still fail fast either way."""

    def _queue(self, tmp, entries):
        qpath = os.path.join(tmp, "q.json")
        with open(qpath, "w") as fh:
            json.dump({"version": "4.2.0", "run_id": "run-test",
                       "cut_by_max_verify": 0,
                       "entries": entries}, fh)
        return qpath

    def test_multi_digit_collision_suffix_accepted(self):
        qid = "a1b2c3d4e5f60001-10"
        with tempfile.TemporaryDirectory() as tmp:
            qpath = self._queue(tmp, [{"queue_id": qid, "priority": 1,
                                       "finding": {"id": "AB-001", "title": "t"}}])
            written = dispatch.render_advisor_prompts(qpath, os.path.join(tmp, "o"))
        self.assertEqual(os.path.basename(written[0]), qid + ".md")

    def test_non_string_queue_id_raises_valueerror(self):
        with tempfile.TemporaryDirectory() as tmp:
            qpath = self._queue(tmp, [{"queue_id": 7, "priority": 1,
                                       "finding": {"id": "AB-001"}}])
            with self.assertRaises(ValueError):
                dispatch.render_advisor_prompts(qpath, os.path.join(tmp, "o"))

    def test_trailing_newline_queue_id_rejected(self):
        # Python's `$` matches before a trailing newline as well as at end of
        # string, so an otherwise-valid id with a "\n" glued on cleared a
        # `^...$` guard and reached the "%s.md" filename interpolation. \A/\Z
        # is the anchor pair that means what this check intends.
        for qid in ("a1b2c3d4e5f60001\n", "a1b2c3d4e5f60001-10\n"):
            with tempfile.TemporaryDirectory() as tmp:
                qpath = self._queue(tmp, [{"queue_id": qid, "priority": 1,
                                           "finding": {"id": "AB-001",
                                                       "title": "t"}}])
                with self.assertRaises(ValueError) as ctx:
                    dispatch.render_advisor_prompts(qpath, os.path.join(tmp, "o"))
                self.assertIn("unsafe queue_id", str(ctx.exception))


class TestQueueIdContractWithEvidence(unittest.TestCase):
    """Wires the two ends of the queue_id contract together. #443 broke this
    silently once: evidence.build_verify_queue's id format changed (positional
    -> fingerprint) but dispatch.render_advisor_prompts's validation regex
    still expected the old shape, and no test caught it because both sides
    were only exercised against hand-written fixtures matching each module's
    own assumptions. Building the queue for real and feeding it straight into
    the render path means the two modules can't silently diverge again."""

    def _finding(self, fid, **over):
        f = {"id": fid, "severity": "HIGH", "panel": "security",
             "category": "injection", "title": "t-" + fid,
             "location": {"file": fid + ".py", "line_start": 1}}
        f.update(over)
        return f

    def test_real_build_verify_queue_output_renders(self):
        findings = [self._finding("A"), self._finding("B", severity="LOW")]
        entries, cut = evidence.build_verify_queue(findings)
        with tempfile.TemporaryDirectory() as tmp:
            qpath = os.path.join(tmp, "verify-queue.json")
            evidence.write_verify_queue(entries, cut, qpath)
            written = dispatch.render_advisor_prompts(qpath, os.path.join(tmp, "o"))
        self.assertEqual(len(written), 2)
        self.assertEqual(sorted(os.path.basename(p) for p in written),
                         sorted("%s.md" % e["queue_id"] for e in entries))

    def test_real_collision_suffix_renders(self):
        # Two findings that collide in fingerprint (same panel/category/file/
        # title) still produce a queue dispatch.render_advisor_prompts accepts
        # end to end, filenames and all.
        a = self._finding("X")
        b = self._finding("Y", title=a["title"], location=dict(a["location"]))
        entries, cut = evidence.build_verify_queue([a, b])
        fp = evidence.finding_fingerprint(a)
        self.assertEqual(sorted(e["queue_id"] for e in entries),
                         sorted([fp, fp + "-1"]))                    # collision fired
        with tempfile.TemporaryDirectory() as tmp:
            qpath = os.path.join(tmp, "verify-queue.json")
            evidence.write_verify_queue(entries, cut, qpath)
            written = dispatch.render_advisor_prompts(qpath, os.path.join(tmp, "o"))
        self.assertEqual(len(written), 2)


class TestKimiDefaultAgentsDir(unittest.TestCase):
    def test_kimi_registration_dir_defaults_to_user_agents(self):
        expected = os.path.join(os.path.expanduser("~"), ".kimi-code", "agents")
        self.assertEqual(dispatch._registration_dir("kimi", None), expected)

    def test_claude_registration_dir_unchanged(self):
        expected = os.path.join(os.path.expanduser("~"), ".claude", "agents")
        self.assertEqual(dispatch._registration_dir("claude", None), expected)

    def test_explicit_agents_dir_overrides_kimi_default(self):
        self.assertEqual(dispatch._registration_dir("kimi", "/custom"), "/custom")


class TestEmitHostAgents(unittest.TestCase):
    def test_claude_files_written_for_all_roles(self):
        with tempfile.TemporaryDirectory() as d:
            written = dispatch.emit_host_agents("claude", d)
            names = sorted(os.path.basename(p) for p in written)
            # #run10: the 4.x panel_review/lens_sweep shells retired with their
            # roles; the registered set is the 5.x matrix + scout + advisor.
            self.assertEqual(names, ["panopticon-advisor.md",
                                     "panopticon-domain-advisor.md",
                                     "panopticon-domain-panel.md",
                                     "panopticon-scout.md"])

    def test_claude_frontmatter_is_enforcement_shell(self):
        with tempfile.TemporaryDirectory() as d:
            dispatch.emit_host_agents("claude", d)
            with open(os.path.join(d, "panopticon-domain-panel.md"), encoding="utf-8") as fh:
                text = fh.read()
            self.assertIn("name: panopticon-domain-panel", text)
            # domain_panel holds scoped Write (#436): it self-writes its
            # out_file; the write-guard hook (Tasks 4-5) confines the write.
            self.assertIn("tools: Read, Grep, Glob, Write", text)
            self.assertIn("model: sonnet", text)
            self.assertNotIn("Bash", text.split("---")[1])  # no forbidden tool in frontmatter
            body = text.split("---", 2)[2]
            self.assertIn("Follow the dispatched task", body)
            self.assertIn("Bash", body)  # charter names the forbidden list

    def test_claude_models_follow_policy(self):
        with tempfile.TemporaryDirectory() as d:
            dispatch.emit_host_agents("claude", d)
            for fname, model in (("panopticon-scout.md", "haiku"),
                                                                  ("panopticon-domain-panel.md", "sonnet"),
                                 # #1029: tool-advisor -> haiku; the cell
                                 # domain-advisor (incl. backup) stays opus.
                                 ("panopticon-advisor.md", "haiku"),
                                 ("panopticon-domain-panel.md", "sonnet"),
                                 ("panopticon-domain-advisor.md", "opus")):
                with open(os.path.join(d, fname), encoding="utf-8") as fh:
                    self.assertIn("model: %s" % model, fh.read(), fname)

    def test_kimi_dialect_has_disallowed_tools(self):
        with tempfile.TemporaryDirectory() as d:
            dispatch.emit_host_agents("kimi", d)
            with open(os.path.join(d, "panopticon-domain-panel.md"), encoding="utf-8") as fh:
                text = fh.read()
            self.assertIn("disallowedTools:", text)
            self.assertIn("- Bash", text)

    def test_codex_toml_agents_are_read_only(self):
        with tempfile.TemporaryDirectory() as d:
            written = dispatch.emit_host_agents("codex", d)
            self.assertEqual(len(written), 4)   # #run10: 4.x roles retired
            self.assertTrue(all(path.endswith(".toml") for path in written))
            with open(os.path.join(d, "panopticon-domain-panel.toml"), encoding="utf-8") as fh:
                text = fh.read()
            self.assertIn('name = "panopticon-domain-panel"', text)
            self.assertIn('model = "gpt-5.6-terra"', text)
            self.assertIn('model_reasoning_effort = "high"', text)
            self.assertIn('sandbox_mode = "read-only"', text)
            self.assertIn("never execute target code", text)

    def test_kimi_agent_file_includes_model_preference_and_when_to_use(self):
        with tempfile.TemporaryDirectory() as d:
            paths = dispatch.emit_host_agents("kimi", d)
            self.assertEqual(len(paths), 4)   # #run10: 4.x roles retired
            for p in paths:
                with open(p, encoding="utf-8") as fh:
                    content = fh.read()
                self.assertIn("whenToUse:", content)
                self.assertIn("override: false", content)
                self.assertIn("model_preference:", content)

            # role-specific preferences
            scout = os.path.join(d, "panopticon-scout.md")
            domain_advisor = os.path.join(d, "panopticon-domain-advisor.md")
            panel_review = os.path.join(d, "panopticon-domain-panel.md")
            advisor = os.path.join(d, "panopticon-advisor.md")
            with open(scout, encoding="utf-8") as fh:
                self.assertIn("model_preference: primary", fh.read())
            with open(domain_advisor, encoding="utf-8") as fh:
                self.assertIn("model_preference:", fh.read())
            with open(panel_review, encoding="utf-8") as fh:
                self.assertIn("model_preference: secondary", fh.read())
            with open(advisor, encoding="utf-8") as fh:
                self.assertIn("model_preference: secondary", fh.read())

    def test_idempotent(self):
        def _read_all(d):
            out = {}
            for p in os.listdir(d):
                with open(os.path.join(d, p), encoding="utf-8") as fh:
                    out[p] = fh.read()
            return out

        with tempfile.TemporaryDirectory() as d:
            dispatch.emit_host_agents("claude", d)
            first = _read_all(d)
            dispatch.emit_host_agents("claude", d)
            second = _read_all(d)
            self.assertEqual(first, second)

    def test_unsupported_host_fails_fast(self):
        with self.assertRaises(ValueError):
            dispatch.emit_host_agents("generic", "/tmp/x")

    def test_cli_kimi_defaults_to_kimi_agents_dir(self):
        with tempfile.TemporaryDirectory() as d, \
             mock.patch.object(dispatch, "KIMI_AGENTS_DIR", d):
            rc = dispatch.main(["--emit-host-agents", "kimi"])
            self.assertEqual(rc, 0)
            for fname in (
                "panopticon-scout.md",
                "panopticon-domain-panel.md",
                                "panopticon-advisor.md",
            ):
                self.assertTrue(
                    os.path.isfile(os.path.join(d, fname)),
                    f"missing {fname}",
                )

    def test_cli_writes_to_out(self):
        with tempfile.TemporaryDirectory() as d:
            rc = dispatch.main(["--emit-host-agents", "claude", "--out", d])
            self.assertEqual(rc, 0)
            self.assertTrue(os.path.isfile(os.path.join(d, "panopticon-scout.md")))

    def test_emission_ignores_ambient_model_env_overrides(self):
        # The advisor policy model is haiku (#1029); set the env override to a
        # DIFFERENT value so the test still proves emission ignores the env.
        with tempfile.TemporaryDirectory() as d, \
             mock.patch.dict(os.environ, {"PANOPTICON_MODEL_ADVISOR": "opus"}):
            dispatch.emit_host_agents("claude", d)
            with open(os.path.join(d, "panopticon-advisor.md"), encoding="utf-8") as fh:
                text = fh.read()
        self.assertIn("model: haiku", text)
        self.assertNotIn("model: opus", text)


class TestVerifyPlan(unittest.TestCase):
    """#493 R1/R2: dispatch-time plan re-verification + hash-bound ack."""

    def _entry(self, enforced=True, role="domain_panel"):
        return {"role": role, "agent": "panopticon-domain-panel",
                "enforced": enforced, "scope_bound": True,
                "out_file": ".panopticon/x.json"}

    def test_enforced_flip_detected_when_shell_unregistered(self):
        with tempfile.TemporaryDirectory() as d:      # empty dir = nothing registered
            problems = dispatch.verify_plan([self._entry(enforced=True)],
                                            host="claude", agents_dir=d)
        self.assertEqual(len(problems), 1)
        self.assertIn("no registered shell", problems[0])

    def test_enforced_entry_with_live_shell_is_clean(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "panopticon-domain-panel.md"), "w", encoding="utf-8") as fh:
                fh.write("x")
            problems = dispatch.verify_plan([self._entry(enforced=True)],
                                            host="claude", agents_dir=d)
        self.assertEqual(problems, [])

    def test_unenforced_reviewer_needs_hash_matching_ack(self):
        plan = [self._entry(enforced=False)]
        with tempfile.TemporaryDirectory() as d:
            no_ack = dispatch.verify_plan(plan, host="claude", agents_dir=d)
            stale = dispatch.verify_plan(plan, host="claude", agents_dir=d,
                                         ack={"acknowledged": True,
                                              "plan_sha256": "deadbeef"})
            good = dispatch.verify_plan(plan, host="claude", agents_dir=d,
                                        ack={"acknowledged": True,
                                             "plan_sha256": dispatch.plan_content_hash(plan)})
        self.assertEqual(len(no_ack), 1)
        self.assertEqual(len(stale), 1)
        self.assertEqual(good, [])

    def test_non_reviewer_roles_ignored(self):
        with tempfile.TemporaryDirectory() as d:
            problems = dispatch.verify_plan(
                [{"role": "scout", "enforced": False}], host="claude", agents_dir=d)
        self.assertEqual(problems, [])


