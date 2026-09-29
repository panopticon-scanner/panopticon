"""#2227 (epic #1795): the wrappers the shell reader did not know.

`shell_reader.command` strips what stands in front of a command only for the
words in its closed wrapper table, and reads any other word as the command
itself. So `setsid curl ... | sh`, `curl ... | chrt 10 sh` and the other forms
below hid both the download and the interpreter from
`scripts/workflow_guard.py`, which reported each step clean, while `nice -n 5`,
`timeout 30` and `nohup` in the same two places were flagged.

Each of the six is now read with the grammar its own source defines --
util-linux 2.39.3 for `setsid`, `ionice`, `taskset`, `flock` and `chrt`, and
expect 5.45.4's `unbuffer` script -- and what that grammar cannot settle stays
an unresolved wrapper, which the guard reports: an option the table does not
know, an expansion in the operand that decides where the command starts, a pid
the program may read as "this process", a `spawn` switch where unbuffer's
program belongs. And behind `xargs`, which appends words from its input, any
wrapper that runs nothing as written is unresolved too.
"""
import unittest

import shell_reader
import workflow_guard as guard

URL = "https://example.test/tool"
CHECK = "echo '" + "a" * 64 + "  tool' | sha256sum -c -"
# The forms the triage measured clean on main, and the three controls it
# measured flagged.
TRIAGED = ("setsid", "setsid -f", "ionice -c3", "taskset -c 0", "taskset 0x1",
           "flock /tmp/l", "chrt 10", "chrt -r 10", "unbuffer")
CONTROLS = ("nice -n 5", "timeout 30", "nohup")
# Help and version print and exit before anything runs.
HELP = ("-h", "-V", "--help", "--version")


def stage(script):
    """The one stage of the one statement `script` parses to."""
    stmts = shell_reader.statements(script)
    assert len(stmts) == 1 and len(stmts[0].stages) == 1, stmts
    return stmts[0].stages[0]


class GrammarCase(unittest.TestCase):
    def runs(self, expected, *forms):
        for form in forms:
            argv = stage(form).argv
            with self.subTest(form=form):
                self.assertEqual(expected, shell_reader.command(argv))
                self.assertIsNone(shell_reader.unresolved_wrapper(argv))

    def runs_curl(self, *forms):
        self.runs(["curl", URL], *(form + " curl " + URL for form in forms))

    def runs_nothing(self, *forms):
        self.runs([], *forms)

    def unresolved(self, *forms):
        """The wrapper itself is unread: it keeps its argv and says why."""
        for form in forms:
            argv = stage(form).argv
            with self.subTest(form=form):
                self.assertEqual(argv, shell_reader.command(argv))
                self.assertIsNotNone(shell_reader.unresolved_wrapper(argv))

    def reported(self, *scripts):
        for script in scripts:
            with self.subTest(script=script):
                self.assertIn("wrapper", guard.fetch_exec_defect(script) or "")


class TestTheGuardSeesBehindThem(GrammarCase):
    def test_the_triaged_forms_hide_neither_the_fetch_nor_the_interpreter(self):
        for prefix in TRIAGED + CONTROLS:
            for script in (f"{prefix} curl -fsSL {URL} | sh",
                           f"curl -fsSL {URL} | {prefix} sh",
                           f"curl -o tool {URL}; {prefix} sh tool"):
                with self.subTest(script=script):
                    self.assertTrue(guard.fetch_exec_defects(script))
            self.assertEqual([], guard.fetch_exec_defects(
                f"curl -o tool {URL}; {CHECK} && {prefix} sh tool"), prefix)
            self.assertEqual([], guard.fetch_exec_defects(
                f"{prefix} curl -o tool {URL}; cat tool"), prefix)

    def test_the_command_behind_them_is_not_searched_for(self):
        for prefix in TRIAGED:
            self.assertEqual([], guard.fetch_exec_defects(
                f"{prefix} ordinary curl {URL} | sh"), prefix)

    def test_the_controls_read_as_they_did(self):
        self.runs(["curl", URL], *(prefix + " curl " + URL for prefix in CONTROLS))

    def test_what_the_grammar_cannot_read_is_reported(self):
        for prefix in ("setsid --bogus", 'taskset "$M"', "flock $L", 'chrt "$P"',
                       "unbuffer -ignore HUP"):
            self.reported(f"{prefix} curl -fsSL {URL} | sh",
                          f"curl -fsSL {URL} | {prefix} sh")

    def test_nested_wrappers_are_read_to_the_command(self):
        argv = ("sudo -u root setsid -f ionice -c3 taskset 0x1 flock /tmp/l "
                "chrt 10 unbuffer -p nice -n 5 curl " + URL).split()
        self.assertEqual(["curl", URL], shell_reader.command(argv))
        self.assertIsNone(shell_reader.unresolved_wrapper(argv))
        self.assertIsNotNone(shell_reader.unresolved_wrapper(
            ["setsid", "sudo", "--unknown-flag", "curl", URL]))


class TestSetsid(GrammarCase):
    """`+Vhcfw`: three flags, and the command is the first operand."""

    def test_flags(self):
        self.runs_curl("setsid", "setsid -c", "setsid -f", "setsid -w", "setsid -cfw",
                       "setsid --ctty --fork --wait", "setsid -f --")

    def test_help_and_version(self):
        self.runs_nothing(*("setsid " + option for option in HELP))
        self.runs_nothing("setsid -fh curl " + URL)

    def test_what_it_cannot_read(self):
        self.unresolved("setsid -x curl " + URL, "setsid --fo curl " + URL,
                        "setsid --fork=1 curl " + URL, "setsid -f")


class TestIonice(GrammarCase):
    """`+n:c:p:P:u:tVh`: five options take a value; -p/-P/-u run nothing."""

    def test_options(self):
        self.runs_curl("ionice", "ionice -c3", "ionice -c 2 -n 7", "ionice -tc3",
                       "ionice --class=idle", "ionice --class idle --classdata=0 --ignore",
                       "ionice -n7 --")

    def test_ids_are_acted_on_and_nothing_runs(self):
        # Every operand after -p, -P or -u is another id, and a non-numeric
        # one is refused: ionice never executes in these modes.
        self.runs_nothing("ionice -p 1", "ionice -p 1 2 3", "ionice -P 1", "ionice -u 0",
                          "ionice --pid=1", "ionice --pgid 1", "ionice --uid=0",
                          "ionice -c3 -p 1 curl " + URL)
        self.assertEqual([], guard.fetch_exec_defects(f"ionice -p 1 curl -fsSL {URL} | sh"))

    def test_no_operand_runs_nothing(self):
        # It prints the current class, or refuses a class with nothing to set.
        self.runs_nothing("ionice", "ionice -t", "ionice -c3")

    def test_help_and_version(self):
        self.runs_nothing(*("ionice " + option for option in HELP))

    def test_what_it_cannot_read(self):
        self.unresolved("ionice -x curl " + URL, 'ionice -c "$CLASS" curl ' + URL,
                        "ionice -c")


class TestTaskset(GrammarCase):
    """`+apchV`: no option takes a value; the mask comes before the command."""

    def test_mask_then_command(self):
        self.runs_curl("taskset 0x1", "taskset -c 0", "taskset -c 0,2-3",
                       "taskset --cpu-list 0", "taskset -a 0x1", "taskset --all-tasks 0x1",
                       "taskset -- 0x1")

    def test_a_pid_is_acted_on_and_nothing_runs(self):
        self.runs_nothing("taskset -p 1", "taskset -p 0x1 1", "taskset -pc 0 1",
                          "taskset --pid 0x1 1", "taskset -ap 0x1 1")

    def test_a_zero_pid_runs_the_command(self):
        # `-p` takes the pid from the LAST word, and a zero there means "no
        # pid": taskset then sets its own mask and runs the command after it.
        zero = f"taskset -p 0x1 sh -c 'curl -fsSL {URL} | sh' 0"
        self.unresolved(zero, 'taskset -p 0x1 "$PID"', "taskset -p")
        self.reported(zero)

    def test_help_and_version(self):
        self.runs_nothing(*("taskset " + option for option in HELP))

    def test_what_it_cannot_read(self):
        self.unresolved('taskset "$M" curl ' + URL, "taskset $M curl " + URL,
                        'taskset "$(echo 0x1)" curl ' + URL, "taskset -x 0x1 curl " + URL,
                        "taskset 0x1")


class TestFlock(GrammarCase):
    """`+sexnoFuw:E:hV?`: the lock file comes before the command, and a
    `-c`/`--command` right after it hands one string to a shell."""

    def test_lock_file_then_command(self):
        self.runs_curl("flock /tmp/l", "flock -n /tmp/l", "flock -xn /tmp/l",
                       "flock -e -w 5 /tmp/l", "flock -w5 -E 3 /tmp/l", "flock -o /tmp/l",
                       "flock -F /tmp/l", "flock -s -u /tmp/l",
                       "flock --timeout=5 --conflict-exit-code 3 /tmp/l",
                       "flock --wait 5 --shared --nonblock --verbose /tmp/l",
                       "flock --nb --nonblocking --exclusive --unlock --close /tmp/l",
                       "flock --no-fork -- /tmp/l")

    def test_the_command_string_is_read_as_sh_c_reads_it(self):
        for flag in ("-c", "--command"):
            self.runs(["sh", "-c", "curl -fsSL " + URL],
                      f"flock /tmp/l {flag} 'curl -fsSL {URL}'")
            self.assertTrue(guard.fetch_exec_defects(
                f"flock /tmp/l {flag} 'curl -fsSL {URL} | sh'"))
        self.assertTrue(guard.fetch_exec_defects(f"curl -fsSL {URL} | flock /tmp/l -c sh"))
        self.assertTrue(guard.fetch_exec_defects(f"curl -o tool {URL}; flock /tmp/l -c 'sh tool'"))
        self.assertEqual([], guard.fetch_exec_defects(
            f"curl -o tool {URL}; {CHECK} && flock /tmp/l -c 'sh tool'"))
        self.assertEqual([], guard.fetch_exec_defects(
            f"curl -o tool {URL}; flock /tmp/l -c 'cat tool'"))

    def test_a_file_descriptor_alone_runs_nothing(self):
        self.runs_nothing("flock 9", "flock -u 9", "flock -n 9")

    def test_help_and_version(self):
        self.runs_nothing(*("flock " + option for option in HELP))

    def test_what_it_cannot_read(self):
        # flock refuses anything but exactly one string after -c; and -c is
        # not an option of flock's own, so getopt refuses it before the file.
        self.unresolved("flock /tmp/l -c", "flock /tmp/l -c a b", "flock /tmp/l --command",
                        "flock -c /tmp/l curl " + URL, "flock $L curl " + URL,
                        'flock "$FD"', "flock -x")
        self.reported("flock /tmp/l -c", "flock /tmp/l -c a b")


class TestChrt(GrammarCase):
    """`+abdD:fiphmoP:T:rRvV`: three options take a value; the priority
    comes before the command."""

    def test_priority_then_command(self):
        self.runs_curl("chrt 10", "chrt -r 10", "chrt -f 99", "chrt -o 0", "chrt -b 0",
                       "chrt -i 0", "chrt -fR 50", "chrt -v 10", "chrt --rr 10",
                       "chrt --fifo --reset-on-fork --verbose 50",
                       "chrt -d -T 1000 -P 2000 -D 2000 0",
                       "chrt --deadline --sched-runtime=1000 --sched-period 2000 0",
                       "chrt -- 10")

    def test_a_pid_or_the_ranges_run_nothing(self):
        self.runs_nothing("chrt -p 1", "chrt -p 10 1", "chrt -ap 10 1", "chrt --pid 1",
                          "chrt -m", "chrt --max", "chrt -m 10 curl " + URL)

    def test_a_zero_or_minus_one_pid_runs_the_command(self):
        # The pid is the LAST word: 0 means this process, and -1 is chrt's own
        # "no pid" value, so both set the policy and run the command.
        zero = f"chrt -p 10 sh -c 'curl -fsSL {URL} | sh' 0"
        minus_one = f"chrt -o -p 0 sh -c 'curl -fsSL {URL} | sh' -1"
        self.unresolved(zero, minus_one, 'chrt -p 10 "$PID"')
        self.reported(zero, minus_one)

    def test_help_and_version(self):
        self.runs_nothing(*("chrt " + option for option in HELP))

    def test_what_it_cannot_read(self):
        self.unresolved('chrt "$P" curl ' + URL, "chrt -x 10 curl " + URL,
                        'chrt -T "$RUNTIME" 0 curl ' + URL, "chrt 10")


class TestUnbuffer(GrammarCase):
    """A Tcl script, not getopt: `unbuffer [-p] program [args]`, and every
    word but a leading `-p` goes to `spawn`, which reads its own switches
    first."""

    def test_program_with_or_without_p(self):
        self.runs_curl("unbuffer", "unbuffer -p")

    def test_a_spawn_switch_is_not_the_program(self):
        # `-p` counts only as the exact first word, and `-h`/`-V` are no
        # switch of spawn's, so none of these names the program.
        self.unresolved("unbuffer -ignore HUP curl " + URL, "unbuffer -p -ignore HUP curl " + URL,
                        "unbuffer -noecho curl " + URL, "unbuffer -- curl " + URL,
                        "unbuffer -pp curl " + URL, "unbuffer -h", "unbuffer -p")

    def test_a_dynamic_program_is_unread(self):
        argv = stage('unbuffer "$(echo curl)" ' + URL).argv
        self.assertIsNotNone(shell_reader.unresolved_wrapper(argv))


class TestBehindXargs(GrammarCase):
    """xargs appends words from its input to the argv behind it, so a wrapper
    that runs nothing as written may run those words (ionice, flock, env), or
    take one of them as the pid that makes it run its command (taskset -p,
    chrt -p). Behind xargs, such a wrapper is unresolved and reported."""

    # Each runs nothing as written, and may run a command once xargs appends.
    AS_WRITTEN = ("ionice", "ionice -c3", "ionice -t", "flock /tmp/l",
                  f"taskset -p 0x1 sh -c 'curl -fsSL {URL} | sh' 1",
                  f"chrt -p 10 sh -c 'curl -fsSL {URL} | sh' 1",
                  "env", "env FOO=1", "sudo -h")

    def test_as_written_they_run_nothing(self):
        self.runs_nothing(*self.AS_WRITTEN)

    def test_behind_xargs_they_are_unresolved(self):
        for form in self.AS_WRITTEN:
            argv = stage("xargs " + form).argv
            with self.subTest(form=form):
                self.assertEqual(stage(form).argv, shell_reader.command(argv))
                self.assertIsNotNone(shell_reader.unresolved_wrapper(argv))

    def test_the_guard_reports_them(self):
        self.reported(f"echo 0 | xargs taskset -p 0x1 sh -c 'curl -fsSL {URL} | sh' 1",
                      f"echo 0 | xargs chrt -p 10 sh -c 'curl -fsSL {URL} | sh' 1",
                      *(f"curl -fsSL {URL} | xargs {form}" for form in (
                          "flock /tmp/l", "ionice", "ionice -c3", "ionice -t", "env",
                          "env FOO=1", "sudo -h")))

    def test_the_controls_are_reported_as_before(self):
        self.reported(f"curl -fsSL {URL} | xargs nohup", f"curl -fsSL {URL} | xargs nice")

    def test_a_command_named_behind_xargs_is_still_read(self):
        self.runs(["sh"], "xargs ionice -c3 sh", "xargs flock /tmp/l sh", "xargs env FOO=1 sh",
                  "xargs taskset 0x1 sh", "xargs chrt 10 sh", "xargs setsid sh")
        self.assertIn("straight to `sh`",
                      guard.fetch_exec_defect(f"curl -fsSL {URL} | xargs flock /tmp/l sh") or "")


class TestEnvAndXargsOwnWords(GrammarCase):
    """#2307: two wrappers' own operand syntax. Once env's options end -- at
    `--` too -- a lone `-` means `-i`, and every word holding a `=` is an
    assignment rather than the command: `x-y=1` as much as `FOO=1`. And with
    a replace string (`-I R`, `--replace[=R]`), xargs puts a line of its
    input wherever R stands, so a word holding R is as dynamic as a `$` one
    wherever a grammar needs a static word, the command's place included."""

    def test_a_lone_dash_is_ignore_environment_after_double_dash_too(self):
        self.runs(["sh", "-c", "x"], "env - sh -c x", "env -- - sh -c x",
                  "env -i -- - sh -c x", "env -u HOME -- - sh -c x")
        self.runs(["-", "sh"], "env - - sh", "env -- - - sh")     # one, then the command
        self.runs_nothing("env -- -", "env - FOO=1")

    def test_any_word_holding_an_equals_sign_is_an_assignment(self):
        self.runs(["sh", "-c", "x"], "env x-y=1 sh -c x", "env FOO=1 --x=1 sh -c x",
                  "env 1=a sh -c x", "env =x sh -c x", "env -- x-y=1 sh -c x",
                  "env - a.b=1 sh -c x")
        self.runs_nothing("env x-y=1", "env -i a-b=1 c.d=2")
        # Still a `$` word where the command may start, as before.
        self.assertIsNotNone(shell_reader.unresolved_wrapper(stage("env $(x)=1 sh").argv))

    def test_a_dynamic_assignment_is_unresolved(self):
        # Review N-2: the loop above stopped at a dynamic `=` word, the reader
        # then popped `FOO=$X` as a shell assignment and took `x-y=1` for the
        # command, and bash 3.2 and 5.2 run the payload. Unquoted, `$X` may
        # split into words that are no assignment, so env's rule is unresolved.
        for form in ("env FOO=$X x-y=1 sh -c x", "env x-y=1 FOO=$X sh -c x", "env FOO=$X sh",
                     "env - FOO=$X sh", "env -i FOO=$(date) x-y=1 sh", "env $(x)=1 sh",
                     "env A={1,2} x-y=1 sh -c x", "xargs -I{} env X={} x-y=1 sh"):
            with self.subTest(form=form):
                self.assertIn("`env` has a dynamic assignment",
                              shell_reader.unresolved_wrapper(stage(form).argv) or "")
        self.reported(f"env FOO=$X x-y=1 sh -c 'curl -fsSL {URL} | sh'")
        self.runs(["python3", "x.py"], "env FOO=1 x-y=2 python3 x.py")   # static: as before

    def test_the_guard_reads_env_through_them(self):
        for form in ("env -- -", "env x-y=1", "env FOO=1 --x=1", "env 1=a"):
            with self.subTest(form=form):
                self.assertIn("straight to `sh`", guard.fetch_exec_defect(
                    f"{form} sh -c 'curl -fsSL {URL} | sh'") or "")
        self.reported(f"curl -fsSL {URL} | xargs env x-y=1",
                      f"curl -fsSL {URL} | xargs env -- -")

    def test_a_word_holding_the_replace_string_is_dynamic(self):
        for form in ("xargs -I{} {}", "xargs -I {} {} -c x", "xargs -0I{} {} a",
                     "xargs --replace {}", "xargs --replace=R R", "xargs -I% sh%",
                     "xargs -I{} setsid {}", "xargs -I{} nice {}", "xargs -I{} sudo {}",
                     "xargs -I{} env {} sh", "xargs -I{} taskset {} sh",
                     "xargs -I{} flock {} sh", "xargs -I{} chrt {} sh",
                     "xargs -I{} nice -n {} sh", "xargs -I{} sudo -u {} sh",
                     "xargs -I3 timeout 3 sh", "xargs -i {}"):
            with self.subTest(form=form):
                self.assertIsNotNone(shell_reader.unresolved_wrapper(stage(form).argv))
        self.reported(*(f"curl -fsSL {URL} | xargs -I{{}} {form}"
                        for form in ("{}", "setsid {}", "nice {}")))

    def test_the_replace_string_in_an_argument_reads_as_before(self):
        self.runs(["cp", "{}", "/d"], "xargs -I{} cp {} /d")
        self.runs(["sh", "-c", "echo {}"], "xargs -I{} sh -c 'echo {}'")
        self.runs(["sh"], "xargs -I{} timeout 30 sh")
        # An assignment whatever the line, but env's rule since review N-2
        # reads no dynamic one: unresolved, not a command.
        self.assertIn("dynamic assignment", shell_reader.unresolved_wrapper(
            stage("xargs -I{} env X={} sh").argv) or "")
        self.runs(["{}"], "xargs {}", "xargs -I% {}")    # no replace string in it


class TestAPatternBashExpands(GrammarCase):
    """#2294: bash expands an unquoted brace (`{sh,-c}`, `{a..b}`) or pathname
    pattern (`*`, `?`, `[...]`) in a word before the command runs, into any
    number of words. Where the command is expected, or a word that decides
    where it starts, such a word leaves the command unresolved, as a `$` word
    behind a wrapper does. Quoted or escaped, it is the word it looks like,
    and an assignment's word is no pattern to bash at all."""

    def test_at_the_command_position(self):
        self.unresolved("{sh,-c} 'curl x | sh'", "[s]h -c 'curl x | sh'", "/bin/s? -c x",
                        "/bin/*sh -c x", "{a..b} x", "x{sh,-c} x", "{sh,'-c'} x",
                        "{sh,-c}$(true) x", "a${b}[c] x")
        argv = shell_reader.statements("if {sh,-c} x; then :; fi")[0].stages[0].argv
        self.assertIsNotNone(shell_reader.unresolved_wrapper(argv))

    def test_where_a_wrapper_expects_the_command_or_decides_where_it_starts(self):
        self.unresolved("taskset {0x1,sh} -c 'curl x | sh'", "exec -a {x,sh} -c 'curl x | sh'",
                        "flock /tmp/*.lock sh", "chrt [1] sh", "nice -n {1,sh} x",
                        "sudo -u {root,sh} -c x", "timeout {5,sh} -c x",
                        "sudo --user={root,sh} -c x")
        for form in ("sudo {sh,-c} 'curl x | sh'", "nohup [s]h"):
            with self.subTest(form=form):
                self.assertIn("dynamic command operand behind a wrapper",
                              shell_reader.unresolved_wrapper(stage(form).argv) or "")
        self.assertIn("dynamic assignment",     # env's own rule since review N-2
                      shell_reader.unresolved_wrapper(stage("env {A=1,sh} -c x").argv) or "")

    def test_where_a_shell_looks_for_c_or_a_script(self):
        # Review N-3: bash 3.2 and 5.2 run `sh {-c,'…'}` as `sh -c '…'`, which
        # was read as `sh` running a file called `{-c,…}`, clean.
        self.unresolved("sh {-c,'curl x | sh'}", "bash -{c,x} 'curl x | sh'",
                        "sh -o pipefail {-c,x}", "sh -- {a,b}", "sh [x].sh")
        for form in ("sudo sh {-c,x}", "env A=1 sh {-c,x}"):
            with self.subTest(form=form):
                self.assertIn("where `sh` looks for `-c` or a script",
                              shell_reader.unresolved_wrapper(stage(form).argv) or "")
        # After the program, a pattern is only the script's argument.
        self.runs(["sh", "x.sh", "*.txt"], "sh x.sh *.txt")
        self.runs(["sh", "-c", "echo", "{a,b}"], "sh -c 'echo' {a,b}")

    def test_quoted_escaped_or_no_pattern_it_is_the_word_it_looks_like(self):
        self.runs(["{sh,-c}", "x"], "'{sh,-c}' x", "\\{sh,-c} x", "{sh','-c} x",
                  "sudo '{sh,-c}' x")
        self.runs(["[s]h", "-c", "x"], '"[s]h" -c x', "\\[s]h -c x")
        self.runs(["sh", "-c", "x"], "taskset '0x1' sh -c x", "taskset 0x1 sh -c x")
        self.runs(["echo", "{a,b}", "*", "[s]h"], "echo {a,b} * [s]h")
        self.runs(["[", "-f", "x", "]"], "[ -f x ]")
        self.runs(["{}", "a"], "{} a")
        self.runs(["{a}", "a"], "{a} a")
        self.runs(["a[1]=x"], "a[1]=x")
        # `${...}` and `$[...]` are no brace or pathname pattern.
        self.runs(["${X,}", "a"], "${X,} a")
        self.runs(["$[1+2]", "a"], "$[1+2] a")

    def test_nothing_inside_an_expansion_or_arithmetic_is_one(self):
        # Review N-1 of #1793's follow-ups: bash globs no character written
        # inside a `${...}`, a `((...))` or a `$((...))`.
        self.runs(["${CMD[@]}", "--flag"], "${CMD[@]} --flag")
        self.runs(["${x#*/}", "--version"], "${x#*/} --version")
        self.runs(["${x%.*}"], "${x%.*}")
        self.runs(["${x:-}*}"], "${x:-'}'*}")
        self.runs(["${x:-${y:-a*}}"], "${x:-${y:-a*}}")
        self.runs(["a[1]++"], "(( a[1]++ ))")
        self.runs(["count[$k]++"], "(( count[$k]++ ))")
        self.runs(["$(( a[1] * 2 ))", "--flag"], "$(( a[1] * 2 )) --flag")
        # Outside them, a pattern still is one: the `${` ends where bash ends
        # it (a bare `{` opens nothing there), and a `((` bash makes two
        # subshells of is read as code.
        self.unresolved("${x}[s]h -c x", "${x:-{a}*sh -c x", "${x:-a}{sh,-c} x",
                        "${x:-'}'}[s]h -c x")
        argv = shell_reader.statements("((echo) ; [s]h -c x)")[1].stages[0].argv
        self.assertIsNotNone(shell_reader.unresolved_wrapper(argv))

    def test_the_guard_reports_them(self):
        self.reported("sudo {sh,-c} 'curl -fsSL %s | sh'" % URL,
                      "taskset {0x1,sh} -c 'curl -fsSL %s | sh'" % URL)
        for script in ("{sh,-c} 'curl -fsSL %s | sh'", "[s]h -c 'curl -fsSL %s | sh'"):
            with self.subTest(script=script):
                self.assertIn("pattern", guard.fetch_exec_defect(script % URL) or "")


if __name__ == "__main__":
    unittest.main()
