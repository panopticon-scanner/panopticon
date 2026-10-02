#!/usr/bin/env python3
"""The `set` options a `run:` step's shell starts with, and what a `set` leaves on.

Split out of `scripts/workflow_gating.py` (#2620) the way that module was split
out of `scripts/workflow_forms.py`: it had reached its size, and this part is a
layer of its own with no gating state in it -- four pure functions of the
option words, which `workflow_gating` re-exports so its callers do not move:

    `seed`           (`-e`, `pipefail`) as a step's `shell:` starts them
    `_errexit`       whether shell or `set` option words leave `-e` (or the
                     option `-o name` sets) on, one value per `o` LETTER
    `_rejected`      whether bash refuses the whole `set` -- a bad letter, or a
                     bad NAME after what earlier words already applied
    `_takes_value`   whether `set` reads a word as the name an `o` before it takes

The layers run one way: this module reads only the option tables in
`workflow_programs` BELOW it (the letters a shell takes, the names `set -o`
knows); `workflow_gating` sits above it and `workflow_forms` above that. The
measured facts behind each rule stay in the function docstrings, where the
pins cite them.

Stdlib only, like everything under it.
"""
from workflow_programs import SET_OPTION_NAMES, SET_OPTIONS, VALUE_OPTIONS


def _takes_value(words, at):
    """Whether bash's `set` reads `words[at]` as the option NAME an `o`
    before it takes: any word that is not itself an option word. `set -o -e`
    prints the settings and the `-e` still turns errexit ON -- rc 1 on bash
    3.2.57 and 5.2.21 with a `false` behind it, and no `SURVIVED` -- and so
    does `set -oo pipefail -e`. A shell's COMMAND LINE takes the next word
    whatever it spells: `bash -oo pipefail -c P` answers `-c: invalid option
    name`, rc 2, and runs nothing at all (`invocation` below, and
    `workflow_programs._past_options`, which counts the same way)."""
    return at < len(words) and words[at][:1] not in ("-", "+")


def _rejected(words):
    """Whether bash refuses this `set` WHOLE: one of its option words carries
    a letter the builtin lacks (`set -Z -e`, `set -eO foo`), or is a LONG one
    -- bash's `set` has none, and answers `set --posix -e` with `set: --:
    invalid option` (review NIT 4) -- or an `o` in it takes a value that is
    no option NAME (`set -o foo`, #2560). A bad LETTER leaves no option
    changed (rc 2, #2443); a bad NAME keeps what the words before it set, as
    the third paragraph says (rc 1 on bash 3.2.57, 2 on 5.2.21). dash and
    `sh` die at the `set` instead, so nothing runs there at all. `set --` is
    the positional spelling that ends the options, not a refusal:
    `set -- "$@"` reads as it always did.

    Read over the words `_errexit` reads, taking one value per `o` LETTER
    exactly as it does -- as bash does, and as
    `workflow_programs._past_options` and `stdin_program` already did -- so
    the two walks agree about which words are values. `set -oo pipefail
    errexit` turns errexit ON and leaves no positional behind (`$#` is 0 on
    bash 3.2.57 and 5.2.21), where the per-word count this replaced read the
    `errexit` as the end of the options (#2559, review NIT 6 of #2551). The
    shape that count was keeping out, `set -oo x -Ze`, is caught by the NAME
    now: `x` is the first `o`'s value and no name, so both bashes answer
    `set: x: invalid option name` and set nothing; the second `o` has no
    value, and `-Ze` is read as an option word (`_takes_value`).

    Reading a refused NAME as setting NOTHING is the fail-closed pick rather
    than bash to the letter: bash applies the names BEFORE the bad one and
    stops there, so `set -o pipefail -o foo` leaves pipefail on (rc 0, both
    bashes) -- but where the one it applied was errexit, the failing `set`
    exits the shell under it and nothing after it runs at all (`set -e -o
    foo`: rc 1 on 3.2.57, rc 2 on 5.2.21, nothing printed after). An unknown
    LETTER is not like that: bash validates a WORD's letters before applying
    that word, so `set -o errexit -Z` leaves errexit OFF (rc 0) -- but a name
    an earlier word applied stays, and `set -ox pipefail -Z` or
    `set -oo pipefail x` leaves pipefail ON and survives, read here as OFF:
    over-reports only. A value the guard cannot read (`$X`, `${X:-pipefail}`,
    a lifted `$(cmd)`) is a refused NAME too: with `X=foo`, both bashes
    answer `set -o $X -e` with `invalid option name`, leave errexit off and
    run what follows, so reading it ON would fail open -- the opposite pick
    from `_refused_name`, whose ON means the program runs and is reported."""
    words, at = list(words), 0
    while at < len(words):
        word, at = words[at], at + 1
        if word == "--" or word[:1] not in ("-", "+") or word[:2] == "++":
            return False
        if word[:2] == "--" or any(letter not in SET_OPTIONS for letter in word[1:]):
            return True
        for letter in word[1:]:
            if letter in VALUE_OPTIONS and _takes_value(words, at):
                if words[at] not in SET_OPTION_NAMES:
                    return True                 # `set -o foo`: no option of that name
                at += 1                         # `-o name`'s value, as `_errexit` takes it
    return False


def _errexit(words, state=False, name="errexit", invocation=False):
    """Whether these shell or `set` options leave `-e` on, from `state` -- or
    the option `-o name` sets, for `pipefail`, which no letter spells.

    One value per `o` LETTER, as bash counts them and `_rejected` reads them
    (#2559): the second `o` of `set -oo pipefail errexit` takes `errexit`.
    `invocation`: these words are a shell's COMMAND LINE -- a `shell:`
    template's (`seed`) or a child shell's (`flattened`, #2444) -- where
    `-O shopt` takes a value, which bash's `set` does not: it rejects `-O`.
    There an `o` takes the next word whatever it spells, where the builtin
    reads a NAME only from a word that is not an option (`_takes_value`).
    A `set` bash refuses whole turns NOTHING on (`_rejected`, #2443, #2560);
    a `+e` in it still reads as off, fail-closed either way.
    """
    words = list(words)
    rejected = not invocation and _rejected(words)
    at = 0
    while at < len(words):
        word, at = words[at], at + 1
        if word == "--" or word[:1] not in ("-", "+") or word[:2] == "++":
            break
        if word[:2] == "--":                    # bash's long options carry none
            continue
        turns_on = not (rejected and word[0] == "-")
        for letter in word[1:]:
            if letter == "e" and name == "errexit" and turns_on:
                state = word[0] == "-"
            elif letter == "o" and (invocation or _takes_value(words, at)):
                if at < len(words) and words[at] == name and turns_on:
                    state = word[0] == "-"
                at += 1                         # `-o name`'s value
            elif letter == "O" and invocation:
                at += 1                         # `bash -O extglob {0}`
    return state


def seed(shell):
    """(`-e`, `pipefail`) as a step whose `shell:` is `shell` starts (#2338).

    GitHub runs a step with no `shell:` as `bash -e {0}` (`sh -e {0}` where
    bash is missing) and `shell: sh` as `sh -e {0}`: `-e` and no pipefail.
    Only `shell: bash` adds it (`bash --noprofile --norc -eo pipefail {0}`),
    and a template (`bash {0}`, `bash -eo pipefail {0}`) runs with exactly
    the options it writes.
    """
    words = (shell or "").split()
    if len(words) < 2:
        return True, words == ["bash"]
    return _errexit(words[1:], invocation=True), _errexit(words[1:], False, "pipefail", True)
