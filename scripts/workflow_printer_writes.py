#!/usr/bin/env python3
"""How a printer's text is decoded: an `echo`'s escapes and a `printf`'s format, as a shell reads them.

Split out of `scripts/workflow_printers.py` at that module's size (700 of its 700 lines; #3013), byte
for byte, in two pieces and in their order: `_decoded`, which decodes an `echo`'s or a `printf`'s text
under ONE reading for `printed`, with the two tables it reads (`_ESCAPES`, `_OCTAL`); and what an
unspelled printer WRITES with every word as written (#2955) -- `_written`, `_formatted` and `_echoed`,
which render one text a shell family for the second walk, and their tables (`_CONVERSION`, `_ESCAPE`,
`_PLAIN`, `_COUNT`, `_KNOWN`, `_PAD`, `_LONG`, `_WRITERS`). `workflow_printers` imports every name
back under its own, so nothing that read `workflow_printers._decoded` or `workflow_printers._formatted`
moved; this module imports nothing from it, so the layers still run one way: the reader below it, the
printers above. It reads no command: which command prints, and what it hands a shell, is
`workflow_printers`' to say; this is how the text it names is decoded.

Stdlib only, like everything under it.
"""
import re

import shell_reader



# The table `_decoded` reads in EITHER mode: a backslash followed by one of these decodes to the
# byte shown. A trailing lone `\`, or one followed by anything else outside this table and the
# octal/`\c` rules `_decoded` reads separately, is unspelled (fail-closed): dash's `echo` knows no
# `\x`, bash's `-e` does (measured, b04).
_ESCAPES = {"\\": "\\", "a": "\a", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t", "v": "\v"}
_OCTAL = re.compile("[0-7]{1,3}")


def _decoded(text, fmt=False):
    """`text` with `_ESCAPES` and an octal escape decoded, or None where one outside those is in it
    -- unspelled, fail-closed. In `echo`/`%b` mode (`fmt` False, as both read octal, review C2): an
    octal escape is `\\0` plus up to three MORE digits (`\\0101` decodes whole, one byte); `\\c` ends
    the text there, dropping it and what follows. In a `printf` FORMAT (`fmt` True, review R-F3):
    `\\c` is kept LITERAL, two characters, and does not end the text; an octal escape is `\\` plus ONE
    to THREE digits counting a leading `0` (`\\0043` decodes `\\004`, leaving `3` as text; `\\163`
    decodes whole, both shells read a leading `1`-`7` as one too). Either mode: a decoded NUL is
    DROPPED, as the shell drops it from the script it reads (review R-F4), and a decoded value past
    0x7F is unspelled (the shell emits a raw byte this reader cannot hold, review M2/R-F3)."""
    out, at, end = [], 0, len(text)
    while at < end:
        char = text[at]
        if char != "\\":
            out.append(char)
            at += 1
            continue
        nxt = text[at + 1:at + 2]
        if nxt == "c":
            if not fmt:                     # `echo`/`%b`: ends the text here
                return "".join(out)
            out.append("\\c")               # a printf FORMAT: `\c` prints literally
            at += 2
            continue
        if nxt in _ESCAPES:
            out.append(_ESCAPES[nxt])
            at += 2
            continue
        octal = (_OCTAL.match(text, at + 1) if fmt and nxt in "01234567"
                 else _OCTAL.match(text, at + 2) if not fmt and nxt == "0" else None)
        if not octal:
            return None                      # `\x`, `\e`, `\u`, `\'`, a trailing lone `\`
        value = int(octal.group(), 8)
        if value > 0x7F:
            return None                      # a raw byte past ASCII: unspelled, fail-closed
        if value:                            # a decoded NUL is dropped, as the shell drops it
            out.append(chr(value))
        at = octal.end()
    return "".join(out)


# What an unspelled printer WRITES with every word as written (#2955), which the second walk weighs
# beside the ONE text `main` weighs. `_CONVERSION` is one conversion of a `printf` format: its
# flags, width, precision, C's length letters and the character that names it (none for `%%`).
# `_ESCAPE` is one backslash escape, and `_WRITERS` what each shell reads BEYOND `_decoded`'s table,
# which all read alike -- by family (for a bash: 5.2, 3.2, and 3.2 as macOS ships it; for a `sh`:
# dash; measured on bash 5.2.21, GNU's and Apple's 3.2.57, dash 0.5.12) and by where the text stands
# (a FORMAT, a `%b` word, an `echo`): `e` is `\e` and `E` `\E`; `x` a `\xHH`; `u` a `\uHHHH` or
# `\UHHHHHHHH`; `q` a `\"`, `\'` or `\?`; `o` an octal number with no `0` in front, which a FORMAT
# always reads. `letters` are the conversions it knows beyond C's (`_KNOWN`; `(` is 5.2's `%(…)T`)
# and `lengths` C's length letters, which bash skips and dash refuses: at any other character it
# prints no more. A text is rendered once a family, never decoded "as any shell might": a decoded
# quote can HIDE the command after it, and a space a width pads can MAKE one, so a reading no shell
# makes proves nothing. `_PLAIN` is a number, or none, that each reads alike (a `-` at most, no `0`
# in front, ASCII's digits, a machine word); `_COUNT` an `int` too: 3.2 dies of a `*` word past one.
_CONVERSION = re.compile(r"%(?:%|([-+ #0']*)(\*|\d+)?(?:\.(\*|-?\d*))?([hjlLtz]*)(.))", re.S | re.A)
_ESCAPE = re.compile(
    r"\\(?:([0-7]{1,4})|x([0-9A-Fa-f]{1,2})|u([0-9A-Fa-f]{1,4})|U([0-9A-Fa-f]{1,8})|(.))", re.S)
_PLAIN = re.compile(r"|0|-?[1-9]\d{0,17}", re.A).fullmatch
_COUNT = re.compile(r"|0|-?[1-9]\d{0,8}", re.A).fullmatch
_KNOWN, _PAD, _LONG = "sbcdiouxXeEfFgGaA", 256, 4096
_WRITERS = {
    "bash": ({"format": "eExuq", "b": "eExuo", "echo": "eExu", "letters": "qQn(", "lengths": "hjlLtz"},
             {"format": "eExq", "b": "eExo", "echo": "eEx", "letters": "qn", "lengths": "hjlLtz"},
             {"format": "eExq", "b": "eExo", "echo": "x", "letters": "qn", "lengths": "hjlLtz"}),
    "sh": ({"format": "e", "b": "eo", "echo": "eo", "letters": "", "lengths": ""},)}
_WRITERS["dash"] = _WRITERS["sh"]


def _written(text, place, kinds):
    """`text` as ONE family's printer decodes it at `place` (`_WRITERS`), to WEIGH and never to
    spell: `_ESCAPES`; an octal number -- one to three digits in a FORMAT, `\\0` and up to three
    more in a `%b` word or an `echo`, and there one with no `0` only where `kinds` has `o`, and
    each a BYTE (`\\543` is `\\143`, a `c`); the kinds it names. A NUL and a value no text holds are
    dropped. `\\c` outside a FORMAT ENDS the output: a NUL stands there, for the caller to cut at.
    Any other pair stays as written."""
    def one(found):
        octal, coded, char = found[1], found[2] or found[3] or found[4], found[5]
        if char is not None:
            if char == "c" and place != "format":
                return "\0"
            return _ESCAPES.get(char) or ("\x1b" if char in "eE" and char in kinds else
                                          char if char in "\"'?" and "q" in kinds else found[0])
        if octal:
            if place != "format" and octal[0] != "0" and "o" not in kinds:
                return found[0]
            digits = octal if place != "format" and octal[0] == "0" else octal[:3]
            value, rest = int(digits, 8) & 255, octal[len(digits):]
        elif ("x" if found[2] else "u") not in kinds:
            return found[0]
        else:
            value, rest = int(coded, 16), ""
        return (chr(value) if 0 < value < 0xD800 or 0xDFFF < value < 0x110000 else "") + rest
    return _ESCAPE.sub(one, text)


def _formatted(fmt, words, kinds):
    """What one family's `printf` WRITES for `fmt` and `words`, the format used again while words
    are left, or None where the guard does not follow it (`_apart` answers LOUD, as `unspelled`
    does past `_DEPTH`). Followed, and then to the character: text and escapes in the format;
    `%%`; `%s`; `%b` (decoded; a `\\c` ends the output); `%c` (one character); `%q` (quoted);
    `%d` `%i` `%u` of a `_PLAIN` number, `0` for a word that begins no number; a `-` and a width
    to `_PAD` on any but `%b`, a number's `0` and a precision on `%s`; a `*` takes a `_COUNT`
    word; a word holding a `$` is printed as it stands, a `%b`'s decoded. At a character the
    family does not know, and at a `%` with none after it, the output ENDS. NOT followed,
    because the shells differ or the text is not one this reads: any other flag, letter, number,
    width or precision; a `$` word or one outside ASCII cut or padded with blanks; a `$` word
    under `%c`, or none padded there; a `%q` of a `~` or of a character outside ASCII's
    printable ones; and a text past both `_LONG` characters and four times what was written (a
    format printed again for every few words multiplies)."""
    made, last, left = [], 0, words[::-1]
    out: list[str] = []

    def word():
        return left.pop() if left else ""

    while (at := fmt.find("%", last)) >= 0 and (found := _CONVERSION.match(fmt, at)):
        made.append((_written(fmt[last:at], "format", kinds["format"]), found))
        last = found.end()
    tail = _written(fmt[last:] if at < 0 else fmt[last:at], "format", kinds["format"])
    size, most = 0, max(_LONG, 4 * (len(fmt) + sum(map(len, words)) + len(words)))
    while True:
        start = len(out)
        for text, found in made:
            out.append(text)
            flags, width, precision, lengths, letter = found.groups()
            if letter is None:
                out.append("%")
                continue
            zero, odd = "0" in flags and letter in "diu", (precision or "")[:1] == "-"
            width, precision = (word() if part == "*" else part for part in (width, precision))
            cut, minus = precision is not None, "-" in flags + (width or "")[:1]
            if not _COUNT(width or "") or cut and not _COUNT(precision):    # read before the letter is
                return None
            if letter not in _KNOWN + kinds["letters"] or lengths.strip(kinds["lengths"]):
                return "".join(out)
            asis = shell_reader.dynamic(text := word(), shell_reader.has_substitution)
            if (odd or flags.strip("-0" if zero else "-") or letter not in "sbcdiuqQ"
                    or abs(int(width or 0)) > _PAD or cut and letter != "s"
                    or (width or cut) and (asis and (minus or not zero) or letter == "b" or not text.isascii())
                    or letter == "c" and (asis or width and not text or text[:1] > "~")
                    or not asis and (
                        letter in "diu" and not _PLAIN(text) and re.match(r"\s*[-+]?[\d'\"]", text, re.A)
                        or letter == "u" and text[:1] == "-" or letter in "qQ" and re.search("[^ -}]", text))):
                return None
            if letter == "b":
                text = _written(text, "b", kinds["b"])
            elif letter == "c":
                text = text[:1]
            elif letter in "qQ" and not asis:
                text = re.sub(r"[^\w%+./:=@#-]|^#", r"\\\g<0>", text) or "''"
            elif letter in "diu" and not (asis or text and _PLAIN(text)):
                text = "0"
            text, ended = text.split("\0")[0], "\0" in text
            text = text[:int(precision or 0)] if cut and precision[:1] != "-" else text
            pad = abs(int(width or 0))
            out.append(text if asis else text.ljust(pad) if minus else text.zfill(pad) if zero else text.rjust(pad))
            if ended:
                return "".join(out)
        out.append(tail)
        size += sum(map(len, out[start:]))
        if size > most:
            return None
        if at >= 0 or not left or not any(found[5] for _text, found in made):
            return "".join(out)


def _echoed(words, row, kinds):
    """An `echo`'s text under one row of `_ECHO` with each word as written: its option words off
    the front, its escapes decoded (`_written`) where that row decodes, as `printed` reads one."""
    pattern, decode, cap = row
    options = 0
    while options < len(words) and (cap is None or options < cap) and pattern.fullmatch(words[options]):
        options += 1
    for letter in "".join(words[:options]):
        decode = letter == "e" if letter in "eE" else decode
    text = " ".join(words[options:])
    return _written(text, "echo", kinds["echo"]).split("\0")[0] if decode else text
