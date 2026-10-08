# Changelog

## Unreleased — 5.2 Claude first-class host (#1344, family PR)

The Claude family's first-class-host PR under `docs/FAMILY-PR-GUARDRAILS.md`:
Claude already shipped its runner, probes, emit branch, registry row and both
guards, so this PR is the evidence a real `driver loop` gives, plus what that
evidence exposed.

- **Workflow reader reads a read-write descriptor's file where an interpreter holds it, as `main`
  reads `N<` (#2881, #2608).** `curl … -o tool` ⏎ `sh 3<> tool <&3` ran the download and read
  CLEAN: the reader read `N<> file` as a write alone, so a dup of N onto standard input (`sh 3<>
  tool 0<&3`, a move `<&3-`, a chain `4<&3 <&4`), a path to it (`sh /dev/fd/3 3<> tool`,
  `/proc/thread-self/fd/3`, `//dev/fd/3`, a climb `../../dev/fd/3`, `/dev/stdout` with `1<>`, a
  path in a value) or a child program (`sh -c 'sh <&3' 3<> tool`, `( sh <&3 ) 3<> tool`, `find
  /dev/null -exec sh /dev/fd/3 \; 3<> tool`) gave the shell nothing it reads. An interpreter -- a
  shell, `python3` and its kind, `eval`, `source` and `.`, the command a `find` runs behind
  `-exec`, `-execdir`, `-ok` or `-okdir` (read as the guard reads it for a use), or a command word
  the step's values decide (`SH=sh` ⏎ `$SH 3<> tool <&3`) but for a checksum tool, which the check
  side credits by its basename (`$X/sha256sum`) -- now reads every file `N<>` still holds open when
  its redirections end, on any descriptor, as `main` reads `N< file`. A dup, a move or an open of
  N's path -- `/dev/fd/N`, `/proc/self/fd/N` or `/proc/thread-self/fd/N`, and `/dev/stdin`,
  `/dev/stdout` or `/dev/stderr` for 0, 1 or 2, each past a run of slashes or a climb
  (`//dev/fd/N`, `../../dev/stdout`) -- carries what N holds to its target, and one whose source a
  value decides (`<&$FD`, `<"$P"`) carries every file held, fail-closed; a later redirection of N
  ends what N held, and only that (`sh 3<> tool </dev/fd/3 3<&-` and `FD=3` ⏎ `sh 3<> tool <&$FD
  3<&-` run the download). Any other command is credited with none of it, so no check is credited
  with a file it only holds: `sha256sum tool | sha256sum -c 3<> sums`, `sha256sum -c self 3<> sums
  <&3` and `X=/usr/bin` ⏎ `$X/sha256sum -c self 3<> sums` check the download against itself, and
  the use stays reported. On the round-3 seat's rows -- its own 989-row hunt and the 20,533 rows of
  the earlier seats' hunts and #2856's round-10 seat -- none goes CLEAN where `main`, `5e58b019`,
  `f5a74db5`, #2856's round 11 (`b7f53f19`) or round 2 reports and a shell runs the payload
  unverified, but for #2899 (158 cells, 32 rows, against `5e58b019`); #2856's own `<>` on standard
  input, which credited a check after fd 0 was redirected again or one that names its own list (56
  cells, 20 rows, against `main`; its round-11 B5), closes with its round 12, folded here, which
  moves its own cells here as there: on the round-3 seat's CZ rows 56 close and 22 over-report as
  `main` reads them, and on #2856's rows 35 close and 70 clear. Round 4's own numbers, against
  round 3: 1,280 cells close where a shell runs the payload (256 rows: a path of N, 830 in 166; a
  dup a value decides, 120 in 24; the shell a `find` runs, 330 in 66), and 100 over-report in 20
  rows, none run by a shell and each reported by `main` as `N<`: a zero-padded `/dev/fd/03`, which
  the kernel resolves to no descriptor (50, 10); `find -ok`, which asks before it runs and is
  answered no (30, 6); and `sh -s /dev/fd/4 3<> tool 4</dev/fd/3 3<&-`, where the shell reads its
  input, not the operand (20, 4). At round 4's head, the fold's CZ rows counted, 1,336 close and
  122 over-report. The price below counts each cell where the head reports, the earlier tree reads
  CLEAN and no shell runs the payload, in the first of these classes it meets: a check (`sum -c` or
  `sum --check`) no longer credited with a file it holds; under `sh`, a row bash runs and dash does
  not (dash's limits: a move, then a leading-zero descriptor, then `source`, then a descriptor past
  9); a zero-padded `/dev/fd/03`; `find -ok`; `sh -s` given a descriptor path; `xargs` given the
  file on its input; and the rest, a shell that holds the file `N<>` opened and reads nothing of
  it, as `main` reads `sh 3< tool`. Against round 2 on the round-2 seat's four hunts (2,556 rows),
  757 cells in 270 rows: a check, 288 in 138; dash's `source`, 66 in 33, and a descriptor past 9,
  56 in 28; `sh -s`, 5 in 1; and a shell holding the file, 342 in 70. And where a shell runs a
  download that a pinned check verifies first, 277 cells in 101 rows are reported (among them L11
  and L12), as `main` reports them, fail-closed. Against `main`, `5e58b019`, `f5a74db5` and #2856's
  round 11 alike on those hunts, 7,078 cells close where a shell runs the payload (1,820 rows), and
  2,687 over-report in 1,142 rows: dash's limits -- a move, 706 in 353; a leading-zero descriptor,
  752 in 376; `source`, 126 in 63; a descriptor past 9, 426 in 213 -- then a zero-padded
  `/dev/fd/03`, 100 in 20; `sh -s`, 20 in 4; `xargs`, 5 in 1; and a shell holding the file, 552 in
  112. Round 5, on the round-4 seat's 956-row hunt and its 22-row probe 0, against round 4's head:
  521 cells close where a shell runs the payload unverified (117 rows: `/dev/stdout` or
  `/dev/stderr` as the path of a held fd 1 or 2, 185 in 37; a climb, 240 in 48; a checksum tool
  named through a value, 96 in 32), and 18 over-report in 6 rows, each a check (`$X/sha256sum -c
  3<> sums 0<&3`) that reads its `N<>` file through a dup onto standard input, as `main` and the
  literal `sha256sum` read it -- 9 cells where the pinned check verifies the download first, and 9
  where nothing runs. On every row set of both seats, no cell goes CLEAN where `main` or a
  reference tree reports and a shell runs the payload unverified, but #2899 and S08n, whose marks
  vary from run to run (#2911), as at round 4. Named open, as ruled, though `main` reports its
  `N<` twin: a symlink the step makes to a descriptor's path, or a relative path the step's own
  `cd` makes resolve to one, which the reader reads as the file it names (`ln -s /dev/fd/3 fd3`
  ⏎ `sh 3<> tool <fd3 3<&-`; `cd /dev` ⏎ `sh 3<> /tmp/tool <fd/3 3<&-`, the download at
  `/tmp/tool`; #2919). Still open, as on `main`: dash's two-digit `N<>`, which dash reads as the
  word `N` and `<>` on standard input, so `cat - 10<> tool | sh` runs the file under `sh`
  (#2903); `cat 3<> tool <&3 | sh` -- a `cat` piped into a shell is a use only where its words
  name the file, so `cat < tool | sh` reads CLEAN on `main` too (#2884); a compound's redirect
  or pipe (`{ curl …; } 3<> tool >&3` ⏎ `sh tool`, #2883); a function call's redirect (`f() {
  sh; }; f < tool`, #2888); a check credited with a file it holds by `N<` (#2886); and one
  credited with the sums on its standard input when it reads something else (`sha256sum -c self
  < sums`, #2908).
- **Workflow reader: a line ending in `|` continues, a command word's `${X:-bash -s}` is read
  whole, and `<>` opens its descriptor (#2756, #2731, #2657; #2733, #2608).** A line ending in
  `|` continues on the next (`curl … |` ⏎ `sh` ran the pipeline and read CLEAN, behind `eval`
  and in a printed or heredoc text too). A command word that is an unquoted `${X:-bash -s}` is
  read as bash reads it, expanded whole and then split at a blank no quote or backslash covers,
  so a shell default's words run as that shell (`${X:-bash -s} <<'EOF'` and `curl … | ${SH:-bash
  -s}` ran the download and read CLEAN). The whole word is read as bash expands it with its name
  unset: the default, a literal glued after the `}` joining its last word (`${X:-/usr/bin/env
  s}h` is `/usr/bin/env sh`; none bash would glob) -- a glued `$(…)` too, which keeps the word
  dynamic (`${X:-sh -c}$(echo) '…'`) -- split at a space, a tab or a newline, each word keeping
  what the reader marked in it, found in one pass over the word -- a lifted `$(…)` stays dynamic
  behind a wrapper, and a `<(…)` a file. A word bash may expand to nothing -- `${X:+W}` and
  `${X+W}`; `${X-W}` and `${X=W}`, empty where the name is set empty; and `${X#W}`, `${X##W}`,
  `${X%W}`, `${X%%W}`, `${X/p/W}`, `${X//p/W}` and a case change (`${X^^W}`, `${X,W}`), whose W
  is a pattern -- of a name, an indirection (`${!X…}`), an element (`${X[0]…}`), a positional
  parameter, `$@` or `$*`, `$!` with no background job, or `$-`, empty under dash with no
  options, is read both ways, as W and as the word after it -- the literal glued after its `}`,
  or nothing -- and the guard reports where either half runs, ranking neither (the round-13
  ruling: the union): it reads a job with W, as `main` reads it, and where a command word had
  both halves, reads it again with that word expanded to nothing (`shell_command.folds`), so
  `curl … | ${X:+/usr/bin/env true} sh` and `${X:+/usr/bin/env true} sh -c '…'` report the `sh`
  the empty half runs, `X=1` ⏎ `${X:+/usr/bin/env sh -c} '…'` the W that runs where `X` is set,
  and a check is credited only in the reading that runs it (`${X:+/usr/bin/env sha256sum -c
  sums} true` ⏎ `sh tool` reports, where `X` is unset). The two readings are two of a step's
  2^k: every word of two halves read as its W, then every one as nothing, so a payload that only
  a mixed reading runs -- the fetch's W and a later word read empty, `X=1` ⏎ `${X:+curl -fsSLo
  t.sh …}` ⏎ `${Y:+/usr/bin/env true} sh t.sh` -- reads CLEAN, as on `main` (#2929), but where
  the two halves conflict (below). Two halves the guard may each report that run apart -- two
  among a shell's kind, a fetcher and a word it does not follow, but that word in front of a
  shell's kind -- are a command it cannot read (`${X:+curl -fsSL …} sh x | sh` runs the download
  where `X` is set). `$0` and `$-` are never unset, so `${0+W}` is always its W and `${--W}`
  never is; and a pattern's or a case change's other half is the name's own value, which no half
  names (#2899). No step's text decides a half: round 12 read W where the step set the name
  anywhere in its text, which took a set after the use, in a subshell, a dead branch, a string,
  a comment or a heredoc, and missed `set x`, `eval 'X=1'` and the shell's own variables. A
  default whose first word names a command the reader knows -- a shell, a wrapper, a foreign
  interpreter, a fetcher, by path too -- is that command, as `main` read the word by its
  basename (`${X:-/usr/bin/env sh -c} '…'`, `${X:-/usr/bin/curl -fsSL} URL | sh`,
  `${X:-/usr/bin/env $(echo sh) -c} '…'`); where no default reads -- a `$NAME` or a nested
  default in it, or a parameter that is no NAME -- `main`'s split words stay when their first
  names such a command by its basename (`${X:-$HOME/bin/env sh -c} '…'`, `${1:-/bin/sh -c}
  '…'`), the default's `}` off their last word at its first `}` and a word of it alone dropped,
  so a default ending in its program names it (`curl … | ${X:-$HOME/bin/env sh}`,
  `${1:-/usr/bin/env s}h <<'EOF'`, `D=/bin` ⏎ `${X:-$D/sh tool}`) -- but a word `main` reads as
  a pattern (`/usr/bin/ba}[s]h`), and `${#:-…}`, `${?:-…}`, `${$:-…}` and `${1:=…}`, which bash
  never expands or refuses, keep `main`'s words (not `$-`, empty under dash with no options, nor
  `$0`, empty in a `-c` text run with an empty `$0`; an indirection, `${!Y:-W}`, is read as a
  name is) -- and the whole word otherwise, as round 9 read it (`RUN='sh tool'` ⏎ `${RUN:-cat
  x}`, which the step's own values resolve, and `${X:-/bin/[s]h -s}`). Rounds 6 to 9 read CLEAN
  721 cells in 145 of the round-9 seat's rows that `main` and the base report, which round 10
  closed; round 10 another 657 in 133 of the round-10 seat's, which round 11 closed (180 of
  them, in 36 rows, a lifted `$(…)` round 10 read as a plain word); and round 11 another 843 in
  175 of the round-11 seat's that rounds 9 and 10 report (`main`'s split words kept the
  default's `}`) and 696 in 152 that round 10 reports (`${X:+W}`, `${X#W}`; 801 in 173 against
  round 9), which round 12 closed; and round 12 read CLEAN, of the round-12 seat's hunts 45-48,
  a default of `$-`, `$0` or an indirection (46 cells in 16 rows that round 10 reports), the
  spellings it did not read as expanding to nothing (110 in 38), the alternate where a set
  elsewhere in the step's text left the name unset (832 in 168), the next word where it missed a
  set (10 in 2 that `main` reports) and a checker naming its list (65 in 22 that `main`
  reports), all of which this round closes, a parent running the payload -- 1,456 cells in 335
  rows against round 12, none of round 12's going CLEAN. On the round-12 seat's 17,810 rows (the
  15,937 and hunts 33-48, its 12 rows whose reading changes from parse to parse aside), none
  goes CLEAN where `main`, either base or rounds 9 to 11 report and a parent runs the payload
  but #2899's (158 in 32 against round 9, and four of hunt 47, below) and #2906's two of hunt
  45; and on the #2885 round-3 kit's 989 own rows this round reads as round 12. Any other word
  is read as it always was, its default holding no blank, so `cat tool | "${SH:-bash}"` and
  `SH=1` ⏎ `"${SH:+sh}" tool` run the shell they name, as on `main`, and `${X:-"sh -c"}`,
  `${X:-sh\ -c}` and `"${SH:- bash}"` name none -- unless a bare blank stands beside the quoted
  one, as the whole word is read dequoted (below). `N<> file` opens the file on descriptor N for
  reading and writing: on 0 it redirects standard input as `<` does, so `bash -s <<'EOF'
  <>/dev/null` no longer credits a check no shell reads, and a check is credited with the file
  `0<>` opens only where fd 0 still holds it when the checker runs and the checker reads its
  standard input -- no list but `-`, `/dev/stdin` or `/dev/fd/0`, a word of digits an option's
  only right after `-a` or `--algorithm`, and every word past `--` an operand (`sha256sum -c 0<>
  sums 1`, `-c -- -x 0<> sums`) -- and reads `0<>` as `main` does, a write, otherwise
  (`sha256sum -c 0<> sums < self`, `-c <> sums 0< self`, `-c 4< self 0<> sums <&4`, `-c self 0<>
  sums`: 56 cells in 20 of the #2885 round-3 seat's CZ rows read CLEAN where `main` reports and
  the unverified download runs; `sha256sum -c <> sums` ⏎ `sh tool`, CK010-CK012 and CK22h, stays
  credited); on any other descriptor a later `>&N` or `1>&N` writes to it, so `curl … 3<> tool
  >&3` ⏎ `sh tool` reports (`main` read `3<` and a `> tool` the dup overrides: 32 rows, every
  shell running the payload), and with no dup nothing lands in it, which `main` and the base
  reported (`curl … 2<> tool` ⏎ `sh tool`, `9<>`, `10<>`, and `>/dev/fd/3 3<> tool`: 65 cells of
  the round-8 seat's rows). `&&` at a line's end and `${X:-bash} -s` read as they did. The whole
  word is the command word's alone (round 8, the coordinator's ruling): the reader keeps a
  `${…}` whole only where it starts a command -- a stage's first word past its keywords and
  assignments, no `case` subject, holding no newline or operator -- and every other word holding
  one is the words `main` split it into, so a download destination and its use, `xargs`'s input,
  a carrier, a value and a redirect's target all meet as on `main`, and every statement and
  stage is `main`'s. A program text that spells a mark the reader puts in its text
  (U+E000-U+E004) is read as `main` reads it, its command word too, and each text is its own:
  the step's, and each it hands a shell (`bash -c`, `eval`, a heredoc), so an inner text that
  spells none is still read whole. `$$` is bash's PID, read in the splitter as the pair before
  anything the second `$` could open, so `$${ | sh` and `${a:-$${b} x; sh tool; echo }` keep
  their pipe and their use; and only a space or a tab no quote covers is a blank, not `\v`, `\f`
  or a Unicode space -- to the reader's scan, and in a default's words, which bash splits at a
  newline too. On the round-8 seat's 13,052 rows, against the base (#2855's head `7fa1e0a8`,
  this PR's base since round 10's fold): 2,467 cells close where a shell runs the payload (511
  rows), none goes CLEAN where the base or `main` reports and a shell runs it, and 231 clear
  where the base reported and nothing runs (55 rows: the two-line check gate, `<>`, `$$`) --
  against `ca232d12`, the base before that fold, 2,481 close (515 rows) and the same 231 clear;
  and on 1,119 rows of my own of `N<>` and its dups, 302 close, none opens, and 240 clear. On
  the round-9 seat's 14,904 rows, none goes CLEAN where `main`, the base or round 9 reports and
  a shell runs it; against round 9, on its seat's hunts 18-23, 909 cells close (183 rows: the
  721 above, and 188 that `main` reads CLEAN too, `cat tool | ${X:-/usr/bin/env sh}`) and 45
  clear (9 rows: `${V:-python3 -m json.tool} <<'EOF'`, and `${X:+bash -s}`, `${X+bash -s}`,
  `${X#bash -s}` and `${X/x/bash -s}` with `X` unset). On the round-10 seat's 15,937 rows, none
  goes CLEAN where `main`, the base or round 10 reports and a shell runs it, nor where round 9
  does but #2899's (158 cells, 32 rows); against round 10, 1,117 cells close (225 rows: the 657
  above, 425 that `main` reads CLEAN too, and 35 in 7 of #2905's that the default's `}` and a
  glued `$(…)` close) and 100 clear (20 rows: a default holding a Unicode or vertical space,
  which bash does not split at, 30 in 6; `${X:+…}`, `${X+…}`, `${X#…}` and `${X/x/…}` with `X`
  unset, 70 in 14). Still CLEAN, as on `main`, where rounds 6 and 7 read them whole -- the
  ruling's re-opens, 1,400 cells of the round-6 head's (305 rows) and 1,759 of the round-7
  head's (396), each row in the first of these it meets: a step that spells a reader mark (`echo
  <U+E004>` ⏎ `curl … | ${SH:-bash -s}`; 710 cells and 151 rows of round 6's, 564 and 120 of
  round 7's), a `${…}` spanning a line (`-o ${D:-tool` ⏎ `}`, `${X:-bash` ⏎ `-s}`; 500 and 108,
  676 and 154), a dup of a `<>` descriptor onto fd 0 (`sh 3<> tool <&3`; 15 and 3 of round 6's),
  a function body on its header's line (`f() { ${RUN:-sh tool}; }`; 16 and 4 each) or a command
  word after a leading redirect (`2>/dev/null ${X:-bash -s} <<'EOF'`; 45 and 9 each; #2907), a
  `for` list or a `case` subject (h21, h22; 10 and 2 each), an assignment `NAME=` whose value
  reaches, before a blank or `;`, a `${` holding a blank or newline ahead of its first `}`
  (`CMD=${CMD:-sh tool}; $CMD`, `F=${D:-"tool" x}` ⏎ `sh $F`; 20 and 4, 349 and 78), a `${…}`
  holding a blank inside double quotes on one line, or a default opening with `"` (`> ${D:-tool
  }` ⏎ `sh "${D:-tool }"`; 21 and 9, 27 and 11), and every other row: an operand or destination
  whose default holds a blank (`sh ${F:-tool }`; 63 and 15, 72 and 18). Open on `main` too, and
  left to their own fix: a nested default (`${X:-${Y:-bash} -s}`), a braced partial word
  (`${X:-bash -s}{,}`), `coproc` (#2894), a pipe into a compound command (#2896), a dup of a
  `<>` descriptor onto fd 0 in the same command (`sh 3<> tool <&3`) or read by a path (`sh
  /dev/fd/3 3<> tool`) and a group's redirect (`{ curl …; } 3<> tool >&3`), filed as #2881; the
  write side of `<>` (`curl … 0<> tool >&0` ⏎ `sh tool`, `>&3-`, `exec {fd}<>`; #2898); an
  expansion that decides a default's command or an option (`${X:-env $E sh -c}`,
  `${X:-${Y:-/usr/bin/env} sh -c}`, `${X:-sh $F -c}`; 80 cells, 16 rows of the round-10 seat's
  -- #2905's 115 and 23, but 25 in 5 the default's `}` closed and 10 in 2 a glued `$(…)` -- and
  45, 9 of the round-11 seat's -- nn-k and nn-w of hunt 33 (`${X:-$E env curl}`), K16 of hunt 35
  (`${X:-sh -}${Y:-c}`), and F1, F2, no-fw, no-p2, no-pg and no-pn of hunt 37 (`${X:-$(echo env)
  sh -c}`) -- or 85, 17 with hunt 34's W14 and W15, a nested default (`${X:-${Y:-/usr/bin/env
  sh}}`); #2905), `${1:-env sh} tool` and `${1:-sh -c '…'}`, a positional parameter's default
  whose first word names its command by no path, read whole as a command the guard does not
  follow (20 / 4 at this head; the seat's 20 / 4 at round 11: n1-f, n1-k and n1-w of hunt 33,
  and Q10 of hunt 41), an `IFS` the step sets (10, 2), a default of blanks alone (10, 2), a
  one-word alternate (`${X:+true} sh -c '…'`, a `$` word `main` reads in front of a command it
  does not know; 5, 1), a pattern in a default's command word (`${X:-/bin/s[h] -c}`; 85, 17, and
  r1 and r3 of the round-12 seat's hunt 45, `curl … | ${X:-$HOME/bin/env /bin/s[h]}`, 10 and 2
  that rounds 9 and 10 report; #2906), and, `main`'s documented gap and #2601's price, a foreign
  interpreter's program text, its default or written out (`${X:-python3 -c} 'import os;
  os.system("curl … | sh")'`, `perl -e`, `node -e`; 184, 37), as a fetch inside `python3 -c`
  needs another language entirely; and a whole default read where the step sets its name, whose
  value bash runs instead (`RUN='sh tool'` ⏎ `${RUN:-bash -s}`, as `main` reads `${RUN:-bash}`
  since #2337; #2899) -- its wrappers' half rounds 6 to 9 reported, the step's values reading
  their whole word, and round 10 reads it as `main` does: 45 cells in 9 rows of my own (`RUN='sh
  tool'` ⏎ `${RUN:-/usr/bin/env true}`, `env -S true`, `timeout 9 true`, `python3 -V`, and
  `RUN='sh -s'` ⏎ `curl … | ${RUN:-/usr/bin/env cat}`) and 158 in 32 of the round-10 seat's --
  and a pattern taken off or replaced, `#`, `%` and `/`, whose other half is the name's own
  value (`X=sh` ⏎ `curl … | ${X#a b}`, `${X%%a b}`, `${X/a b/c}` and `${X#a b} -c '…'`:
  seth1-seth4 of the round-12 seat's hunt 47, 18 cells in 4 rows that rounds 9 to 11 report and
  `main` reads CLEAN; #2899). New fail-closed over-reports against the base, none run by a shell
  (206 cells in 57 of the round-8 seat's rows -- 232 in 63 against `ca232d12` -- and 28 in 14 of
  the `N<>` rows): the continuation's -- a CRLF after `|`, `|&` ⏎ `sh` under dash, `|` ⏎ `$$ sh`
  (26 cells, 7 rows); a `<>` that bash or dash does not read as standard input -- `bash -s
  <>tool <<'EOF'` and `bash -s 0<> tool <<'EOF'` (the heredoc is the input), `source /dev/stdin
  <> tool` and `bash -s <<'EOF' <>${N:-/dev/null }` under `sh`, `sh {v}<> tool` (bash opens a
  new descriptor), `sh <> tool 0<&-` and `sh 0<> tool 0<&-`, and `sh 00<> tool` under dash (30,
  8) -- and a descriptor past 9 under dash, which opens none (`curl … 10<> tool >&10` ⏎ `sh
  tool`; 28, 14); and the whole word's (150, 42), all but two rows `main`'s own reading of the
  default written out: a default dash reads otherwise (`${X:-$'bash' -s}`, `$'-s'` and `$'-c'`,
  which dash keeps with their `$`, and `${RUN:-source ./tool}`; 20, 10), an `IFS` the step sets
  (5, 1), a name the step assigns (`RUN=cat` ⏎ `${RUN:-sh tool}`; 15, 3), `$$` in the default
  (`${X:-bash $$ -s}`; 40, 8), `sh -c "… \$0"` or a backquote in the default (20, 4), `curl … |
  ! ${SH:-bash -s}`, which no shell parses (5, 1), and an inner program behind a line that stops
  `-e` shells first (`X=1` ⏎ `bash -c '… | ${SH:-bash -s}'`; 45, 15) -- the two new beside
  `main`'s reading are `${X:-$$ bash -s} <<'EOF'` and `${X:-sh -c "echo \`id\`"} <<'EOF'`. On
  the round-9 seat's hunts 18-23, against the base, 643 cells in 161 rows, none run by a shell:
  a download fed to a whole default that names no shell (`curl … | ${V:-jq -r .}`, `${V:-less
  -R} <<< "$(curl …)"`; 245, 49), the guard's catch-all for a command word it does not follow --
  or, for `python3`, its reading of the interpreter -- where `main` reads all but `python3 -m
  json.tool` and `tar -tz` CLEAN written out; a quoted or escaped blank beside a bare one, the
  whole word read dequoted (`${X:-"" bash -s}`, `${X:-\ bash -s}`, `${X:-"bash -s" }`; 170, 40
  -- bash 3.2 runs `${X:-"" bash -s}` and `${X:-'' bash -s}`); `$'…'` and `$"…"` under dash, and
  inside a single-quoted `eval` or `bash -c` text (38, 16); `| !` at more positions (55, 11);
  `${X:?bash -s}`, which stops the shell with `X` unset (10, 2); `${X:-/bin/sh* -s}` (10, 2); a
  here-string into a wrapper's default under dash (`${X:-/usr/bin/env bash} <<< "$(curl …)"`;
  32, 16); `/usr/bin/xargs` (15, 3) and `/usr/bin/sudo`, which the harness's sudo refuses and a
  hosted runner's runs (30, 6); `>&03` and `10<>` under dash (24, 12); `sh 0<> tool 0<&-`, `sh
  00<> tool` and `sh 0<> tool 3<> /dev/null 0<&3`, a dup onto fd 0 after its read (12, 3); and
  `bash <(${X:-/usr/bin/wget -qO-} …)` under dash (2, 1). Round 10's own, against round 9, are
  21 cells in 6 of the round-9 seat's rows: `/usr/bin/sudo` (15, 3) and `bash <(…)` under dash
  (6, 3). On the round-10 seat's hunts 24-32, against the base, 126 cells in 35 rows, none run
  by a shell: a quoted or escaped blank beside a bare one (`${X:-"/usr/bin/env sh" -c}`; 56,
  13), `xargs` with no input (25, 5), `bash <(…)` under dash (22, 11), a tilde in a later word
  (`${X:-./env ~/bin/nice sh -c}`; 10, 2), a name the step sets (10, 2), `exec -a` under dash
  (2, 1) and `function f { … }` under dash with `-e` (1, 1); and against round 10, 8 cells in 4
  rows, `main`'s own reading of an array element under dash (`${X[0]:-/usr/bin/env sh -c}`),
  which dash rejects. On the round-11 seat's hunts 33-44 (its 11 rows whose reading changes from
  parse to parse aside, and S08n, which joins them: a lifted `$(…)` read as an option's letters,
  `main`'s own, #2911), against the base, 360 cells in 120 rows, none run by a shell: a default
  holding a Unicode or control character, which bash does not split at (`${X:-bash<U+00A0>-s
  x}`; 110, 22), a pattern substitution under dash, which rejects it (`${X/a/env true} sh -c
  '…'`; 96, 48), a process substitution (`${X:-env bash}<(curl …)`, glued on, which runs a
  `bash/dev/fd/63` no system has, and `${X:-env bash -s <(curl …)}` under dash, which has no
  `<(…)`; 40, 11), `${X:?env true} sh`, which stops the shell (40, 8), an array element under
  dash (`${X[0]:-/usr/bin/env sh} tool`; 28, 14), a here-string under dash (`${1:-/usr/bin/env
  bash} <<< "$(curl …)"`; 20, 10), a quoted empty word beside a blank (4, 2), a heredoc inside
  `$(…)` under dash (2, 1), and `${X:-env s}$Y`, an `IFS` the step sets, `/usr/bin/tee -a log`
  and `env -i sh` (5, 1 each); against round 10, 76 cells in 29 of those rows -- the pattern
  substitution (32, 16), a brace or glob glued after the `}` (`${X:-/usr/bin/env sh -s}{,}`,
  `}?`; 12, 3), the array element (10, 5), the process substitution (10, 2), a carriage return
  in the default (10, 2) and the here-string (2, 1) -- and against round 11, 143 cells in 70:
  the pattern substitution (96, 48), the array element (28, 14), the here-string (14, 7) and
  `${X:-env bash}<(…)` (5, 1); and on the CZ rows, against round 11, 22 cells in 10, as `main`
  reads them: a later redirection, dup or close of fd 0 that fails the check round 11 credited
  (`-c 0<> sums 0<&-`, `-c 0<> sums < /dev/null`, `-c 0<> sums 0<&4 4< self`; 18, 6), and a
  here-string or `00<>` that dash refuses or reads otherwise (4, 4). On the round-12 seat's
  rows, against round 12 -- the union's price, beside #2912's below; the #2885 round-3 kit's
  20,533 regression rows hold ten of these rows and no other -- 474 cells in 134 rows, none run
  by a shell, each a half no parent runs: the next word where the step sets the name and the
  alternate runs nothing (`X=1` ⏎ `${X:+/usr/bin/env true} sh -c '…'`, the ruling's
  `SET_RUNS_NOTHING`; `set -- 1`, `X=$(true)`, `read X < /dev/null`; 172, 38); W where nothing
  sets the name -- a positional parameter (`${1:+/usr/bin/env sh} -c '…'`, `${@+…}`, `${10:+…}`;
  77, 17), a name (`${X:+bash -s} <<'EOF'`, `main`'s reading; 55, 11) and one only bash sets
  (`${BASH:+…}` under dash; 12, 6); `$-` holding bash's options (`${-:-/usr/bin/env sh}`,
  `${-:+…}`, `${-#…}`; 52, 13); `$0` where it is not empty (`${0:+…}`, `${0=…}`; 10, 2); an
  indirection, an element or a case change under dash, which rejects it (86, 43); and a checker
  naming its list where the list fails the check under `-e` (`sha256sum -c 0<> sums 1`; 10, 4,
  which `main` reports). `SH=1` ⏎ `bash -c '"${SH:+sh}" tool'` reports again, as on `main` and
  the base (their over-report: the `-c` shell sees no `SH`), which round 8's kept test had
  cleared. The cost, measured on the forge against the base `ca232d12`: 1.04-1.07x for a
  pipeline or `||` list of unterminated `${` to 8,000 stages, where round 8 grew to 143x -- the
  scan runs only at a command word now, and ends with its stage; 0.98-1.02x for an unterminated
  `${` per line, statement, `&&`, `&`, subshell, quote or nested default and for the single
  unterminated line, where round 8 paid 1.5-7.6x; 0.04-0.12x for unterminated `echo ${x |`
  lines, one statement by the continuation; 0.98-1.07x for the closed and quoted cases and on
  rounds 3-7's shapes. At a command word the whole default is one shlex token, built a character
  at a time, which `main` pays for the double-quoted spelling of the same default (`"${X:-…}"`:
  0.21 s at 8,000 words and 8.05 s at 64,000 on `main`, the head and the base alike; #2912):
  against the base's reading, `main`'s split words, the unquoted spelling costs 1.45x at 1,000
  plain words, 1.83x at 8,000 and 6.87x at 64,000, 1.11x to 6.50x for case C's words
  (`${X:-$HOME/bin/env a0 …}`) and 1.23x at 1,000 to 1.84x at 128,000 for a glued suffix, as the
  round-11 seat measured it -- `main`'s quoted-word cost on the unquoted spelling. A default's
  words take their marks in one pass, where round 11 tested every mark of the whole word against
  each (4.6x the base at 1,000 `$(…)` words, 15.7x at 4,000; the round-11 verdict's B3), so such
  a default costs that shlex token alone -- at 16,000, 6.9x the base for `$(…)` words, 7.5x for
  backquotes, 7.2x for `<(…)`, 5.5x for the three mixed and 2.3x for a glued suffix, each within
  1.04-1.15x of `main`'s own double-quoted spelling (#2912). Both halves read no step text,
  where round 12 scanned it for the names a step sets (7.24x the base at 16,000 unclosed `x[`
  before a `${X:+…}` command word; 0.99-1.11x now), and a checker's reads on fd 0 are dropped by
  a set (round 12: 2.48x at 64,000 `0<>` on one checker; 0.59-0.69x now). The union reads a job
  again where a command word has both halves: at most twice the folds of one reading -- two, or
  four with an `Unsure` statement -- a factor that does not grow with the step (on the forge,
  interleaved, median of 3: 1.94-2.02x one reading for n words, n `$(…)` or a W of 64,000
  characters in the word; n uses of `${X:+/usr/bin/env true} sh -c 'echo'` after `X=1` cost
  3.2-3.3x the base, which reads `true` there; and on the round-12 seat's hunts 33-48, 1.30x
  round 12 and 1.76x `main` in all, and on hunts 42, 43 and 46, the ones dense in such words,
  1.58-1.74x the ranked draft's one reading (2.29-2.51x W's fold alone); the round-13 seat's n
  lines of one such word each cost 2.83-2.98x one reading from 250 to 2,000 lines, flat against
  `main`).
- **Codex model profiles move to GPT-6 (#2872).** Pinned role defaults now use `gpt-6-luna` or
  `gpt-6-sol`; set `PANOPTICON_MODEL_<ROLE>` to pin another installed model.
- **Workflow guard reads a function header in the spellings bash takes at a statement's head
  (#2664, #2608; #2785).** `f(){ curl … | sh; }` ⏎ `f`, `f ( ) { … }`, and a header after
  `then`, `do` or an opened `{` ran the pipe under bash 5.2.21, 3.2.57 and dash and read CLEAN:
  the reader knew a header only as `f()` at a statement's start, so `f(){` was one command word,
  `f ( )` a subshell, and `then f() {` the command `f` -- the body's first command on the
  header's line became that header's argument, and the call ran a function the guard had no body
  for. The splitter now reads `()` and `( )` after a name wherever bash does, ends a group's `{`
  before a header on its line as its own statement, and keeps `function NAME ()` to the name.
  Three readings move with it, each to bash's: a block nested in a one-line function's body
  inside a forked group no longer closes that body, a group's `{` before a header is the
  group's, and `function f ( )` defines `f`. 60 cells go CLEAN -> REPORT with no shell running
  the payload -- a function defined in one of the new spellings and never called, defined in a
  branch that does not run, backgrounded, after `unset -f` or redefined to `:` -- each as `main`
  already reports the `f() {` spelling, fail-closed. Still CLEAN while the shells run them
  (limits, named in the PR): a body that is a `case`, a function defined inside a function body
  or a `case` arm or a `( … )` subshell, `time f() {`, `function g { f() {`, and the names
  `a.b`, `a:b` and `1f`. Two fix rounds closed what the seats found. A negated group holding a
  header (`! { f() { CHECK; }; f; }` ⏎ USE) had its `!` stranded on the `{`, so the check read
  as gated: the `!` is now carried onto every statement the group holds, as bash runs a negated
  compound with errexit off, placed past the keywords that open the statement so `then`, `do`,
  `case` and an arm are still read first -- which also closes the own-line `! {` ⏎ `CHECK` ⏎ `}`
  form `main` missed; `! !` is read as one negation (bash XORs: fail-closed), and a
  short-circuit inside a negated group, a call in a branch that does not run or in a child, a
  call after `unset -f` and a prefix assignment are read under the `!` too (214 hunt cells and
  36 harness cells on the round-2 rows, 110 more on the round-3 families: 324 fail-closed cells
  in all). A called function's assignment (`T=/dev/null; f(){ :; T=tool; }; f; sh "$T"`) never
  reached the use, `main` reporting it only because the misread header made it the step's own
  statement; carrying the body's value out surely read past what the shells do (a `return` the
  body takes, a wrapper that runs no function, a later redefinition, a stand-in, a `declare -g`
  bash 3.2 and dash lack), so a call now adds what the body may assign as UNSURE candidates and
  keeps the caller's own (`scripts/workflow_called.py`; every definition before the call, and
  the functions the body calls, eight deep; `local` dies with the call, a subshell body reaches
  nothing (one whose first command opens with a `{` word too: `f() ( { T=x; } )`, `f() ( echo {
  ; T=x )`), and a call the step backgrounds (`f &`) carries nothing back -- a one-line `( f )`
  still does, fail-closed; `time` -- one `-p`, then one `--`, before a group, a `!`, an
  assignment or an `if` -- and `eval` (one `--`) run the function, as bash 5.2.21 reads them
  (bash 3.2.57 runs neither `time --` spelling, dash no `time` call at all: read as calls,
  fail-closed); the arm of a one-line `case` is stepped past first; a function named like a
  wrapper, `sudo() { … }; sudo x`, is the call bash makes of it, where `env f` with no `env`
  function runs none; a body's call in a list it backgrounds, `g() { f & wait; }` or `g() { f &&
  : & wait; }`, carries nothing, as at the top level; and a call site carries its bodies eight
  times a step -- `static_values` rebuilds the table at each statement that reads it, so a site
  is visited at each rebuild after it, and a memo of the carries, keyed on the state of the
  names they read or set, grew past `main` where the step assigns the words a body spells (round
  10) -- walking only the statements that may write, and every one where bash may write a name
  the step does not read (`${X:=v}`, arithmetic, `let`), copying and merging back only the names
  its bodies spell or set, and not at all where no body may write; a carry costs the statements
  it walks and the names it copies, and one costing more than 128 counts as more than one, so a
  site's carries cost 1,024 at most (round 11's walked a body's K statements eight times a site
  where the body set K names: 3.9x `main` at K = 50, 5.7x at 3,200); where a body may set any
  name (`eval`, `source`, a name taken from a value), a carry gives every other held name its
  own stand-in, as `record` does, once a walk and then to the names changed since; past a site's
  carries, each name its bodies may set holds the cap's stand-in on both sides, its word-lists
  too, so `${A[1]}` reads it, and where a body may set any name every name the table holds does,
  as the round-9 head had it -- each once a walk and then, at a later visit, those changed
  since, as the walk writes them: a statement that may set any name sets its plain names too
  (`export "$K=v" X=P` sets `X`), and a `read`, `unset` or `local` behind a wrapper (`command`,
  `nohup`, `nice`, `env`, `timeout`, `stdbuf`, `setsid`, `flock`, `xargs`) the names it names,
  as the walk's `_cleared` reads it through `shell_command.command` and takes the stand-in away
  (round 11 missed that write, and the use read the step's own value while every shell ran the
  payload: 195 cells in 53 rows of the round-11 seat's hunt, and 78 in 16 more, #2910's, that
  every tree read CLEAN: a body that may set any name with a wrapped `read` between two calls),
  so no name a carry sets escapes it; and a stand-in makes no list where the name held none,
  sharing one read-only list, so the names a walk stands in leave the collector nothing to walk;
  so a step reads within a constant factor of `main`'s time -- 1.01-1.34x on the forge, `main`
  and the head interleaved in one process a size (the round-11 seat's `seat-cost18.py`, medians
  of three, the collector on), over the round-11 seat's 20 shapes to K = 1,600 (200 where `main`
  turns cubic, 800 for `wideassigned`) but for `calls`, and on the six that grew in round 11 to
  3,200: `calls` falls from 3.88x at K = 50 to 1.12x as its carries outgrow `_WORK`; `evalwide`
  and `evalbetween` fall from 1.17-1.19x to 1.08-1.09x, `srcwide` and `srcbetween` from
  1.17-1.20x to 1.08-1.10x, and `wide` holds at 1.04-1.05x -- each within about 0.01 of flat
  from K = 800, the order of the two trees in a process moving it that much (a process's second
  run is its slower, the head's the more so: averaged over both orders `wide` reads 1.036, 1.043
  and 1.042 at 800, 1,600 and 3,200) -- at a price: past the budget a use of a name the bodies
  may set reads every download, where no shell runs one -- a call followed by more than eight
  statements that read the table (`g() { eval :; }; g`, twelve `: "$T"`, `sh "$T"`: 30 cells in
  6 rows of the round-10 seat's 3,701, MP07-MP09 and MV01, MV02 and MV06), a body that may set
  any name in a loop changing a name twelve times (`. ./env.sh`: 15 in 3, the round-9 seat's
  BU78-80), an array's whole-array use (`sh ${A[@]}`, `sh ${A[*]}`) at nine and twelve states
  (90 cells in 18 rows of the round-10 seat's, BB120-BB128 and BB136-BB144: 54 under bash, and
  36 under `sh`, which has no arrays; at eight, it reports as `main` reads the array written
  out), and under `sh`, where dash has no arrays, an array's element (68 cells in 34 rows of the
  round-9 seat's 2,903); within one read, no site in the round-8 seat's 2,667 rows is visited
  past the budget (eight visits at most, in 2 rows), and none reads otherwise than the round-10
  head reads it; at a price, round 12's, where a wrapped `read`, `unset` or `local` stands its
  names in again though a wrapper that runs no builtin leaves them alone -- under `-e`, where
  the failing wrapper stops the step (`nohup unset T`: 66 cells in 22 rows of the round-11
  seat's hunt), and under `sh` an array, which dash lacks (6 in 3) -- and where a body's carry
  costs more than 128, carried fewer than eight times a site, or never past 1,024, so every name
  it may set holds the stand-in from its first call (none of the 4,095 rows of the two seats
  reaches it: the dearest carry there costs 89); at a price too, now that a fresh carry reads
  the plain names of a statement that may set any name: under `sh`, a carry through a bashism
  dash rejects (`declare`, `typeset`, `printf -v`, `source`, an array: 60 cells in 30 rows of
  the round-10 seat's), and a `readonly` name assigned again, which bash refuses (`readonly
  "$K=v" X=P` twice: 20 in 4) -- and at a price besides: `T=P; f() { T=/dev/null; }; f; sh
  "$T"`, and #2785's `g() { T=x; }; T=P; g; sh "$T"`, are reported though no shell runs `P`, as
  are a never-run decoy in a called body (`if false; then T=P; fi`), an assignment a body makes
  only in a subshell, a pipe stage, a background job or a child shell, read as the step's own
  statement is (`( T=P )`, `( T=P; )`, `( :; T=P )`, `( T=P ) & wait`, `( T=P ) || :`, `if ( T=P
  ); then`, `( ( T=P ) )` and `( T=P ); :`, their two-line spellings with them: 85 cells in 17
  rows of the round-8 seat's 2,667; `{ T=P; } | cat`, `: | T=P`, `T=P & wait`, `{ T=P; } &
  wait`, `eval '( T=P )'`, `bash -c 'T=P'` and `sh -c 'T=P'`: 55 in 11; and a subshell body on
  its header's next line, `f()` ⏎ `( T=P )`, or after `function f()`: 10 in 2), a call after
  `unset -f f`, `bash -c f` or `export -f f; bash -c f` (15 in 3), under `sh` a body whose
  header dash rejects (`function f { …; }`, `function f () { …; }`: 29 cells in 17 rows), a call
  in a `{ …; } &` group the body backgrounds, and under `sh` a call behind `&>`, `>&`, `&>>`,
  `;&` or `;;&` (dash reads `&>` as `&` then `>`); and `eval -p f` or `eval -- -- f` reads as a
  call of `f` (the guard's `eval` reader keeps the words not led by `-` as the program) though
  bash rejects `-p` and dash runs `--` as a command. The sure carry is #2785's own PR. The value
  table's candidate cap moves with it, in the values lane, on the coordinator's rulings (#2871):
  every truncation keeps what it can beside the cap's stand-in -- a name its first eight
  candidates (`workflow_values._update`), a word's or an argv's product its first 64 (`valued`,
  `valued_argvs`), so an installer's honest OS-by-arch product written inline (`unzip
  "tool-$V-$ARCH.zip"`, 3 x 3) reads CLEAN as on `main`, where stored in a name first or walked
  by a `for` (`F="tool-$V-$ARCH.zip"; unzip "$F"`) the name holds nine and pays the name's price
  (30 cells in 6 rows of the round-8 seat's) -- and a use holding the stand-in reads as every
  download the step holds there, so it reports wherever an unverified download can reach it. A
  write of the whole value or a sure `unset` ends it; a write of word 0 (`T=y`, which bash makes
  `T[0]=y`) keeps it at the other keys; an array keeps its word-lists beside it; and the order
  kept carries no safety. `main` held the stand-in alone, which a use reads as nothing, so a
  payload anywhere among nine or more candidates now reports -- the round-4 seat's 7-arm `uname`
  and `$RUNNER_OS` dispatchers with an OVERRIDE line after them, `main`'s own x20 rows, the
  ninth candidate of #2871 (`for T in a b c d e f g h P`; seven conditional reassignments, then
  `[ -z "$NOPE" ] && T=P`): true reports, every shell running the payload; the array rows report
  under `sh` too, where dash has no arrays and runs nothing. The price, measured: a use of a
  name with nine or more candidates reports where no shell runs a download -- 26 cells in 6 rows
  of the round-6 seat's 1,823, 196 in 53 of the round-7 seat's 2,136 (`for T in a b c d e f g h
  i; do :; done; sh "$T"`) -- as does a use of a product past 64 (65 cells in 13 rows of the
  round-8 seat's hunt: PB107-PB118, PB120), and a step that spells the reserved name
  `${__panopticon_past_the_cap}` itself reads it as the stand-in (15 cells in 3 rows). Against
  the round-5 seat's 1,697 rows the head closes 1,804 cells `main` leaves CLEAN and adds 542
  fail-closed ones (177 since the round-4 head, 68 since the round-5 head, 25 since the round-6
  head); against the round-6 seat's 1,823, 2,055 and 596; against the round-7 seat's 2,136,
  2,479 and 757 (35 since the round-7 head, which this one clears of 82: the products within
  64); against the round-8 seat's 2,667, 3,282 and 1,104 (none since the round-8 head, which
  this one clears of 35: subshell bodies whose first command opens with a `{` word); against the
  round-9 seat's 2,903, 3,804 and 1,317 (83 since the round-9 head: the array stand-in's 68
  under `sh` and MP07-MP09's 15, both priced above); against the round-10 seat's 3,701, 5,229
  and 1,967 (125 since the round-10 head, the budget's price and the two above, which closes 360
  the round-10 head left CLEAN while a shell ran the payload: a name only a statement that may
  set any name sets, which its shared carry restored stale, and a body that may set any name
  past the budget); against the round-11 seat's 394 hunt rows, 273 close (its B1's 195 and
  #2910's 78) and 72 are added, round 12's price above; and none goes CLEAN where `main` reports
  and a shell runs the payload (16 cells do where none runs). A text the table would build past
  4,096 characters is still dropped, as on `main` (a limit, kept for a follow-up). Still CLEAN
  while a shell runs the payload, each as on `main`: a `case` whose header shares a one-line
  body's line (`g() { case x in x) f;; esac; }`) is not read as one; nor is a call made through
  a value (`F=f; $F`), one in a `case` behind `time`, one a loop's body makes before its own
  definition (`for …; do f; f() { … }; done`), one to a function the step names `eval` or `time`
  (`eval() { … }; eval f`, and a bare `eval`; a bare `time` is read as the call), or one a
  function makes of its own arguments (`sudo() { "$@"; }; sudo f`); an array past the cap loses
  the stand-in at its other keys where a later `T[0]=y`, `read T`, `printf -v T`, `mapfile T`,
  `unset 'T[0]'` or `( T= )` writes it, each still ending it; a body's `T=$1` holds no argument
  of its call, its `T=$(…)` and `printf -v T` no value, and a body that sets `T=P` before its
  `local T` is read as leaving `T` alone; a body whose only write is `${T:=…}` or `${T=…}`
  (#2781), or a `command`-wrapped `read T`, is read as setting nothing, within the budget and
  past it; and a check whose failure a subshell, a pipe, an `if` condition, `time` or `!` keeps
  from stopping the step (`( { f() { CHECK; }; f; } )`, `{ …; CHECK; } | cat`) still clears the
  download. And the header test at every `(` had joined and split the whole buffer before the
  match, about x4 per doubling of one `(( … ))` statement, now computed only behind a match.
  Still CLEAN as on `main` (#2928): a check in a group piped into another command inside a `bash
  -ec` or `bash -s` child, the function form among them (`bash -ec '{ f() { CHECK; }; f; } |
  cat; USE'` and its `bash -e -s` heredoc twin), which `main` since #2849 reports only by
  failing closed on the `f()` header it misreads.
- **Reviewer write safety separates the boundary from its transport (#1622).**
  `artifact_write_guard` now means reviewer-controlled artifact writes are impossible or confined.
  The static `self_write_delivery` fact is true only for Claude and Kimi, and a write-capable role
  self-writes only when that fact and a proven boundary both hold; all other cases remain
  return-persist. Current Claude/Kimi proof covers the write-tool surface. When tool policy is
  REFUTED and the operator passes `--allow-unenforced`, `unenforced-ack.json` names the remaining
  Bash-path gap. For that PROVEN-boundary case, with no flag or with tool policy UNKNOWN, no
  acknowledgement is written; the gap appears only in the `tool_policy_enforced` posture line. An
  unproven boundary (including generic) still requires `--allow-unenforced`. Codex gains no
  capability claim in this policy change.
- **Workflow guard: the stdin and `-c` string walks read a shell's options as the shell does, and
  the guard only adds reports (#2616, #2864, #2647, #2654; #2858).** `job_defects` returns `main`'s
  findings -- a pass in which every join of the stdin and string walks answers as `main` does
  (`workflow_options.mains_answer`) -- then those of a second walk that the first pass does not
  make, so every finding `main` makes stands. The second walk skips a long option's FILE (`bash
  --rcfile /dev/null <<'EOF'` and `--init-file` ran the heredoc and read CLEAN: #2616) and reads
  bash's one-dash long words in the leading run (`bash -norc <<'EOF'`, `bash -norc -c '…'`: #2864);
  reads options on after `-s`, so `bash -s -c true <<'EOF' <check>` counts no check bash never
  reads (#2647) and dash's `sh -s -c true` reads the heredoc after the string; counts none after a
  lone `-` with a word behind it (`bash - /dev/null`: #2654), where the shell runs none of the body
  (`-n`, `-o noexec`, `-D`, `--version`, `-version`, `--pretty-print` but under `-i`) or where the
  option run holds a word that may expand (`-o $X`, a `~`, a pattern); seeks the `-c` string in
  every reading of such a word; and weighs a `$Y` after `-c` or `-c --` as a value in the option
  slot. Nothing is cleared: a body under a refused option, an exit or noexec stays reported though
  nothing runs (#2603, #2606), and so do the over-report halves of #2647 and #2654.
- **Workflow guard: what the second walk adds, and what it costs (#2858 rounds 10-11).** On the
  round-5 to round-8 seats' sets (80,514; 29,639; 18,548; 15,713 steps), their 222 direct cases and
  round 10's seat hunt (4,276 rows), the first pass gives `main`'s findings exactly and the job
  holds every one of them. Joining the walks at their inputs (round 10) was not enough: four
  consumers read less given an added reading -- `_on_stdin` and annotate's `_complete`,
  `substitution_script`, a printer-fed body read under both shells, an added `}` regrouping the
  first fold -- and 850 of the seat's rows read CLEAN where `main` reported; a union of findings
  ends that class. Against `main` the walk adds reports on 9,328 steps where a payload or an
  unverified use runs and 24,516 where nothing does, on the four sets (posture-blind step counts,
  every `shell:` setting read; a `noe` step judged on its two `{0}` settings alone gives 9,057 /
  24,515): a body only it reads 2,414 / 6,858, a check only `main` counted 2,529 / 4,605, a string
  only it reads 1,973 / 2,809, a check in a string `main` reads 1,696 / 7,752, a candidate only it
  weighs 691 / 2,447, several 25 / 45 (46 of the 222 cases; 6 of the hunt's rows, a withheld string
  read under both shells' printers). The over-reports
  are fail-closed: a word that may expand may be the FILE, `-n` or `-c` (`bash $X -c "<check>"`,
  `bash -o $X -s`), a FILE may hand its parameters on (`bash w.sh -c '…'`), a body or string whose
  check is withheld reads under both shells' printers (`bash -s -c 'echo hi' <<'EOF' echo 'sh\ttool'
  | sh`), and a long option read on past its FILE meets one that refuses or exits (`bash --rcfile
  /dev/null --version`). The cost: the job reads a step twice, so every ratio to `main` rises by
  about one and stays flat with n -- on round 10's seat shapes at 1,000 to 8,000 words, 2-3x for
  most, 3.4-3.8x for a long option's FILE, 3.5-4.4x for one-dash runs, 4.5-5.6x for `-o $X`, and
  11-16x for the two `-c --` shapes (`Y=; Z=; bash -c -- $Y $Z… 'P'`, `X=; bash -c -- $X… sh
  <<'EOF'`), which `main` reads CLEAN though bash runs the payload, every word a candidate weighed
  as `main` weighs its own; each range spans a Linux aarch64 box (its low end) and a Mac. The job
  keys each finding with its step's name, so it stays linear wherever the name is one the workflow
  schema takes, a string (8,000 steps sharing one finding: 2.7x `main` on the Linux box, 3.3x on
  the Mac). Open, and this PR's own: a `name:` the schema refuses -- a list or a mapping -- is
  compared with the others under its finding, so where many share one finding the cost grows
  fourfold with each doubling (4,000 such steps: 0.14 s with list names and 0.20 s with mapping
  names on the Linux box, 0.10 s and 0.13 s on the Mac; `main` 0.005 s and 0.002 s); the guard pins
  in `tests/test_workflow_options.py` hold the stdin walk's recursive call whole -- its argv as its
  own frame's one `command()` result, its depth and its walk -- at every depth to its bound of 64,
  so a one-line change of what that recursion sees, on one restriction or two -- depth, word
  position, inner shell, run length, a member, a holder, a spelling, a second `command()`, a
  swapped walk -- is caught, and the residual that round 15 named there is closed. Open, as on
  `main`: a check counted under a refused shell where errexit is off (round 9 withheld it: 14 rows
  of round 5's matrix), #2608's `-s $X` and `-c $X` rows, `-c $(…)`, #2900's one-dash long option
  behind a shell the step names through a variable (`CMD=bash; $CMD -norc <<'EOF'`), and the
  guard's other named gaps.
- **Workflow guard: what `eval`'s words and a `-c` string hand on (#2673, #2683, #2684, #2764,
  #2669, #2331).** `eval 'curl … |' 'sh'` ran the pipe and read CLEAN: `eval` joins its words before
  it runs them, and the guard read them one by one. Where a word begins or ends with an operator the
  words are now joined, with each word's lifted text kept, so a statement split across them reads as
  written (a join the reader refuses is refused on this path as on the stdin walk's, one answer);
  elsewhere they read one by one as they did. The stdin walk's own join renders a word holding a
  `$(…)` instead of dropping it -- `eval "sh $(echo -s)"` is `sh -s`, `"sh $(cat f)"` a `sh`
  handed a word that may vanish, `"$(echo 'sh')"` the shell `sh` -- so the heredoc each of them
  reads is reported; a FILE program beside a heredoc (`bash <(echo 'sh') <<'EOF'`) hands the body
  to the shell the FILE names; and a `-c` string holding a `<(…)` beside a `$(…)` is a script
  after all, the file rendered as an operand (`bash -c "sh $(echo tool) <(echo x)"` ran `tool`
  and read CLEAN). #2685 is already closed on main and pinned.
- **Workflow guard: the shell option grammar moves to `scripts/workflow_options.py` (#2331).** A
  pure move out of `scripts/workflow_programs.py`, which stood at the 700-line ceiling: the option
  letter and name tables, the refusal readers (`_refused`, `_refused_name`), `_past_options` and the
  three option-slot word readers (`_value`, `_before_operand`, `_may_spell_option`), byte for byte,
  with every name re-exported from `workflow_programs` so no importer changed. Guard answers are
  identical before and after over the 6,803 inputs the guard test families feed `job_defects` and
  `fetch_exec_defects`; no expectation moved. Sizes: 700 -> 559, and 166 for the new module.
- **`scripts/shell_reader.py` splits its command layer into `scripts/shell_command.py` (reader
  lane).** A pure move at the reader's size (699 of 700 lines): the keywords, assignment and
  function-header spellings a statement may open with, the shells and the default or optional `$`
  words that may stand for one, and the `_command_result` walk behind `command`,
  `command_as_written`, `unresolved_wrapper`, `wrapper_words`, `negated` and `conditional` now
  live in the new module, byte for byte; the reader imports every name back under its own, so no
  caller moved, and the new module imports nothing from the reader. No verdict changes: every
  `job_defects` answer the guard's test suite produces is identical before and after.
- **Child scripts keep their own failure reach when the parent shell carries on (#2423,
  #2331).** A check inside `sh -ec 'CHECK; USE'` now clears that child's later use even when the
  step has run `set +e`, starts from a no-errexit `shell:` template, or pipes the child's enclosing
  group without pipefail. The parent's refusal remains bounded to the command that runs the child,
  so a use after it is still reported; a child without its own `-e` remains reported too. Checks
  whose `-e` is suspended by an `&&`/`||` list or condition, or whose status is hidden by a later
  pipeline stage without child pipefail, also remain reported when execution reaches a later use.
- **Child-script `&&` lists keep their failure reach inside the list (#2416, #2653, #2331).** A
  failed checksum ahead of `&&` inside `sh -ec`, `eval`, or a `bash -e -s` body now certifies only
  the suffix that depends on it. A use in that skipped suffix remains gated, including one in a
  nested script; a use after the list is reported. This closes #2653's five stdin/`-c` forms.
  #2416 remains open: set 3's `v2` and `v6` rows, where the list is a called function's body, still
  read CLEAN and need their own follow-up.

  One list-scoped pass records case and group state without a process cache. Explicit braces keep
  their source positions. Because the reader retains only aggregate parenthesis counts, a hidden
  open/close pair in one stage, or a hidden opener beside leading `!` operators, is marked
  ambiguous instead of being assigned an order. A handed check keeps an existing parent `Reach` or
  a specific parent refusal; only when it has neither does the affected frame get a conservative
  refusal that names hidden parenthesis order, explicit compound negation, or a compound condition.
  That mark belongs to the innermost frame opened or enclosing the uncertain stage, so it ends
  before a sibling list; a direct check keeps main's bounded answer while it remains in the marked
  frame. No negation, condition, or function-call credit is inferred from an unplaced compound
  boundary, while a function check once again reads the enclosing negation or condition around
  every proved call in its wrapper chain. Explicit even parity such as `! ! { ...; }` keeps the
  shell's ordinary answer; the final gate contains 2,499 such CLEAN cells, 2,211 of them where main
  reports, and no measured parent runs the payload in any of them.

  The Bash `time` option skip is restored. A `coproc` after a marked or unmarked `case` arm is
  recognized, so B42's a19 family keeps its asynchronous refusal instead of exporting child-local
  reach. This is narrower than the general `coproc` gap: 250 payload-running cells in sets 21 and
  31, including function-called and `bash -ec` forms, remain CLEAN as on main (#2894). The no-digest
  refusal is applied before any context gate, and a bare function header spends its reader-hidden
  pair once when that pair is the evidence for the header. The 18 removed round-five and round-six
  test methods return with 136 original assertions; four more assertions are replaced by stronger
  step pins. Seven reason checks name the current refusal, and only the three CLEAN checks
  superseded by the accepted frame boundary are omitted. The clean-parent refusal is pinned by
  `test_b32_ambiguous_child_keeps_mains_report_when_the_parent_is_clean`;
  `test_b30_function_checks_read_the_call_sites_enclosing_context` restores all 31 round-six #2855
  call-context cells and adds direct-setting coverage for nested wrappers. The D1-D3 boundary
  controls and D8 refusal-off control fail focused tests. Focused pins also kill K2, N07, D14, S2,
  S3, the L20 asynchronous-function-gate edit, and the ME11 re-cut. Of the nested-call-chain edits,
  L15 and L24 fail pins; L14 (innermost call context only), L23 (no call collection through wrapper
  recursion), and L25 (negation refusal at the step only) pass the full suite and take back
  round-eight REPORT-side gains where main is CLEAN (F34). B1 and B8 remain with direct pins; D7,
  B10, B14, N08, N10, and S5 are removed or folded into the simpler source-order walk. The former
  N18 close-carry branch is also omitted; its removal gives N13 and four spelling variants back to
  CLEAN, matching main (five rows, F32). D9's `why is None` fold keeps 285 measured no-run cells on
  their parent-`Reach` answer and CLEAN, matching main, instead of replacing it with a structural
  refusal (F36).

  My final posture-aware Forge gate generates 936,855 candidate rows across sets 1-38. It joins
  924,755 of them to runtime truth -- the 815,744-row round-six baseline and 109,011 round-seven
  hunt rows -- while the expected 12,100 generated baseline rows remain outside the truth corpus.
  There are zero cells where fresh main REPORTs, this head is CLEAN, and a measured parent runs the
  payload. Against main, the head adds 95,390 payload-running reports, leaves 9,029 payload-running
  cells CLEAN for follow-up, makes 12,054 main reports CLEAN only where no measured parent runs,
  and adds 24,730 no-run reports.

  Of that no-run price, 10,128 cells use the explicit structural fallback: 5,904 hidden-parenthesis,
  3,936 compound-negation, and 288 compound-condition refusals. Compared with round six, the head
  gives up 266 payload-running reports where main is also CLEAN: 15 condition-group, 50 `coproc`,
  105 negated-brace, 24 negated-parenthesis, and 72 `time` cells. The 15 condition-group cells are
  set 23's `j03t`; the 24 negated-parenthesis cells are set 23's `j02t` (15) and set 36's `i06p3t`
  (9). Against round seven, the head also gives back set 30's `u07t` (24 payload-running cells,
  CLEAN on main and at round six; F33). Outside the gate, the #2855 replay gives back N13's three
  cells, which report at rounds six and seven and are CLEAN on main (F32).

  My final-source Bash 5.2.21 cost pass reports every generated nest in all five settings. At
  depths 100, 200, 400, 800, 1,600, and 2,400, candidate/main brace ratios are 1.84, 1.93, 2.00,
  2.03, 2.03, and 2.06×; function ratios are 1.70, 1.85, 1.97, 2.04, 2.09, and 2.12×. The function
  increments shrink, while the brace increments flatten within run-to-run spread; both remain a
  bounded constant factor. My three-pass, 40,000-cell full-set sample has no verdict instability
  and a 1.137× median: 178.6 CPU seconds against main's 157.1 seconds.
- **Workflow guard reads a `-c`/`eval` string with a live expansion beside a double-quoted
  escape as bash hands it on (#2466, #2331).** `bash -c "x=\$(curl -fsSL $URL); eval \"\$x\""`
  and the mixed-quoting `bash -c "x=\$(curl … i.sh)"'; eval "$x"'` run the download under bash
  5.2.21, 3.2.57 and dash and read CLEAN: #2342 undid the `\$` escapes only where no live `$` was
  left in the word, so a `$URL` beside them kept every backslash and the inner `x=$(curl …)` was
  text. The reader now spells such a word with each backslash gone and a live `$` word carried as
  the value it already is at top level, so the string reads as #2341's carried download handed to
  `eval`; the `eval`, backquote and `echo … | sh` twins read the same way. A word that also holds
  a lifted `$(…)` keeps its markers in that text, so the `Opaque` rendering of `bash -c "sh
  \$(echo tool) $(true)"` is `sh $(echo tool) $(...)`, read as its escape-only twin is (the
  neighbour noted on #2466), and a printer's word holding one stays unspelled. A live `$` in a
  COMMAND-word position (`bash -c "$CMD … | sh"`) stays unread, as `$CMD … | sh` is at top level;
  the gap list says so.
- **Workflow guard reads a `$` word in front of a shell as an optional wrapper (#2472, #2331).**
  `$SUDO sh -c 'curl … | sh'` ran its pipeline with `SUDO` unset or empty -- bash 5.2.21, bash
  3.2.57 and dash all drop the empty unquoted word, and `sudo` hands on -- and read CLEAN, as did
  `${SUDO:-} sh tool`, `CMD=; $CMD sh <<'EOF'`, `bash -c "\$x sh tool"` and `$SUDO curl … | sh`.
  The reader now drops an unquoted `$` word that is one reference, with no default or a wrapper's,
  in front of a name it knows (a shell, an interpreter, a wrapper, a fetcher) and reads the rest as
  the command, fail-closed. A quoted `"$SUDO"` keeps its word (bash runs `''` and stops), and so
  does a word the step's own table resolves to a literal that is no wrapper (`SUDO=echo` prints,
  `A=X=1` runs `X=1`): `workflow_annotate` marks it `kept`, and its rule-7 veto now fires for a
  value-reached builtin that may assign (`R=read; $R CMD`) rather than for any name outside the
  ones it reads. The price: a value set outside the step that runs nothing of what follows
  over-reports, and a checksum behind such a word is still not credited.
- **Codex read broker passes through a search-only directory (#2839).** `_open` opened every
  component from `/` read-only, so a review root under a directory that grants `--x` and not `r`
  (`drwx--x--x`, a per-tenant parent) refused every `read_file`, `search` and `list_files` -- and
  the scope binding before them -- although the kernel let the path be traversed. Directories the
  walk only passes through are now opened for search alone (`O_PATH` on Linux, `O_SEARCH` where
  CPython exposes it; macOS from 3.13), with `O_DIRECTORY | O_NOFOLLOW` kept on every step so a
  symlink component still fails, and the last component still opened to read. Without either flag
  the walk is the old read-only one and such a root still fails closed. The hard-link rule (#1642)
  is untouched.
- **Workflow guard reads a printer's `$X` and a `$CMD` through the step's values (#2468, #2600,
  #2601, #2331).** Where the step assigns a name one literal no shell expands, `echo "$X" | sh`
  weighs that text as its program (`X='curl … | sh'` reports as its literal twin), and a `$CMD`
  command word reads as the name it holds: `CMD=sh; $CMD <<'EOF'` credits its check under `sh`'s
  `-e`, `CMD=true`, `cat` or `PYTHON=python3` read as theirs. The step is marked once before
  `flattened`, the one place a value body's credit is not yet fixed; any other value -- one with a
  `$`, a backquote or a `<(` in it too -- reads as before, a quoted `'$X'` over-reports, and a
  `$(...)` or handed script inherits no mark yet. A resolved word reads as its literal twin, the
  twin's filed gaps included, so a command word is marked only where the step surely runs it, for
  a name the guard reads, and a printer's value only where its text fetches -- each only where
  every program the statement hands a shell is plain.
- **Workflow guard follows a download through the step's own values (#2425, #2489, #2331).**
  Where a use as written names no download, a name the step itself assigns a literal or an array
  literal is read through that value (`T=cuda_1.run; sh "$T"`, `declare -a a=(sh tool); "${a[@]}"`,
  a `for` header's words), and a call hands the values it sees to the function body; the use as
  written keeps main's reading. Quotes are gone to the reader, so a quoted twin over-reports, as
  does a reassignment the shell may skip; a table kept statement by statement was rejected because
  it cannot repeat the loop, condition and function-body walks of one asked per use.
- **Fail-closed workflow messages now identify guard readings (#2424, #2331).** Carried
  variables and conditional checksum rescues say when scope or status comes from a conservative
  reading. Direct carries and proven non-stopping rescues keep their existing wording; verdicts
  do not change.
- **Workflow guard now lets bound downloads own value-form stdin (#2607, #2331).**
  When `curl -o "$T"` is followed by `$T <<'EOF'`, the existing run finding now stands alone and
  the heredoc is treated as payload input, so its text cannot invent a shell stream finding or keep
  a checked download flagged. Unknown `$CMD` bodies stay fail-closed; disabling all value-body
  reads was rejected because it would hide their real `curl … | sh` executions.
- **Four Bash 3.2-only substitution-heredoc parse gaps are now explicit (#2626, #2608).** A body
  line with an apostrophe, unbalanced double quote, backquote, or bare `$(` can make Bash 3.2
  reject text Bash 5.2 accepts, but none of the measured shapes runs a payload under 3.2. The
  #2493 refusal stays limited to `)` because widening it would report parse-only differences.
- **`eval` brace alternatives bind only downloads they can name (#2624, #2608).** The
  second parse now expands bounded brace lists and numeric ranges before matching a fetched
  path, because treating every brace group as `*` misses real uses and binds excluded names;
  unbounded expansion was rejected because workflow text controls its cost.
- **Compound-command streams now reach their closing executor (#2430, #2331).** Fetches and
  carried downloads printed inside `{ }`, `( )`, `if`, loops, or `case` now bind to a shell after
  the compound's closing pipe. File redirects, disconnected input, and nonexecutors stay clean.
- **Multiline `case` headers stay visible (#2429, #2331).** A literal `in` on the line after
  its subject now reaches the statement reader, so commands in those arms remain visible to
  the workflow guard.
- **Workflow guard: a `cat` with a quoted heredoc on its stdin and an `echo` read as the step's
  shell prints it are printers too, through a substitution as well (#2467, #2476, #2478, #2487,
  #2495, #2728).** `cat <<'EOF' | sh` is read as `sh <<'EOF'` is, a `cat` with an option too (its
  body read whole: `-n` over-reports), and an EXPANDING `cat <<EOF | sh` is reported as `sh <<EOF`
  is; `echo`'s backslashes read as bash prints them (literal unless `-e`) or as `sh`/dash decode
  them, and a `printf` format's always. A shell a `-c`/`eval` string names, or a `${X:-sh}` default
  stands for, reads them both ways, as does one inside a `$(…)` in a script handed on or in a script
  a `$(…)` hands a shell (#2728); the step's own `$(…)` reads per the step's shell. A pass-through
  between the printer and the shell -- `tee` writing plain files with `-a`/`-p`/`-i`, `--append` or
  `--output-error[=MODE]` at most; a `cat` whose only operands are `-` (and one `--`) -- is read
  through (#2478); any other `tee`/`cat` spelling, or a stage that rewrites the stream (`tr`,
  `base64 -d`), leaves the program unread, reported where its words or the printer's text fetch, or
  beside a reported download. A printer inside a `$(…)` or a `<(…)` is read as the text the shell
  runs where every reading agrees on it (#2487, #2495): `eval "$(echo 'sh tool')"`,
  `sh <(echo 'sh tool')` and `bash <(cat <<'EOF' … EOF)` report the download they run, and the
  documented `eval "$(cat <<'EOF' … EOF)"` gap closes; an unquoted `$(…)` is read unsplit (`eval`
  joins bash's fields; `-c` runs the first alone, an over-report), a backquote whose text escapes
  `$`, `` ` ``, `"`, `\` or a newline, and a text the reader refuses, are not rendered, and
  the catch-all row for a word all substitution stays beside every such read. Named gaps:
  `shopt -s xpg_echo` turns bash's `echo` into a decoder, which this rule does not
  follow; a word the shell reads specially once unquoted (a quote, space, newline,
  `#`, `\`, `<`, `>`, an open `$(`) or a lifted `$(…)` word inside the unread stage's words still
  hides the fetch that follows; and a substitution's printer the readings disagree on
  (`sh -c "$(echo 'sh\ttool')"`) stays unread.
- **Pipeline uses after `case` compounds reach the workflow guard (#2610, #2608).** A
  literal `esac` now closes its case before a following redirect or pipe, so `| sh payload`
  is a real stage instead of one argv hidden in case-pattern state. Closing every `esac`
  spelling earlier was rejected because quoted and escaped forms can still be arm patterns.
- **Workflow glob matches now reach loop, positional and function values (#2585, #2331).**
  A live pattern such as `./cuda_*.run` stays tied to the download when `for`, `set --`, or a
  direct function call stores it. Literal `shift` commands reindex that value, while `$@` and
  `$*` retain it for loops and first-script uses. Quoted and nonmatching patterns, reassignment,
  step boundaries, and relative path changes retain bounded controls.
- **Nested `case` arms expose their commands to the workflow guard (#2617, #2608).** The
  reader keeps a parent arm separate from the inner `case` header, so two- and three-level
  bodies no longer hide a fetch-and-execute pipeline. Retaining the parent arm also keeps an
  inner checksum from clearing execution in the parent's sibling arm.
- **Workflow guard: value stdin inherited through `eval` or `sh -c` is read (#2599).** A quoted
  heredoc handed to an inner `$CMD` now gets shell analysis and names that word, closing a CLEAN
  `curl | sh` path; an unset `sh -c "$P"` is deliberately reported fail-closed rather than
  treating an unknown value as data.
- **Checks inside command substitutions now gate the uses beside them (#2435, #2331).**
  `x=$(CHECK && bash t.sh)` credits `CHECK` under that substitution shell's own failure reach;
  `CHECK; bash t.sh`, a plain use, and a check in a sibling substitution remain reported.
  Check discovery moved to `workflow_checks.py`, taking `workflow_guard.py` to 700 lines.
- **ANSI-C words no longer hide adjacent workflow findings (#2614, #2470).** A non-ASCII
  escape now leaves only its word unknown, so ordinary CI prose does not replace a nearby
  fetch-and-execute finding with a whole-step refusal. Backslash-newline also stays literal
  inside `$'...'`, matching both bashes instead of joining text they keep separate.
- **Workflow guard keeps stdin possible after a value-form shell option (#2605).**
  `sh $X file.sh <<'EOF'` no longer hides its body when `$X` may be `-s` or `--rcfile`;
  `X=-e` is the disclosed fail-closed cost, because always treating the bare word as a script
  file would reopen the execution defect.
- **Workflow guard: value-form consumers no longer hide streamed or redirected downloads
  (#2602).** Direct, carried and pass-through streams, plus fetched file stdin, now report under
  `$CMD`, closing a CLEAN execution path; a `$CMD` holding `cat` is deliberately reported
  fail-closed because assuming an unknown command only reads data would reopen the defect.
- **Workflow guard now reads `$` command stdin inside substitutions (#2598, #2331).**
  `x=$($CMD <<'EOF' …)` no longer hides a written `curl … | sh`: the program reader now speaks
  before the stdin hand-off only inside substitutions. Top-level wording and option-value priority
  stay unchanged; directly prioritizing the body reader was rejected because it hid louder reasons.
- **Line-only subshell rescues keep their enclosing status context (#2579, #2331).** When `(` is
  on the line before a checksum, its `|| exit` now carries through `)` into an outer `||`, so a
  swallowing branch no longer certifies later execution. Unrescued and piped diagnoses remain.
- **Workflow paths now follow a static working directory (#2427, #2331).** A literal `cd` binds
  relative fetches, checks, aliases and uses to the file they reach. Each step starts at the
  workspace; subshells and command substitutions inherit, then restore, their caller. A branched
  or dynamic `cd` stays fail-closed as an unknown directory. Known different paths remain clean.
- **Workflow guard now reads expanding heredocs under `$` command words (#2597, #2331).**
  `$CMD <<EOF` no longer hides a written `curl … | sh`; substitutions stay values in this second
  read to avoid duplicate findings. This fail-closed reading can flag non-shell bodies whose text
  resembles shell, while preserving innocent `$PYTHON`; a blanket unread warning was rejected
  because it would flag that control.
- **Workflow guard: the printer rules move to `scripts/workflow_printers.py` (#2331).** A pure move
  of `printed`, `_piped` and `_PRINTERS` out of `workflow_programs`, which re-exports them, so the
  printer follow-ups have room; the guard's answers are byte-identical before and after.
- **Workflow guard: a value in a shell's options is weighed to its first operand, or past a word
  that may re-open it (#2490, #2479, #2484, #2486).** A louder reason drops a statement's `Idle`
  one, `sh $X "$x"` names its carried download, a `-c`/`eval` string holding a `$(…)` is read
  opaque, and `sh -c "$(cat f)"`, blanks around it too, is reported unread beside a download.
- **Line-only subshell boundaries now retain their shell status (#2420, #2331).**
  The workflow reader keeps lone `(` and `)`, including `esac )`, so a following `||`, `&&`,
  pipeline or background separator reaches the gate. Subshell-local options and assignments no
  longer leak into the enclosing step's model.
- **Interpreter redirections now bind expanded paths to fetched scripts (#2426, #2331).**
  `bash < "$PWD/x.sh"` and a literal redirect after a fetch to `"$PWD/x.sh"` use the same
  last-part path binding as interpreter operands. Other basenames and non-interpreters stay clean.
- **Function checks now count only after a failure-gating call (#2421, #2331).**
  Definitions, rescued calls, and child scripts inside them no longer certify later execution;
  a plain call still credits a check whose failure stops that function and the step.
- **Conditional carriers no longer hide a failed checksum behind a later command (#2418, #2331).**
  Brace groups, subshells and functions tested by `&&` or `||` now report a check whose status a
  later command replaces. A plain function call still gates uses that occur after that call.
- **Nested conditional groups no longer inherit an earlier checksum status (#2578, #2331).**
  When a later command replaces a checksum's status before an enclosing group reaches `&&` or
  `||`, the guard reports the later use. Checks that remain the group's final status still gate.
- **Conditional checks no longer certify uses that can outlive their list (#2419, #2331).**
  A checksum behind `A &&` or `A ||` clears only paths that require the check to run. A final
  `A && CHECK` can still gate a later job step, while `A || CHECK` cannot. Literal commands get
  no special exit-status proof, keeping the rule fail-closed.
- **Checksum rescues no longer certify their own failure-only body (#2417, #2331).** A use
  inside the check's `||` branch is reported even when that branch later exits. The same
  stopping rescue still certifies uses after it, and unrelated checks retain their existing
  ordering and file-binding diagnoses.
- **Workflow guard: a stdin program is read behind `eval`/`-c`, past a value in the option slot, and
  under a `$` command word (#2500, #2485, #2473).** The quoted heredoc `eval 'bash -s'`, `sh $X` and
  `$CMD` run is caught.
  A check behind an `eval`/`-c` string counts for nothing; the body is still read. Nor does a check
  count past `$X` or under `$CMD`: one clears a download only in the body of a shell written at its
  own level, as before. Nothing else in a body behind a string, past `$X` or under `$CMD` is taken
  for the step's own either (bar one whose holder's own options read stdin, `bash -s -c 'sh'`): the
  job is read with such bodies and without them, and a defect of either reading is reported.
  `X=script.sh` over-reports; `$CMD` itself is `Idle` beside a reported fetch.
- **A checksum rescue inside a piped group is not credited without pipefail (#2630, #2608).**
  `{ CHECK || exit 1; } | cat`, its multi-line and subshell spellings, a `{ f; } | cat` call and
  a `|| return 1` twin leave only the piped stage's subshell, so without `pipefail` the pipeline
  takes the last stage's status and bash 3.2.57/5.2.21 and dash run the payload; the default and
  `shell: sh` postures now report them, while `shell: bash` (`-eo pipefail`) still clears them.
  The nested-paren spelling #2627 fixed, the `set -o pipefail` form and the no-pipe rescue keep
  their verdicts. 0 occurrences in the 11 corpora and the calibration pool.
- **Bare-subshell rescues piped onward clear only when pipefail stops the step (#2631, #2608).**
  The `( CHECK || exit 1 ) | cat` family -- the bare-`( )` sibling of the `{ ... }` forms #2582 and
  #2630 handle -- now reads CLEAN under `shell: bash` (`-eo pipefail`), where the failed group stops
  the step and no shell runs the payload, matching its brace twin; 19 such spellings (a trailer after
  the rescue, a `|| return 1`, a subshell stage, a called function body, `if`/`while` conditions) are
  covered. Where the failure is swallowed (`|| true`) or the exit masked by a command on an `&&`
  list's errexit-suspended left side, the payload still runs on bash 3.2.57/5.2.21 and the guard
  keeps reporting it -- the subshell's abort is resolved before the concurrent-stage break, and a
  `return` does not leave its subshell. The 10 named clears, the `( CHECK || exit 1 ) | cat` posture
  split, and the `{ ... } | cat` must-stays are unchanged. 0 occurrences in the corpora and the pool.
- **A use step that runs after a failed step is no longer cleared by an earlier step's check
  (#2632, #2608).** A plain `CHECK` or `CHECK || exit 1` in step a stops step a, but a later step
  whose `if:` runs after a failure -- `always()`, `failure()` or `!cancelled()` -- still runs the
  payload; the default, `bash` and `sh` now report it. `success()`, a plain expression, no `if:`,
  and a check that shares the use's own `always()` step keep their clear. 0 occurrences in the 11
  corpora and the calibration pool.
- **Workflow function gates reach proved later calls (#2586, #2331).** The guard recovers 8 of
  56 previously declined real call sites (25 to 33 of 105 scopes), including grouped calls and
  one proved wrapper. The other 48 remain fail-closed, chiefly on multi-helper steps. Distant
  piped calls retain their concurrent-use bound; posture changes, removals, redefinitions, and
  conditional calls still refuse the proof. An `||`-suppressed call is credited only when the
  gate remains the function's final status; the conservative `unset` barrier is disclosed. The
  mutually recursive function/status proof now lives in `workflow_function_calls.py`, leaving
  both proof modules room under the 700-line ceiling. A success handler after the inner
  subshell's nonzero exit invalidates each supported call form; assignment-only handlers do not
  inherit that failure. `continue-on-error` keeps the shell's posture and bounds credit after the
  proved call and before the end of its own step.
- **Tab-prefixed substitution heredoc delimiters have a regression pin (#2584, #2331).**
  A `<<-` word starting with a tab bypasses the `EOF)` terminator reading, but #2493 already
  refuses the `)` retained in its body. The pin preserves that protection because Bash 3.2
  runs the following payload where Bash 5.2 treats it as data; no new lexer rule is needed.
- **`[[ ... ]]` is one statement to the workflow reader (#2441, #2331).** The `&&`, `||`, `(`,
  `)`, `<` and `>` inside a conditional are its operators, not list separators, subshells or
  redirections, so `CHECK && [[ -f a || -f b ]] || exit 1` no longer reaches the guard as three
  statements with the `|| exit 1` rescue that ends the real list lost -- the step was refused
  where bash stops dead. `[[ $a < $b ]]` records no redirection either, and a `=~` alternation
  leaves the compound-command count balanced. Bash 3.2.57 and 5.2.21 agree on 23 probes; dash
  has no `[[`. A newline after an inner `&&` still ends the statement, as it did.
- **`shell_reader.py`'s token layer moved to `scripts/shell_tokens.py` (#2628, pure move).**
  `_Token`, `_Parse`, `derived`, `readable`, `is_marker`, `has_substitution` and `yields_words` now
  live in the new module and are imported back into the reader under their own names, so no caller
  changed; the reader goes from 683 to 599 lines, making room for #2441 and the reader half of
  #2617.
- **Substitution heredocs whose bodies contain `)` now fail closed (#2493, #2331).** Bash 3.2 may
  close the substitution there and execute later body text as code, so the lexer now names the
  ambiguity instead of accepting one reading. Selecting a parser by runner was rejected because
  the owner ruled one conservative answer for every workflow.
- **Candidate programs now expose code around substitutions (#2482, #2331).** A dynamic `-c`
  option made the guard discard an entire program word containing `$(...)`, so its visible fetch
  pipeline read clean. It now reads the outer program with the substitution opaque while the
  normal walk reads the inner script. Evaluating substitution output was rejected because that
  would invent commands from runtime values.
- **Enclosing checksum groups retain the step's pipefail state (#2582, #2331).** The workflow
  guard credits `{ ( CHECK || exit 1 ); } | cat` under `shell: bash`, where pipefail carries the
  group's failure and stops the step, while default and `sh` modes still report it.
- **Case-arm closes no longer truncate command substitutions (#2474, #2580, #2331).** The matcher
  took an unparenthesized `case` pattern's `)` for its surrounding `$()` close, so a fetched
  pipeline in the arm—including a later arm on an `EOF)` rest—escaped the substitution parse
  and read clean. It now follows nested case phases and balanced patterns, while subjects needing
  another parse fail closed by name. Treating every `)` after `case` as an arm close was rejected
  because it could hide later shell code.
- The `set`-posture reading (`seed`, `_errexit`, `_rejected`, `_takes_value`) moves from
  `scripts/workflow_gating.py` to a new `scripts/workflow_posture.py`, a pure move with re-exports,
  so the gating module has room again under the 700-line ceiling (#2620).
- **Quoted workflow globs stay literal (#2432, #2331).** The guard now uses lexer pattern
  provenance when matching fetched paths, so `sh "./cuda_*.run"` does not claim to run a
  download while unquoted and partly quoted patterns still do. Bash 3.2.57, Bash 5.2.21 and
  dash agree; 439,716 frozen corpus rows and 4,642 real jobs keep identical answers.
- **Shell quoting now has a dedicated flat module (#2615, #2608).** ANSI-C decoding and
  quote-aware heredoc and here-string word spelling moved unchanged from `shell_lex.py` to
  `shell_quote.py`, restoring lexer headroom. Further compression of the lexer's governing
  contract was rejected because a line budget must not choose which behavior stays documented.
- **Checks do not gate concurrent stages in their own pipeline (#2422, #2331).** The workflow
  guard reports a downloaded payload used by another stage of its checksum group's pipeline,
  including a checksum ahead of `&&` under every supported shell. It still credits a use after
  a failing pipefail pipeline and a use gated by `} &&`.
- **ANSI-C numeric escapes now expose shell program options (#2470, #2331).** The lexer left
  `\\xHH`, `\\nnn`, `\\uHHHH`, and `\\UHHHHHHHH` encoded, so a decoded `-c` could run a fetched
  script while the guard read the step clean. It now shares Bash's ASCII escape table across
  words, heredoc delimiters, and here-strings, and fails closed beyond ASCII. Keeping only the
  four identity escapes was rejected because it hid executable option words.
- **A `set` is read the way bash counts it (#2559, #2560, #2561, #2331).** A `set`'s option values
  now count one per `o` LETTER, as bash counts them and as the program readers already did, and a
  `-o` value that is no option NAME refuses the whole `set`, as an unknown option LETTER already
  did (#2443). So `set -oo pipefail errexit` arms errexit -- the second `o` takes `errexit`, and
  `$#` stays 0 -- and `set -o foo -e` arms nothing, where bash answers `set: foo: invalid option
  name` and changes nothing. That second one was a fail-open: the guard credited a check bash
  never armed, and passed a step that runs its download with the checksum failing. A shell's
  command line is read the same way, so `bash -c -o foo P` hands over no program; the names were
  measured as the letters were -- bash 3.2.57 and 5.2.21 for the builtin, their union with dash
  for a command line, which takes `-o stdin` where bash exits 2 -- and the measured-shells list
  is now pinned against the two shell-name lists it has to agree with (#2561). Rejected: keeping
  the per-WORD value count the #2551 docstring defended, which is what read `set -oo pipefail
  errexit` as arming nothing at all.
- **A heredoc whose substitution closes before its body is read like Bash 5.2 (#2498, #2331).**
  The lexer refused `$(cat <<EOF)` before reading the lines below it, so one generic finding
  replaced the fetch sentence in every affected step. It now files that body first and skips its
  consumed source after parsing the close-line rest; Bash 3.2's code reading remains documented
  as the standing version disagreement. Keeping the refusal was rejected because it hid the
  actionable defect without adding safety.
- **Queued heredocs after an `EOF)` close are read in Bash 5.2 order (#2497, #2331).** The
  guard used a generic refusal because one pass met the first body's same-line rest before the
  later bodies Bash reads first. The lexer now retains two source offsets, reads those bodies
  from the next line, then parses the saved rest, so body and rest payloads get specific
  findings. A second lexing pass was rejected because it would duplicate state and cost; two
  `EOF)` ends remain fail-closed because Bash reports a syntax error.
- **Nested shell-group status reaches its enclosing failure gate (#2431, #2438, #2331).** The
  workflow guard credits `( CHECK || exit 1 )` under outer errexit and follows a checksum's
  failing `&&` list through consecutive closing groups to an outer `|| exit 1`. It still reports
  `exit 0`, disabled outer errexit, and unsafe enclosing-group contexts. Bash 3.2.57,
  Bash 5.2.21 and dash agree on the target and controls.
- **An unended substitution heredoc no longer hides a later `EOF)` close (#2494, #2331).**
  After one scan reached the script's end, `_Lines` used the exact-line index for every later
  body, so it swallowed a pipeline Bash 3.2 runs between a later `B)` and exact `B` line. An
  exact line now proves and bounds that later scan, which can find the earlier `B)` while staying
  linear; resuming every unbounded scan was rejected because hostile inputs restore quadratic
  cost.
- **A substitution heredoc's `EOF)` rest is read as Bash 5.2 parses it (#2492, #2331).** Bash
  drops that rest's first `;`, so the guard missed `EOFsh -c; 'curl … | sh')` while reporting a
  `true; curl … | sh` rest whose download never runs. `_Lines` now bounds one separator-token
  omission to that logical line and command, preserving its word break; a rest beginning with `;`
  is refused because Bash 5.2 rejects it while 3.2 can run later code. A candidate before `then`
  or `do`, including across a folded `\\`-newline, is refused too: Bash keeps that required
  separator, and omitting it hid an executable compound body. An unbounded Boolean and a
  character-only omission were rejected because they hid later-line and no-space payloads.
- **Artifact diagnostics preserve the failing stage (#2571, #1816).** Findings-file and
  dispatch-plan integrity rows now distinguish oversized, unreadable and unparseable inputs.
- **A delta map that dropped a whole path turns the on-diff gate INCONCLUSIVE (#2517).** The fourth
  counter joins #2405's broken-artifact measure (owner ruling 2026-10-02). `paths_dropped` — #2169's
  count of paths whose value in the hunk map was not a list of ranges at all, so the loader drops
  the path entirely — now turns a PASS into `gate: INCONCLUSIVE` on an active delta under the
  default on-diff gate scope when gate-eligible findings exist, exactly as
  `paths_emptied_by_drops`, `ranges_dropped` and a set `payload_malformed` already did (and, as
  for those three, a FAIL or OFF run over such a map now reads NOT CERTIFIED too). The
  DIRECTION is why: a dropped path LEAVES the map, so a HIGH in that file classified off-diff, left
  the gate's source set, and the run reported a PASS it had not earned — the fail-open mirror of
  the emptied arm, which admits such findings to the gate instead. A legitimate change shape never
  produces one (the loader drops a path only for a non-list value, and no `diff_map.parse` output
  carries one), so the ruling's "never fires on a deletion-only PR" property holds; the `[]`
  remainder stays disclosed and is never gated on. Disclosure-only was rejected: the stderr line
  and both report blocks already published the count, and a note beside a green gate is not a
  refusal to certify. The exclusion pin flips to an inclusion one, the reason names the counter and
  the direction so the operator finds the same number in `meta.coverage.delta`, and a new
  end-to-end pin reads INCONCLUSIVE for a map that dropped `b.py` with a HIGH at `b.py:3`.
- **Container cleanup failures reach coverage metadata (#2556, #1817).** A failed scanner
  container stop now records the same redacted, bounded detail sent to stderr in the tools
  manifest and both human reports, while preserving the original timeout and gate outcome.
- **A download written to a `$`-spelled path binds to its literal basename at use (#2442).** The
  mirror of #2345, and a fail-open until now: that issue bound a `$`-spelled OPERAND by its last
  part (`sh "$PWD/cuda_1.run"` after `curl -o cuda_1.run`), but a `$`-spelled DESTINATION only
  through a glob, so `curl -o "$PWD/cuda_1.run"` followed by `sh cuda_1.run` — the commoner
  spelling — read CLEAN while `sh cuda_*.run` was reported. bash 3.2.57, bash 5.2.21, dash, zsh
  5.9 and ksh 93u+ all run the download through the plain name, the `./` spelling and a
  `chmod +x` before it. One predicate in `workflow_operands` (`_last_part`) now answers both
  directions for an operand and for a command word, and it takes the same fail-closed looseness
  the operand side already took: what `$PWD` expands to is not evaluated, so a same-named file
  under another directory binds too (`sh scripts/cuda_1.run`), which over-reports rather than
  reading the shell. The destination's basename must be WRITTEN — `curl -o "$PWD/$F"` still binds
  nothing by name, and a lifted `$(…)` in that basename is carried through it — and the checksum
  side stays exact: `echo "<sum>  cuda_1.run" | sha256sum -c -` does NOT credit a fetch to
  `"$PWD/cuda_1.run"`, because loosening the side that CHECKS would clear bytes nothing read.
  Half of the `PATH_DIRS` gap entry (#2308) closes with it: the `$HOME/.cargo/bin` spelling of a
  download run by its bare name is now reported, which every shell runs once the file is
  executable and that directory is on PATH. The calibration pool's 4,642 real jobs answer
  identically.
- **Bounded artifact reads share typed outcomes (#2554, #1816).** Evidence scope now uses the
  common no-follow reader; verdict loaders consistently label size, I/O, special-file, and parse
  failures, and run-artifact readers delegate limit validation to the same primitive. The 4, 8,
  and 16 MiB caps now state which source, verdict, or aggregate metadata class each one bounds.
- **The self-scan matrix gives `CI` explicit `Shell` and `Workflows` layers (#2521).** Adding
  `shell_heredoc.py` filled the 48-file leaf, so the next `.github/**` file would have replaced
  the authored `CI` cell with engine-balanced `CI_1` / `CI_2` chunks. The layers hold 9 and 39
  files, respectively, keep each test beside its code, and put `CI` behind the shared 40-file
  headroom guard. This costs one extra review cell now; waiting would make the next unrelated CI
  contributor inherit an automatic split and its unplanned test inventories.
- **Broken batch stop predicates identify their failure point (#2555, #1817).** The runner logs
  the completed entry and final predicate frame inside the existing redacted 200-character
  detail budget, then keeps yielding launched work and still honours a later stop.
- **Tolerant verdict extraction keeps small wrapped bundles (#2553, #1816).** A fixed 64 KiB
  minimum scan budget reaches JSON after shallow nested or 256-open-brace prose while the
  length-scaled caps still bound large inputs.
- **Interrupt cleanup retains child process groups (#2550, #1816).** Ctrl-C snapshots each
  validated group, waits once for the shared SIGTERM grace, and escalates before reaping any
  leader, so a resistant descendant cannot escape SIGKILL. The price: a retained leader is a
  zombie that keeps its group alive, so every interrupt now waits the full `INTERRUPT_GRACE`
  (5 s) before SIGKILL where it used to return as soon as the leader died.
- **Family PR review discloses missing agents (#2546, #1817).** Missing finders and verifier
  votes become explicit incomplete-review facts and log lines; a partly verified finding cannot
  enter the confirmed or dropped lists.
- **Kimi credential cleanup reports partial failures (#2545, #1817).** Cleanup distinguishes
  removed, absent and failed paths; retained-home and exit messages no longer claim secrets are
  gone when an unlink failed.
- **The workflow guard checks shell option letters against the shell's own table (#2443, #2444,
  #2475).** Three readings of a shell's options read the WORDS and not the letters, so each took a
  spelling the shell refuses for one it runs. A `set` carrying a letter bash's builtin lacks —
  `set -Z -e`, `set -eO foo` — was read as turning errexit back on after a `set +e`, so a checksum
  written after it was credited; bash answers `set: -Z: invalid option` with rc 2 and changes
  nothing, and bash 3.2.57 and 5.2.21 both run the download with the check failing (#2443). A
  child shell's `-O shopt` was read as the `set` builtin's `-O`, which takes no value, so
  `bash -O extglob -ec '…'` read `extglob` as the end of the options and never saw the `-ec`: the
  step was refused as running where no `-e` holds, though both bashes stop the child at the
  failing check and a `sh` that refuses `-O` runs nothing at all (#2444). And the option skip
  after `-c` (#2332) read on to the program through a word no shell takes, so
  `sh -c -K 'curl … | sh'` was FLAGGED although bash 3.2.57, bash 5.2.21, dash and bash-as-`sh`
  all exit 2 before they read the program (#2475). One table of letters answers all three, in
  `workflow_programs` (`SET_OPTIONS`, `SHELL_OPTIONS`), read there by `_past_options` and above it
  by `workflow_gating._errexit`: bash 5.2.21's `set` letters for the builtin (`-r` among them,
  and not the `i`/`I` that 5.2 refuses while surviving), and for a command line their union with
  its own `-c`, `-i`, `-l`, `-r`, `-s`, `-D`, `-O` and the `-I`/`-V` dash takes — every letter
  measured on bash 3.2.57, bash 5.2.21, dash, zsh 5.9 and ksh 93u+. On a command line the refusal
  is PER SHELL, because that measurement found zsh running twenty of the letters bash refuses and
  ksh running `-G`: `zsh -c -K 'curl … | sh'` fetches and RUNS the download under either bash as
  the step's shell, so only `sh`, `bash` and `dash` are read as refusing, while zsh, ksh, the
  unmeasured `ash` and a shell NAMED by a word rather than written (`$X -cK`, `${X:-sh} -cK`,
  whose program #2337 and #2344 report in their own words) are read ON, exactly as before. Both
  directions fail CLOSED: a `set` with an unknown letter turns NOTHING on (a `+e` in it still
  reads as off, and bash leaves errexit where it was), and an invocation with one hands over no
  program, so nothing runs and the rule is silent, which the gap list now says in the guard's own
  voice. `set` keeps its own reading, where `-O` is no option at all (the `set -O foo -e` pin is
  unchanged) and a LONG word is a refusal too, since bash's `set` has none: `set --posix -e`
  leaves errexit off and the download runs on both bashes, while `set -- "$@"` is the positional
  spelling and reads as it always did. Two spellings stay fail-closed on purpose: a letter in a
  SEPARATE word ahead of `-c` (`sh -K -c '…'`) is read on, and so is an option word that is not
  all letters: bash, dash and ksh refuse `-1`, `-I{}` and `-nw5`, but zsh RUNS `-1`, and all five
  shells run the program after `sh -c -u$X P` wherever `X` is empty.
  Over the 11 probe corpora (439,716 rows) 10 rows go FLAGGED→CLEAN, every one an option word of
  letters after `-c` handed to a shell of the measured family that refuses it — `-F`, `-g`, `-K`,
  `-fR`, `-S`, `-w`, each rc 2 on bash 3.2.57, bash 5.2.21, dash and bash-as-`sh` with nothing
  fetched and nothing run — and 4 two-step rows lose exactly the sentence of the step that went
  clean; 0 rows go CLEAN→FLAGGED and no other answer moves, in the same 14 rows before and after
  the per-shell scoping. Over the 3,200-workflow calibration pool (4,642 jobs) no job's answer
  changes, and a text census finds no job carrying a `set` letter outside the table, a refused
  option word after `-c`, or an `-O` at all.
- **Timeout cleanup retains the session group identity (#2532, #1816).** An unpolled leader that
  Darwin reports gone cannot hide its live descendants, which still receive the SIGKILL phase.
- **Verdict ingestion has bounded resources (#2531, #1816).** Advisor verdicts use a shared
  8 MiB regular-file reader, and tolerant JSON extraction bounds memory and compatibility work.
- **Runner batches name a broken outage stop predicate (#2544, #1817).** Work still continues,
  while one redacted and bounded diagnostic tells the operator the short-circuit was unavailable.
- **Scanner timeout cleanup names container-kill failures (#2543, #1817).** Missing or empty
  container ids, launch errors and nonzero kill exits are reported without replacing the timeout.
- **Image freshness lookup failures now fail monitor runs (#2542, #1817).** Push runs retain the
  warning fallback, while scheduled and manual checks return an error with the API diagnostic.
- **Family PR review bounds verifier fan-out (#2535, #1816).** Each of five finders is limited
  to 25 findings by its output schema and again before three-way verification. The result and log
  disclose truncation by dimension, bounding a run at 375 verifier calls.
- **Report chunk sizing is linear in its findings (#2534, #1816).** Each finding is serialized
  once for sizing, with exact UTF-8 envelope and separator costs tracked incrementally.
- **Evidence-scope import scans are bounded and memoized (#2533, #1816).** Each source is a
  regular file read at most once per entry and only through a 4 MiB byte cap before parsing.
- **A literal shell's dynamic program is read as unread, like a dynamic shell's (#2483).**
  `workflow_programs.scripts` hands on a shell's `-c` operand — and `eval`'s — as the script text,
  and a word that is ENTIRELY parameter expansion spells no command for `workflow_forms.flattened`
  to read, so `curl -fsSLo tool …` beside `sh -c "$P"` read CLEAN while bash 3.2.57 and 5.2.21
  both run the download once `$P` is `sh tool`; so did `bash -c "${P}"`, `eval "$P"`,
  `sh -ec "$P"` and `${X:-sh} -c "$P"`. The `$CMD -c "$P"` twin has been REPORTED since #2465's
  fix round (`candidates` hands a `$` command word's program to `unread_program`): one dynamic
  program word, two answers, decided by whether the shell happened to be spelled out.
  `dynamic_program` now reads that word wherever a shell takes one, and `unread_program` reports
  it `Idle`, kept under #2481's predicate exactly as the twin is — beside a fetch this guard
  reports, and nowhere else, so a credited download leaves it standing nowhere. `$@`, `${@}` and
  `$*` are one thing in three spellings and read alike (`set --` gives a step positionals), and a
  nest of any depth is still all expansion (`${A:-${B:-${C}}}`), since braces are counted rather
  than matched by pattern. Three spellings are NOT this rule and read as they did: a lifted
  `$(...)` marker, whose inside the guard's own walk reads (`sh -c "$(cat tool)"`), a string
  MIXING literal text with an expansion (`sh -c "echo $X"`), and a word holding text of its own
  (`sh -c "${A}x"`). The rule also speaks LAST: a value where a shell reads its options keeps
  #2344's reason, which `_weighed` makes LOUD where a word after it fetches
  (`sh $X -c "$P" 'curl … | sh'`), and this rule's droppable one would have replaced it. Where
  #2341's `carried` names the same statement louder — `x=$(curl …)` then `sh -c "$x"` — the quiet
  sentence is dropped and the carried one stands alone, the dedup `_Unprinted` already had for
  printers (one class for both now, `_Quiet`). Five readings fail CLOSED on purpose: the reader
  drops quotes, so `sh -c '$x'` is reported though bash runs nothing unless `$x` is exported;
  `eval set -- "$P"` is the getopt idiom and runs none of the value as a command, unless it holds
  a `;`, which `eval` does run; a cut (`eval "${x//$'\r'/}"`) is reported as an unread word,
  though the guard still does not follow the download through it; `curl … | sh -c "$P"` says both
  of its defects, the stream and the unread program; and `sh -c "$*"` says this rule's sentence
  beside the pattern one #2294 already gave the script inlined from it. The value gap the gap list
  keeps is untouched: `sh -c "sh $X"` runs `tool` where `$X` names it and still reads clean,
  because no word follows the value. Over the 11 probe corpora (439,716 rows) 42 rows gain the
  sentence, all of them already flagged, with 0 CLEAN→FLAGGED, 0 FLAGGED→CLEAN and no reason lost;
  over a 1,372-row grid of the shape itself 190 rows go CLEAN→FLAGGED, every one beside an
  uncredited download or a carried one, and its 70 `sh $X -c` rows read exactly as main does. Over
  the 3,200-workflow calibration pool (4,642 jobs) three jobs hand a literal shell such a word —
  mlflow `cross-version-tests.yml :: test1` and `:: test2` (`eval "$MATRIX_INSTALL"` and two
  more), vector `k8s_e2e.yml :: test-e2e-kubernetes` (`bash -c "$2"`) — and none of them fetches,
  so no job's answer changes.
- **A hand-edited non-string manifest run_id is refused at the read, not crashed on in Popen
  (#2525).** `phases/synthesize` and `phases/tools` both thread `manifest.get("run_id") or ""` into
  the child's argv unconverted, and `run_manifest.load_manifest` type-validated only `host` while
  `run_tag` slugs the id through `str()` — so a `"run_id": 7` edited into `run-manifest.json`
  survived the load, stayed truthy, and reached `subprocess.Popen` as a non-string argv member. The
  `TypeError` that raises is covered by neither `phases/child`'s `OSError` → `DriverError`
  conversion nor `driver.run`'s `except (DriverError, ValueError)`: the driver died with a
  traceback and no `status:` line at all. The loader now requires a PRESENT `run_id` to be a
  non-empty string, which covers every phase that threads it at once rather than one flag at a
  time — `phases/engine` hands each phase the dict this loader returned. A bad one is DISCARDED
  with a stderr line naming the field and the value, exactly as an unknown `host` is, and never
  raised: this same read is what `runio._run_tag` calls on every artifact path resolution, the
  `--reset` recovery path included, so an exception here would be one `--reset` could not clear
  (the failure `run_tag`'s own docstring records). The driver then takes its existing
  corrupt-manifest path — clear the derived artifacts, rebuild from the real CLI args — and ends
  with a `status:` line. An absent or null `run_id` is left alone, like an absent host: the setup
  namespace and every pre-key manifest carry none, and the consumers already read it as an
  absence. #2107's own residual assertion stays as it is, because it measures the phase handed a
  manifest dict directly; its cover is the loader's new test class.
- **Discovery uses the canonical confinement predicate (#2450, #1768).** `discovery.py` carried a
  third private `_within`, with its own cached root realpath, beside the two names that already
  alias `claim_scope.confined_to_root`. Substituting the canonical one naively would have been a
  regression and not a cleanup: it JOINS the path onto the root it resolved, and all three callers
  handed it a candidate they had already joined — so a RELATIVE repository root got double-prefixed
  (`confined_to_root("repo", "repo/x")` resolves `repo/repo/x`), and a decoy directory of that
  name, one a reviewed tree can simply commit, would have answered for an escaping symlink and
  read it as confined. Each caller now passes its repo-relative path instead: the changed-files
  listing, the git-listing `isfile` probe, and the `--scope-file`/`--scope-files` clamp. The cached
  root realpath moved DOWN with it, into `claim_scope._real_root`, so the performance property the
  private copy existed for survives the move — one `realpath` of the root per distinct root, not
  one per candidate on a whole-tree expansion. Only an ABSOLUTE root is memoized there, because a
  relative one names a different directory in every process cwd. Both shapes are now pinned, the
  working-directory decoy and the escaping symlink, in `tests/test_claim_scope.py` (the predicate)
  and `tests/test_discovery_scope.py` (the two call sites).
- **The workflow guard keeps an unread program only beside an unverified fetch (#2481, #2499).**
  Owner rulings 2026-10-01. The job-level predicate in `workflow_forms.kept` was "the job
  downloads something", so a program the guard cannot read — `$PYTHON -c '...'`, a `$CMD -c`
  candidate, a script handed to a shell inside a `$(...)` — was reported beside ANY fetch,
  including a download its `sha256sum -c` cleared and an API `curl ... | jq` that is no download
  at all. It is now reported only beside a fetch the guard itself reports: a download no checksum
  clears (the unread program is counted as the use the checksum was owed, ADDED to the uses
  `_defect` can read, so a checksum BEHIND such a program clears only the uses in front of it), a
  `curl ... | sh` stream, an unresolved transfer, or a download no file holds — `x=$(curl ...)`,
  the `carried` shape, and one a pipeline writes past the fetcher (`curl ... | cat > f`,
  `| dd of=f`, `| sponge f`, `| cat | tee t`, none of which `parse_fetch` binds a destination to;
  `workflow_forms.unbound`). Two readings are deliberate and fail closed: the report names the
  unread program and not the download that makes it one (one sentence, as before), and a download
  a variable holds keeps the reason even where only an `echo` reads it, because no file exists for
  a checksum to name. The same predicate now governs the foreign-language stdin program
  (`python3 - <<'EOF'`, `node <<'NODE'`, at the top level or inside a substitution), #2499's
  owner ruling (b), decided once for both; the EXPANDING-heredoc report is
  untouched and still loud with no fetch at all. Over the 3,200-workflow calibration pool 31 jobs
  clear and none newly fails: metabase `pr-env.yml :: deploy_pr` (`$ADMIN -c` psql beside an
  OIDC-token `curl | jq`) and 30 jobs whose heredoc program parses a `pom.xml`, YAML, HTML or
  JSON and fetches nothing.
- **`diff-hunks.json` is now bound to its `groups.json` generation (#2107).** One discovery child
  writes the hunk map and then the inventory, as two independent atomic writes, and only the
  inventory carried a run binding — so nothing compared the surface the review covered with the
  diff the gate scoped to. A probe traced every driver path and could not assemble the mixed
  pair (the pre-child clear, the hunks-before-groups write order and the per-run folder each stop
  it), but a hand-run `discovery.py` followed by a hand-run `synthesize.py` does — `--groups` is
  auto-discovered, `--diff-hunks` is not, so the operator supplies one half and inherits the
  other — and it was accepted in silence: 0 of 1 gate-eligible HIGH classified on-diff against
  the other generation's map, a green `--gate-scope on-diff` gate over a change nothing measured.
  The driver now stamps both halves with this run's `run_id`, and the loader gains an optional
  expected generation that rejects a foreign or absent stamp as the new `payload_malformed` value
  `generation-mismatch`. The refusal is REPORT-VISIBLE, not stderr-only: the synthesize phase
  hands the pair over with `--diff-hunks-run-id` even when it can already see the mismatch, so
  `meta.coverage.delta_artifact` publishes the reason instead of reading null like a run that was
  never a delta one — the gate is identical either way (no `base` survives, so the delta is
  inactive and the scope widens to whole-repo, which fails closed). `synthesize.py` defaults that
  expectation to the stamp on the `groups.json` it read, so the hand-run pair is bound too; an
  explicit `--diff-hunks-run-id` overrides it, and an unstamped inventory expects nothing, which
  keeps every direct caller and hand-written artifact reading byte for byte as before. The path
  is withheld in one case only, a manifest whose `run_id` is not a non-empty string: there is
  nothing to thread (the child cannot launch on such a manifest either way; #2525).
- **The self-scan matrix's `RepoProfiling` group has layers (#2273, #1784).** It sat AT the 48-file
  group cap, so the last two discovery policies to come out of `discovery.py` were parked in
  `Orchestration:Core` instead of claimed beside it — `dot_paths.py` (#1784) and
  `exclude_carve_out.py` (#1757). Owner-approved split into `RepoProfiling:Discovery` (24 files),
  the half that runs on every review — the file walk, the grouping of that listing against the
  matrix, the delta map, the committed-plan contract and the tests axis — and
  `RepoProfiling:Profiling` (26 files), the one-time setup and the durable profile it writes: the
  grouping engine, the surfaces/floor model, the committed-config names and trust classes, setup
  flow and proposal, and the catalog data those read. Both parks are reversed — the two modules
  are claimed by `Discovery`, beside the module they came out of and their only runtime caller —
  and `tests/test_matrix_coverage.py`'s 40-file headroom guard is now parametrised over
  `RepoProfiling` as well as `ToolAdapters`, with a second guard so a renamed group cannot make it
  vacuous. Matrix and tests only: no Python module moved.
- **The driver loop waits a bounded backoff before re-launching a failed entry (#2506, #1813).**
  Headless only: `min(2 ** streak, 8)` seconds plus up to 25% jitter before an entry whose last
  launch failed is launched again — 2 s then 4 s, since the per-entry cap of 3 parks it after
  the third — so a transient hiccup no classifier recognises no longer spends all three of its
  launches in seconds. A streak of 0 waits nothing and session mode never waits, a human
  advancing that loop. `runners/outage.py` owns the schedule, the line and the mode check, so
  `orchestrate.py` gained one call and no lines.
- **Every workflow job declares its token posture (#2247, #1784).** A fleet test rejects jobs
  whose effective `permissions:` would come from the repository default, while accepting job
  blocks and workflow-level blocks inherited by every job.
- **The shell lexer's heredoc body index moves to `scripts/shell_heredoc.py` (#2496).**
  A pure move: answers are byte-identical on the 11 corpora and the calibration pool; the lexer
  leaves its 700-line ceiling.
- **A SIGTERM to a hand-run `run_tools.py` now ends its scanner containers (#2507, #1814).**
  `__main__` runs `main` through `procgroup.sigterm_as_interrupt`, as `driver.py` has since
  #2199, so a plain `kill` raises the interrupt the teardown handles instead of ending the
  process at the default disposition and orphaning a `docker run --rm` client. The capture in
  `tools/base.py` now ends the child's tree on any interrupt mid-read, before closing the pipes.
- **A target's `exclude_paths` no longer hides the SEC surface (#1757, AGT-1355709320).** Owner
  ruling 2026-09-25: a target-authored `exclude_paths:` may not take a file the objective SEC floor
  matches out of the SEC domain. Those files are no longer pruned — they form one dedicated
  SEC-only review group, `exclude_paths_sec_carve_out`, whose coverage is pinned to `["SEC"]`; every
  other domain still honours the exclusion and the files join no other group. Disclosed in three
  places: `groups.json` and `meta.coverage.exclude_paths_sec_carve_out` carry the globs, the paths
  and the count, and discovery's stderr line carries the globs and both counts. The report block
  renders as one line in the Markdown and HTML coverage sections. Absent when nothing is
  committed, `count: 0` when globs carved nothing. `--pr` mode is identical, the tool axis is
  untouched, and the `/helm/` `/k8s/` substring half of SEC-71240568 was already fixed by #1838.
- **The security workflows' pull-or-build step can now finish its fallback build (#2509, #1818).**
  In `security.yml` and `security-fork.yml` the step ceiling equalled the 600 s pull deadline, so
  a stalled pull left the local build zero seconds; the ceiling is 25 min (pull 10 + a measured
  ~11 min build + margin), under the job's 30, and a test pins the inequality.
- **A provably broken diff-hunks artifact now turns the delta gate INCONCLUSIVE (#2405, #1783).**
  On an ACTIVE delta under `--gate-scope on-diff`, a non-zero `paths_emptied_by_drops`, a non-zero
  `ranges_dropped` or a set `payload_malformed` refuses a PASS for a run carrying gate-eligible
  findings — the map that chose the gate's scope is provably damaged. It is the
  `zero_hunk_gate_gap` posture (#2178, narrowed by #2222) over a map that still carries ranges,
  which in practice means the two drop arms: the older rule wins when both hold, and the one
  `payload_malformed` value an active delta can carry empties the map, so #2178 answers there.
  Knowingly missed: a truncated map whose paths arrived `[]`, which nothing tells apart from a
  deletion-only, binary, mode-only or same-content rename change — the rest of
  `paths_without_ranges` stays disclosed and is never gated on, and the schema descriptions now
  say exactly that.
- **An advisor's differing OCRDb code is recorded, never applied (#2101).** The schema and
  `evidence.apply_verdict` always said so; `apply_verdict_quality`, later in the live call order,
  rewrote the finding's `code` from the same value that record holds, so each step read correctly
  alone. It no longer reads the verdict's `code` at all, and the two fields that described the
  mutation are retired: the finding's `code_corrected_by` and
  `meta.coverage.ocrdb.code_corrections`. The catalog-strain signal still reads
  `provenance.advisor_code`, and the advisor prompt now asks for a second opinion rather than a
  correction. The rejection/backup policy is unchanged, and severity is still mutated only by the
  override discipline -- now measured against the PUBLISHED code's default, so a reason-less
  override reverts to the panel's code rather than to the advisor's.
- **nvd-cache.yml no longer publishes a database whose sync the deadline killed (#2508, #1818).**
  `timeout` exit statuses 124 and 137 now fail the sync step; other non-zero statuses stay
  tolerated as per-record errors and the DB is verified by the size floor as before.
- **Five flat-import fallbacks now catch `ModuleNotFoundError`, not `ImportError` (#2510, #1824).**
  `score_gate`, `host_disclosure`, `diff_map`, `model_resolver` and `safe_git` spelled the arm one
  class wider than every other fallback, so a package that resolved and then broke inside was
  retried flat instead of surfacing; `tests/test_module_identity.py` now pins the narrow class.
- **`tests/test_citations.py` no longer imports `_version` flat inside a test (#2511, #1824).**
  The module under test binds `scripts._version`; the in-test flat import built a second module
  object, the double-module hazard `tests/test_layout.py` rule 2 exists to prevent.
- **The last `0o755` chmod literal in a test is gone with its dead helper (#2389, #1777).**
  `tests/_test_helpers.argv_through_shell` had no callers after #2161 pinned an absolute
  interpreter; deleting it removes the standing bandit B103 MEDIUM the HIGH-only gate let stand.
- **Direct discovery owns its implicit delta map under the selected repository (#2102).**
  Delta runs without `--out` write `<target>/.panopticon/diff-hunks.json`, and whole-repository
  runs clean that same path. Explicit outputs still keep the map beside `--out`.
- **Tools-image pins move together: semgrep 1.178.0, filelock 4.0.3, starlette 1.7.0.** Dependabot's
  requirements-only bump (#2501) failed the closure test, which ties `ARG SEMGREP_VERSION` to the
  pinned file; both moved here and the wheel digests were regenerated by `bump_pins.py`.
- **The shell lexer reads, or refuses by name, a heredoc delivered inside a substitution (#2331).**
  The body of a heredoc in `$(...)` whose `EOF` and `)` stand on lines of their own is read (#2336).
  A heredoc in a substitution ends at an `EOF)` line, as in bash 5.2, not a later `EOF` (#2343).
- **The workflow guard reads the command and program forms its reviews found unread (#2331).**
  The command behind an `A+=x`, `a[1]=x` or `arr=(a b)` prefix is now read, as `X=1`'s is (#2348).
  The program after option words that follow `-c` is read: `sh -c -e P`, `sh -c -- P` (#2332).
  Values before a shell's program are read: `sh $X 'P'`, `sh $'-c' P`, `-eo pipefail [-]c` (#2344).
  A `$` command word that may be a shell is read: `${X:-sh} -c P`, `$CMD -c P` (#2337).
  A double-quoted `-c` or `eval` program is read as bash hands it, `\$` unescaped (#2342).
  The program an `echo` or `printf` pipes into a shell is read: `echo 'sh tool' | sh` (#2333).
- **Semgrep scans real test code despite target ignore files (#2109, #2055).** The pinned argv
  owns its ignore policy, keeps generated/package-manager exclusions, drops the four default
  test-path exclusions, and applies disclosed `exclude_paths`; live real-Git and non-Git probes
  cover both target ignore formats. The bounded 5,000-result ingest cap retains the measured
  2,274-result self-scan. For the initial baseline transition, CI rescans the exact base commit
  with the new policy, so standing test findings match while PR-added findings still gate.
- **PR worktree reuse parses Git's machine records (#2100).** Acquisition reads NUL-delimited
  porcelain paths, so spaces no longer hide a registered tree or truncate the main-worktree path
  in transport-setting remedies.
- **Golden captures reject image-mount paths (#2261, #1768).** SARIF normalization reads the
  shared scanner mount, capture reroots fixture payloads before verification, and any surviving
  fixture or probe prefix prevents the golden write (a surviving `src/` is a real directory).
- **Reports disclose tool findings that cannot be placed (#2260, #1768).** The JSON counts
  active findings by adapter, the HTML scanner context renders those counts, and the adapter
  contract accepts an empty `location.file` only beside `path_resolution: unresolved`.
- **A literal matrix entry that stops existing now reds (#2454, #1784).** The ~320
  `match:`/`tests:` entries with no glob character are checked against the tree, beside the
  allowlist guard, so a renamed file cannot leave its leaf listing dead text while the file
  itself falls back to a sibling glob; a stale `!` negation is caught the same way.
- **The legacy-only config refusal keeps its own remedy too (#2453, #1784).** A tree carrying
  only `.panopticon/groups.yml` is refused with the `migrate-config` move that fixes it, and no
  longer with "fix it or re-run `driver setup`" appended -- setup refuses that tree outright.
- **`ToolAdapters` gains a `Contract` layer (#2315, #1784).** The adapter base, SARIF
  normalization and their contract tests move out of `Integration`, which sat at the 48-file
  cap; a headroom guard now reds any `ToolAdapters` leaf above 40 before the cap does.
- **The readiness matrix row's remedy fits a refusal that names its own install (#2384, #1784).**
  A config refusal that already names its own remedy (`pip install pyyaml`) no longer has
  "fix it or re-run `driver setup`" appended, which setup could not deliver; every other
  refusal keeps it.
- **Pip-audit uses the shared path-confinement predicate (#2262, #1768).** Requirement
  candidates become absolute before the shared check, so relative target roots still reject
  escaping symlinks; the private duplicate is gone.
- **One `setup_proposal` in a driver-shaped process, at call time too (#2413, #1766).** The
  six lazy sites in `setup_flow` import it through the package inside their function bodies --
  that module has no flat mode -- and `discovery`'s lazy site keeps the guarded flat fallback
  its own flat mode needs, so the grouping engine imports it the same way and the call-time
  census keeps its three named residuals.
- **Adapter and rollback comments describe current behavior (#2190, #1784).** Brakeman's
  fallback explains that it supplies CWE citations when a capture omits `cwe_id`; the existing
  rollback prose already describes termination of registered child process groups.
- **A delta run's fixture disclosure describes the changed set (#2410, #1784).** The
  `--scope-changed` pass starts its fixture-root list empty, so `excluded.fixture_dirs` and the
  stderr line name only roots pruned from the surface the run reviewed, like every other
  disclosure on a delta run.
- **A locus-free finding is legal in the prompt and legible in the gate (#2409, #1784).** The
  domain-panel template now says a repo-wide catalog or coverage gap omits `location` instead
  of inventing a `file`, and the security gate's row prints `?` for a file it does not have,
  as the HTML and Markdown renderers already do.
- **The workflow guard credits a checksum only where its failure stops the step (#2331).**
  A top-level `set +e`, `eval`'d or not, now turns errexit off for the checks after it (#2335).
  A step's `shell:` now seeds errexit and pipefail; a piped check gates only under pipefail (#2338).
  A check ahead of `&&` now clears only what its list runs, unless the list fails the step (#2334).
  `shopt -uo` and `builtin set` turn either off too; bash's `shopt -so` turns one on (#2335, #2338).
  The guard reads `sh "$PWD/f"`, `x=$(sh f)`, `cd s; sh ../f*` and spaced `case` arms (#2345).
  `x=$(curl ...)` then `eval "$x"`, `sh -c "$x"` or `echo "$x" | sh` is now reported (#2341).
- **setup_proposal has one identity in a driver-shaped process (#2256, #1766).** Its three
  catalog imports take the guarded package-first shape its siblings use, so the flat copy every
  setup path reaches binds the same catalog modules the package side does and the import-time
  census's residual shrinks to the modules the flat `--repo-scan` entrypoint still owns.
- **One owner for the container privilege drop (#2150, #1767).** The tool runner, the fixture
  runner and the egress sidecar all splice `scanner_config.privilege_drop_flags`. The daily fixture
  lanes spell the same two flags out, keeping the ceilings exemption the workflow now states. The
  runner's private aliases are gone, so one patch of the owner reaches every launch.
- **A reconcile resume rebuilds the comment it posted (#2157, #1780).** The progress receipt
  records the repo root the scrubbed comment was built under, every body on that plan is built
  under that root, so a resume from another checkout confirms the posted comment instead of
  dead-ending on a body it could never match.
- **Delta runs are capped and disclosed like whole-repo runs (#2376, #2377, #1784).** The
  `--scope-changed` surface is bounded by `DISCOVERED_FILES_MAX`, the `discovery` block says which
  surface its numbers describe (`surface`), and both paths publish what the policy pruned by class
  (`pruned`: dot-path, excluded-dir, `.git` segment; null on the non-git walk, which counts nothing)
  with one stderr line when any count is non-zero.
- **A whole-file finding is legal end to end (#2174, #1784).** The emission envelope no longer
  requires `location` (the report schema never did), `validate_report` warns only on a missing
  `location.file` rather than on every finding without a line, and the security gate prints `?`
  for a missing line like the other renderers.
- **A non-hashable tool_name denies instead of crashing the guard (#2394, #1777).** The write
  and read guards test the tool roster inside their never-crash envelope, so a list or dict
  `tool_name` prints a deny instead of escaping `main` with a non-blocking exit; the read
  guard's envelope comment now calls its early returns permissive.
- **file_issues renders malformed sibling fields as absent (#2398, #1768).** A string
  `citations`, `occurrences` or `additional_loci` value, a non-dict locus and a non-string
  `location.file` no longer abort the filing run, and `reconcile_apply` refuses an unreadable
  source report by name through its own `refusing:` path.
- **Tell a broken rangeless path from a legitimate one (#2386, #1783).** Both delta blocks carry
  `paths_emptied_by_drops`, the subset of `paths_without_ranges` a broken artifact produced, and
  the stderr disclosure names the rangeless paths (first ten, escaped).
- **Repair the artifact-carried delta keys at the read, then pin them (#2382, #1783).** The
  diff-hunks loader reads the seven keys it copies verbatim into `meta.coverage.delta` as null
  when they carry a value of the wrong type, lists them in
  `meta.coverage.delta_artifact.keys_repaired` and on stderr, rejects an unsupported
  `schema_version` as a fourth `payload_malformed` reason, and the report schema now type-pins
  those seven keys.
- **Read the committed config once per discovery run (#2269, #1761).** Exclusion and group
  readers share per-call snapshots, so one resolver disclosure reaches the operator once.
- **Retire the dead rule-id pre-filter (#2366, #1768).** `ingest_tools._rule_id` no longer
  re-filters the fields `evidence.tool_rule_id` already reads totally, and coerces a non-string
  rule id to text before the CWE regex sees it.
- **Escape request-sourced strings that reach a terminal (#2379, #1783).** The dispatch script
  escapes any request-sourced string outside a safe charset (the checkpoint, the progress label,
  the missing-id line), and the driver loop renders its pending-id lists with `%r`.
- **Give unmatched groups a usable readiness remedy (#2268, #1761).** The failed preflight row
  now offers direct repair before the setup command that refuses an invalid committed config.
- **The stored-report path fails loud, not with a traceback (#2372, #2373, #1768).** `file_issues`
  and `evidence` read `location` / `provenance` / `evidence` through the one guarded reader each,
  so those three malformed shapes no longer abort the filing run. `reconcile.load_report` refuses
  unparseable JSON, a non-object report, `meta`, part or discarded-claims sibling and a non-list
  `meta.parts` with one reason naming the file (and the key where there is one), which both CLIs
  print before exiting 2.
- **Name integrity failures in HTML (#2265, #1761).** The NOT CERTIFIED banner renders
  every truthy certification-sinking reason from the shared integrity table.
- **The write guard fails closed when it crashes (#2391, #1777).** `main` now runs the
  interpreter check and the adjudication inside the read guard's never-crash envelope, so an
  unexpected exception becomes a deny response instead of a traceback and a non-2 exit the host
  treats as a non-blocking error -- which let the Write it exists to deny proceed.
- **Keep mixed cross-domain metadata renderable (#2266, #1761).** Summary aggregation sorts
  missing and named cell domains deterministically instead of raising before the report renders.
- **The Claude write guard runs under the driver's own interpreter, and every guard hook runs
  it isolated (#2161, #2163, #1777).** `write_guard_hook`'s registered `PreToolUse` command began
  with the bare word `python3`, and nothing resolved it: the CHILD looks that name up in ITS PATH,
  which `runners/children.py` rewrites through `executable.resolve`, dropping every entry inside
  the review root. An operator whose `python3` came from the reviewed repo's own `.venv/bin`
  therefore armed a hook the child could not start -- and a hook that cannot start fails OPEN, so
  write confinement was off with nothing said. The command now names the driver's own validated
  `sys.executable`, the binding `read_guard_hook` and the Kimi hooks already use, and `install`
  refuses before writing either file rather than arming a hook it cannot start. That refusal is
  computed on ACCESS rather than at import (#2006), because a raise inside the hook process is
  itself fail-open. `-I` now pairs with the pinned interpreter on the Kimi hooks, so a
  `sitecustomize` cannot choose code for a confinement decision (#1996), and their guard
  round-trip probe spawns the tokens of the armed command itself rather than a copy of them, so
  the evidence can no longer describe an argv the per-run config never registered (#2163).
- **Keep HTML evidence disclosures fail closed (#2195, #1774).** The coverage header counts
  the same active findings as its collapsed unverified section, and malformed evidence values
  render there without crashing.
- **Surface dropped token-ledger inputs (#2171, #1782).** Usage collection counts a present
  non-object `usage` value in its existing drop tally, and successful driver-side collection
  forwards the bounded collector disclosure to stderr.
- **A diff-hunks path with no ranges is disclosed (#2381, #1783, ARC-B8 follow-up).** A map that
  NAMES a path and gives it no range -- `{"a.py": [[1, 5]], "c.py": []}` -- classified every
  finding in `c.py` as on-diff and nothing anywhere said so: the loader drops nothing (an empty
  list is well formed), both #2169 loss counters read zero, and the two whole-map disclosures
  need `hunks_ranges: 0`, which `a.py`'s one real range denies. It is the only FAIL-OPEN shape in
  this family -- under the default `--gate-scope on-diff` those findings reach the gate's source
  set as if the diff had touched their file. A third counter now publishes it,
  `paths_without_ranges`, in `meta.coverage.delta` and `meta.coverage.delta_artifact` alike, plus
  one stderr line naming the count and the artifact. Classification is UNCHANGED on purpose:
  `diff_map.parse` emits a rangeless key for a file the diff changed without ADDING a line -- a
  pure deletion, a binary or mode-only change, a 100%-similarity rename -- and deleting a line
  can introduce a finding (a removed check), so classifying it on-diff is that module's
  documented contract. What was wrong is that a truncated or hand-edited map is
  indistinguishable from that legitimate shape; the counter is the input a later gate rule would
  need to tell the two apart.
- **Share reply publication and artifact roots (#2346, #1820).** Reply persistence uses the
  common atomic JSON writer, which cleans opened staging files after failures and leaves
  rejected paths untouched. Writers and reply placement share lexical root discovery while
  preserving their distinct symlink policies.
- **Use current OCRDb domains in synthesis test filenames (#2253, #1765).** Inert fixtures now
  use uppercase domain codes; explicit rejection fixtures retain the retired spellings they test.
- **Bind report domain enums to the runtime roster (#2347, #1821).** Contract tests cover the
  report, X0X and strain schemas, including coverage cells that exclude the domainless sentinel.
- **`driver readiness`'s gating `dependencies` row is reached for every runtime package (#2369,
  #1784).** The row names an absent `pyyaml`, `defusedxml` or `jsonschema` with its `pip install`
  before the first paid dispatch, and it printed for `jsonschema` alone. Four modules on the
  driver's own import path imported a third-party package at MODULE level: `tools/spotbugs.py`
  (`defusedxml`, reached through `scripts.tools`'s package body, which imports every adapter, which
  the host probes import) and `setup_flow.py`, `discovery.py` and `setup_proposal.py` (`yaml`). A
  checkout thinner than `pyproject.toml` therefore got a `ModuleNotFoundError` traceback out of
  `import scripts.driver` and no document at all — loud, and it named the package, but it was not
  the preflight. Each of those imports now sits inside the function that uses it, with no fallback
  and no `except ImportError:` arm, so a missing package still raises loudly from the one call that
  needs it (#2363); `ADAPTERS` stays a plain `dict`, since three test modules `mock.patch.dict` it
  and `capture_goldens.py` enumerates it. `repo_config.read_document` now REFUSES the document when
  `pyyaml` is absent rather than raising through `phases/readiness._matrix_row` and
  `setup_flow._check_groups_manifest`, both of which document that they never raise. Two guards
  pin the property. `tests/phases/test_readiness_verb.py` blocks each of the three packages in a
  child interpreter and reads the row back: exit 1, `missing` is exactly that pip name, and no
  `Traceback` on stderr. `tests/test_workflow_pins.py` asserts by AST that no module the driver's,
  `run_tools`' or `security_gate`'s import chain loads names a non-stdlib, non-local module at
  module level. It walks every statement not inside a function body — `try`/`except*`/`finally`,
  `if`, `with`, `for`, `while`, `match`, `class` — rather than enumerating shapes worth descending
  into, because a guard that knows six shapes is a guard the seventh walks past; a module-level
  `try:`/`except ImportError:` is refused not because it needs the package at import time (it does
  not) but because an except arm that rebinds the name is the fallback #2363 forbids and one that
  passes leaves the name unbound for a `NameError` at first use, while an unguarded import takes the
  row down. It selects the modules by FILE rather than by `sys.modules` name, which is how the
  fourth offender was found at all. The same file's gate-closure guard now ALSO reads those IMPORTS,
  beside the `RUNTIME_PACKAGES` proxy it keeps: every third-party module those chains import, nested
  ones included, maps through `importlib.metadata.packages_distributions()` to a distribution pinned
  in `.github/requirements-gate.txt`, and its PEP 503 normalisation is now the full `[-_.]+` fold.
  The two cover different sets and both are load-bearing — the gate's chain imports `jsonschema` and
  `defusedxml` but never `yaml`, so the proxy is the only guard keeping `pyyaml` in the closure.
- **A rejected diff-hunks artifact is disclosed in the report (#2169, #1783, ARC-B8 follow-up).**
  Three gaps the B8 disclosure left. An unreadable or non-object `diff-hunks.json` yields a payload
  with no `base`, so the review degrades to a non-delta one and `meta.coverage.delta` is null --
  the same null a run that was never passed `--diff-hunks` writes; only stderr said otherwise, and
  a `driver run` keeps a child's stderr only on failure. The loader counted a whole lost path (a
  `hunks` value that is not a list) as `ranges_dropped += 1`, the same as one malformed pair, so a
  lost file read as a lost line range -- yet every finding in that file classifies off-diff, which
  a narrowed file does not. And `meta.coverage.delta` was `{"type": ["object","null"]}` with no
  `properties`, so `tests/test_schema_parity.py`'s walk treated it as a deliberately open leaf and
  never descended: fourteen keys with no schema entry and no parity coverage, #1602 in miniature
  inside #1602's own guard. So: a sibling `meta.coverage.delta_artifact` --
  `payload_malformed`, `ranges_dropped`, `paths_dropped` -- an object whenever a `--diff-hunks`
  path was GIVEN and a read attempted, active delta or not, and null when none was, so its
  presence alone is the fact; a separate `paths_dropped` counter in the loader, in both report
  blocks, in the one stderr line and in the zero-hunk certification reason, which now names a
  loader drop as the cause instead of calling it indistinguishable from an empty change; and
  every key of both blocks pinned under `properties` with a description, with a parity test that
  the schema's pinned key set EQUALS the key set the fixture's report emits, so the open leaf
  cannot return silently. `meta.coverage.delta` itself is untouched, and its sibling's schema
  node states that contract. The seven values the block copies verbatim out of the artifact are
  described but NOT type-pinned -- a schema error is terminal (`ARTIFACT_INVALID`) and nothing
  normalizes them at the read, so pinning them would let a hand-supplied artifact end a paid-for
  run; the driver's discovery phase rewrites or removes that file, so the exposure is the direct
  `synthesize.py --diff-hunks` path rather than a `driver run`. #2169's third gap asked for the
  walk, and the pin that closes it stops at the keys this controller computes; #2382 is the
  follow-up that normalizes those seven at the read and then pins them. Still out of scope, as
  #2169 says, and now filed as #2381: a partial map naming a file with no ranges
  (`{"c.py": []}`) classifies every finding in it on-diff with no warning, a fail-open this
  change does not touch.
- **`dispatch.js` refuses an unenforced entry that names a shell, and every refusal escapes the
  entry id (#2166, #1783).** `loop_batch.refuse_misrouted` calls its two shapes "the same
  statement read from either side": an enforced entry whose agent is not the checkpoint's shell,
  and an UNENFORCED entry that names a shell at all — the phases set `agent` to null on those, so
  a name on one is a claim the run never made. B7 (#2154) taught the session-mode Workflow script
  only the first half, so `{enforced: false, agent: "panopticon-domain-panel", model: "opus"}`
  hand-copied into `args.entries` ran on `model` with no refusal and no log line. The validation
  loop now refuses it too, beside the other half and before any `agent()` call, so no entry in
  the batch launches. The same loop's refusals also interpolated `e.id` raw where
  `loop_batch.misroute_refusal` deliberately uses `%r`: the id is read out of the dispatch
  request, a file in the reviewed tree, so a control character, an ANSI escape or an embedded
  newline in it reached the operator's terminal as bytes the terminal acts on. Every refusal in
  the loop that prints an id now prints it through `JSON.stringify`. The enforced/unenforced
  dispatch branch itself is unchanged: validation now leaves it reachable only by the two shapes
  it was written for. The workflow checks SHAPES only — which shell a checkpoint may name is
  `refuse_misrouted`'s check, one level up — and `agent: ""` reads as absent on both halves of the
  JS statement, where `refuse_misrouted` treats it as a claim.
- **`--scope-changed` asks the same dot-path policy `--repo-scan` asks (#2272, #1784, ARC-F2E).**
  The delta path built its reviewed set from git-diff output, pruned fixture corpora and committed
  `exclude_paths`, and stopped -- it never asked `dot_paths.allowed`. So a tracked, CHANGED
  `.hidden/a.py`, `.venv/lib/x.py` or `.mypy_cache/b.py` -- and a changed `node_modules/c.js` in a
  target that tracks it -- was reviewable surface under `--scope-changed` while `--repo-scan` pruned
  it; #1136's comment at that caller already named this class of delta-path divergence. The branch
  now goes through the SAME `_filter_reviewable` with the SAME arguments as the whole-repo listing,
  so the one dot-path policy, `EXCLUDE_DIRS`/`EXCLUDE_DIR_GLOBS` on every ancestor segment, the
  fixture prune (#434) and the `.git`-segment drop hold under delta review too -- and so does the
  drop of a changed TRACKED symlink, which `--repo-scan` already dropped (`_is_confined_regular`
  is the shared `isfile`), so a target that tracks symlinks loses those files from a delta review.
  The instance a target hits unless it gitignores that directory: a delta run no longer reviews its
  own untracked `.panopticon/` run artifacts, which used to arrive as an `Ungrouped` cell of nothing
  but run output, with a scout checkpoint spent on it; the run now advances through the remaining
  phases instead.
  The delta path now feeds the same `pruned_fixtures` list, which stays whole-repo-scoped because
  the listing runs first and the changed set is a subset of it: a delta run's
  `excluded.fixture_dirs` equals the whole-repo prune, unlike `excluded_count`, which #1136
  re-derives from the changed set. Two divergences remain and are NOT touched here -- the delta call
  skips `_cap_discovered`, so the `discovery` block still describes the whole-repo listing on a
  delta run (#2376), and prunes are silent on both paths (#2377). A parity test pins AGREEMENT
  rather than a second copy of the policy: over one tree carrying every dot-path shape
  `dot_paths` distinguishes, plus a tracked symlink, the delta set must equal `--repo-scan`'s OWN
  output intersected with the changed set.
- **Discovery's git failure and truncation reach the report (#2271, #1784, ARC-F2E).**
  `discovery.py` records `method`, `files_seen`, `files_truncated` and `git_failure` in the
  `discovery` block of `groups.json` and prints the last two on its OWN stderr. On the driver path
  `phases/discovery.discovery_execute` runs the child through `child._run_child` -- both streams
  into bounded buffers -- and reads that stderr only when `groups.json` is MISSING, and no synth
  module, renderer or schema read the block. So on a successful `driver run` both disclosures were
  captured and dropped: a git-listing failure was a silent downgrade to a raw walk that does NOT
  honour the target's `.gitignore` ("this run's surface may be far larger than the target's own"),
  visible only to whoever hand-ran `discovery.py`. Two new `meta.integrity` keys carry them now --
  `discovery_git_failure` (the reason, else null) and `discovery_files_truncated` (an integer on
  every scan, `0` included; null = no discovery block, not measured) -- threaded from the parsed
  `groups.json` through `PlanInputs.load` on the same seam as `plan_owed` / `plan_sha256`, and
  rendered by the existing `INTEGRITY_KEYS` loop as `**Note:**` lines. THE RULING: both are
  NON-GATING, the same precedence the truncation disclosure already had, because the reviewed
  surface is a SUPERSET (git failure) or a PREFIX (truncation) of the intended one and the artifacts
  on disk are still what they claim to be, which is what this section measures. THE DISSENT,
  recorded so the owner can flip either `sinks` in one line: a surface "far larger than the target's
  own" is arguably not a run that should certify at all. Both values are isinstance-guarded at the
  publish boundary (`groups.json` is target-writable, and a bool is not an integer where `integer`
  is pinned), and the failure string is git's stderr, so it goes through `evidence_text`'s
  `inert_text` wrap like every other free-text slot. `method`, `exclude_paths` and `ungrouped_files`
  stay run artifacts in `groups.json` only; this surfaces the two that name a DEGRADED run.
- **One guarded `location` reader in `evidence.py`, so a malformed stored finding no longer aborts
  the cross-run diff (#2365, #1768, ARC-A4A).** `finding_fingerprint`, `matrix_finding_id`,
  `reconcile_key` and `_queue_tiebreak` each carried their own `finding.get("location") or {}`, and
  `reconcile.iter_records` a fifth copy. `load_report` is a plain `json.load` with no schema check,
  so a stored report holding `"location": "a.py"` reached `.get("file")` and aborted the WHOLE
  cross-run diff with `AttributeError` -- exactly the blast radius #2359 closed for `tool_evidence`,
  in an idiom that had by then recurred four times. All five sites read `evidence.location_of` now,
  which hands back the dict or `{}`, so a non-dict `location` keys precisely as an absent one does.
  `iter_records` also skips a non-dict `findings[]` entry instead of raising on it, printing one
  counted `reconcile: skipped N non-dict <key> entries` line to stderr per section, because a
  silently dropped claim is a disclosure gap; and a `findings` or `discarded_claims` section that is
  not a list reads as empty in `load_report` and in `iter_records`, and counts nothing. An AST guard
  in `tests/test_evidence.py` walks `evidence.py` and fails if `location` or `tool_evidence` appears
  as a constant anywhere outside its one reader, in any idiom -- subscript, `.get`, `.pop`,
  `.setdefault`, `in`, or a constant bound to a name -- a subscript write excepted. The honest
  limits: that guard covers `evidence.py` alone; `phases/review.py` and `security_gate.py` keep the
  idiom on adapter-constructed findings, whose `location` is always a dict an adapter built, so
  those are safe by construction, but `scripts/file_issues.py` -- the other consumer of this same
  `load_report` -- still carries it and is tracked as #2372; and one layer up, a report whose top
  level is not an object or whose `meta.parts` is not a list still aborts in `load_report` itself
  (#2373).
- **The spotbugs adapter imports `defusedxml` unconditionally; the silent stdlib fallback is gone
  (#2363, #1784, ARC-F2E).** `tools/spotbugs.py` opened with a `try`/`except ImportError` that
  rebound `ET` to `xml.etree.ElementTree`, so a declared, readiness-gated dependency -- listed in
  `pyproject.toml`'s `[project] dependencies`, pinned in `requirements-tools.txt` and gated by
  `readiness_checks.RUNTIME_PACKAGES` -- was in practice optional hardening, downgraded with no
  stderr line, no manifest row and a `nosec` that silenced the scanner along with it. The paths that
  never run readiness were the exposure: the CI gate `security_gate.py`, which imports
  `ingest_tools` and through it every adapter, and a resumed run whose `readiness.json` already
  recorded `ready: true`, both parsed an untrusted scanner report with internal-entity expansion
  enabled. The import is bare now, so a missing package fails at import naming `defusedxml` on every
  path -- readiness included, because the driver reaches the adapter package through its host
  probes, so the gating `dependencies` row is reached only for `jsonschema` until #2369 makes it
  reachable for all three; SKILL.md and the `RUNTIME_PACKAGES` comment say so rather than crediting
  the row. Only one environment had to learn the package: the tools image already ships
  `defusedxml==0.7.1`, and `.github/requirements-gate.txt` now pins it too, so the `scan`,
  `fork-scan` and adapter-integration steps that import the adapter package under
  `--require-hashes --no-deps` keep importing -- with a new `tests/test_workflow_pins.py` guard
  holding every `RUNTIME_PACKAGES` pip name to that closure. The `# nosec B314` on `ET.fromstring`
  went with the fallback, since bandit does not flag the defused call, and the adapter test that
  pinned the fallback as working now asserts the import raises instead.
- **A dropped tool member's `occurrences` and `additional_loci` move onto the surviving finding
  (#2361).** Sub-issue of #1768 (ARC-A4A), and the bug the #2353 review reproduced -- that PR's
  parity fixture had to pick two lines no agent claimed to keep the key reachable at all.
  `synth/findings.aggregate_tool_findings` deliberately parks an aggregated survivor on a locus an
  agent also flagged, so `synth/corroborate.dedupe` reinforces the pair -- and dedupe keeps the
  MORE SEVERE member, usually the agent finding, whose `_reinforce_merge` copied cvss, scenario,
  impact, remediation, references and citations but not the aggregation. So an agent flagging one
  of a rule's lines silently retired that rule's other loci and its count: nothing in the report
  said the rule had fired more than once, and `scripts/file_issues.py`, which renders both, had
  nothing to render. A new `_carry_aggregation` moves the pair, and only where the aggregated
  member actually LEAVES the report: dedupe's exactly-two tool+agent merge and its per-category
  sub-bucket drop loop (which runs whether or not the category has an agent member -- the carry
  is a property of the drop, not of corroboration) carry it, while the per-category
  representative merge does NOT -- that tool
  finding survives its own rule bucket and reaches the report, so carrying there would have two
  entries claim one pair of hits, on an entry that does not even alias the source. It carries only
  when the dropped member is tool-sourced (an agent finding can declare either key) and in the
  survivor's category (one rule's loci are not another issue's), only a well-typed non-empty locus
  list and a count above one moving as ONE unit, and only onto a survivor with no aggregation of
  its own -- which keeps it, never a sum (#2225: two artifacts at one manifest locus are two
  issues). Honest limit, unchanged here: the absorbed tool member's rule id is not disclosed
  anywhere in the report -- `_merged_ids` carries its finding id for verdict binding only and is
  stripped before the artifact is written.
- **One guarded reader for `tool_evidence`, so a malformed stored finding cannot abort `reconcile`
  through the rule id (#2359, #1768, ARC-A4A).** The low follow-up #2358 left behind: that change
  guarded the field's read in `artifact_term`, while `tool_rule_id` still read the same field --
  and its `provenance` fallback -- with `(finding.get(...) or {}).get(...)`, which raises
  `AttributeError` on a string or a list. Nothing validates a report read off disk
  (`reconcile.load_report` is a plain `json.load`) and `iter_records` fingerprints EVERY record of
  a prior run through `finding_fingerprint`, which reads the rule id, so one schema-invalid finding
  in a stored report aborted the whole cross-run diff with a traceback instead of keying as
  rule-less. `evidence._tool_evidence` is now the single reading of the field for both functions
  (`{}` for absent or malformed), the provenance fallback is guarded inline the same way, and a
  dict-valued field reads exactly as before.
- **SKILL.md's dependency list now matches the gating readiness row -- `defusedxml` was missing
  (#2323, #1784, ARC-F2E).** SKILL.md's § Dependencies named `pyyaml` and `jsonschema`, so a
  checkout that installed exactly what the doc listed failed `driver readiness`'s gating
  `dependencies` row on `defusedxml`, one of the three packages
  `readiness_checks.RUNTIME_PACKAGES` checks -- and a missing package is the one readiness failure
  a fresh checkout meets first. The paragraph now names all three and says how each is absent
  differently: `pyyaml` takes discovery down with a traceback, `jsonschema` fails closed after the
  whole review has been paid for, and `defusedxml` is caught only by the readiness row itself --
  which, being `PHASES[0]`, refuses to start the run -- because nothing in the scan would fail:
  `tools/spotbugs.py` falls back to the stdlib XML parser, which expands the internal entities
  `defusedxml` refuses, so an ingest driven outside the loop (the CI gate `security_gate.py`, which
  imports `ingest_tools` and never runs the readiness phase, or a resumed run whose
  `readiness.json` already recorded `ready: true`) parses an untrusted scanner report with the
  hardening silently gone. Golden capture also imports it, unguarded, but runs outside a review
  rather than in one. A new `tests/test_skill_md.py` case reads
  `RUNTIME_PACKAGES` and asserts the section names every pip name in it, so a package added to the
  gating row cannot skip the doc again.
- **`additional_loci` described in the report schema and walked by the parity fixture (#2353).**
  Sub-issue of #1768 (ARC-A4A), and the LOW the #2225 review left: the sibling key `occurrences`
  got a schema entry and a fixture value, `additional_loci` got neither.
  `synth/findings.aggregate_tool_findings` stamps it with the other loci one rule fired at in one
  file before collapsing them into one finding, and nothing described it, so no consumer could
  validate against it -- and #1602's parity walk stayed green because the fixture's SARIF had one
  hit per rule per file, so no finding ever carried the key. That SARIF now fires B602 twice in
  the reviewed file, at two lines no `_agentic` finding claims: an aggregated survivor sharing an
  agent's locus meets dedupe's tool+agent reinforce-merge, whose survivor is the more severe
  member (here the HIGH agentic finding), and the key would reach no artifact at all.
  `discarded_claims[]` items `$ref` the findings item schema, so the one entry covers both
  sections.
- **The `bandit`, `gitleaks` and `trivy` goldens are re-captured, and the provenance ratchet is
  empty (#2313, #1784, ARC-F2E).** Part (b) of ARC-168995033, and the half that needed docker: the
  three were captured through `panopticon-tools` with `--network none` against a SYNTHETIC corpus
  mounted at `/src` -- an `app/main.py` of textbook bandit offences, an `app/settings.py` of
  invented tokens, a fake `app/deploy_key.pem`, and a known-vulnerable node lockfile for trivy --
  so no committed golden names `/mnt/panopticon` or an operator worktree any more, and gitleaks'
  snippets are the scanner's own `REDACTED`. `tests/test_goldens_provenance.py` `PENDING` is now
  `frozenset()`; the ratchet's stale-entry half is what proved each re-capture, failing on all
  three until the entries came out. The normalization contract, the legacy-SARIF severity tests
  and the security gate's non-vendored/vendored pair all hold on the new bytes.
- **`finding_fingerprint` and `reconcile_key` carry the artifact term (#2352, #1768, ARC-A4A).**
  Follow-up to #2225: the two stages that COLLAPSE tool findings learned that one advisory against
  two artifacts at one manifest locus is two issues, but the two IDENTITY functions did not. Two
  vulnerable jars sharing one CVE at `pom.xml:1` hashed identically, so the verify queue handed the
  second one a `<fingerprint>-1` suffix and logged a collision for a pair that is two real
  vulnerabilities; `reconcile.py` recomputes both keys on both runs from today's algorithm, so a CVE
  newly matched against a second jar in run 3 was read as the FIRST jar recurring from run 2 -- a
  new vulnerability reported as a standing one. Both identities now append
  `tool_evidence.package_name` when the finding names an artifact, and one definition,
  `evidence.artifact_term`, is the only reading of that field: it serves both identities and
  replaces the inline copy each collapse stage carried (`synth/findings.aggregate_tool_findings`
  and `synth/corroborate._by_package`, behaviour unchanged). A finding naming no artifact -- every
  SARIF-path and agent finding, and one carrying an empty or non-string value -- keys byte-for-byte
  as it did before the term existed. The `--pr`/delta gate needed NO change and got none:
  `security_gate.finding_identity`'s fourth element is the whitespace-collapsed TITLE, which
  dependency-check starts with the jar name, so two artifacts were already two gate identities --
  now pinned by a test. The same one-locus shape reaches `osv-scanner`, `pip-audit`, `npm-audit`,
  `cargo-audit` and `bundler-audit`, which the one definition covers by construction.
- **The workflow guard closes eight LOW follow-ups from its 5.2 reviews (#1793).**
  `env -- - sh` and `env x-y=1 sh` read through to `sh`, and `xargs -I{} {}` is reported (#2307).
  `sh <<< '…'` is read as its script; an interpreter's here-string bash expands is reported (#2293).
  A brace or glob word where a command starts (`{sh,-c}`, `[s]h`) is reported, not read (#2294).
  Globs in `[[ … ]]`, array literals and extglob groups are not commands; `@(sh) -c …` is reported.
  `"$PWD/tool"` and `"$(pwd)/tool"` are read as running a download called `tool` (#2310).
  A bare `tool` is read as running a download written to `/usr/local/bin/tool` (#2308).
  A checksum must precede each use of a download, not only its first (172 pre-existing fail-opens).
  A checksum in a script given to `sh -c`, `eval` or a shell's stdin must stop the step to count.
  Its own pipefail (`bash -o pipefail -c`, a plain `set -o pipefail`) is read as its `-e` is.
  Such a script sits in its runner's branch, and its own `fi` or `done` ends none of the step's.
  A script given to a shell inside `$(...)` is reported if it fetches or its job downloads anything.
  `env A=$X sh` reads through to `sh`; `env $(x)=1 sh` and `env A=$X -c …` are reported.
  `sh {-c,'…'}` and `sh [-]c` are reported, and `sh ./x_*.run` as running a download `x_1.run`.
- **Catalog rows for `.bandit` and two unlisted eslint spellings (#2330, #1784, ARC-G1B).** Owner
  ruling 2026-09-28 on #2274: a root dot-file no shipped catalog NAMES stays invisible BY DESIGN,
  and the remedy for a wanted one is a catalog row per spelling -- never a widened stem.
  `skill/data/commons_catalog.yml` `Config` gains `.bandit`, `.eslintrc.cjs` and `.eslintrc.yaml`,
  and `skill/scripts/dot_paths.py` `FILES` gains the same three, so this repository's own `.bandit`
  -- named by neither the catalogs nor the SEC floor, and therefore reaching no group at all -- is
  reviewable surface; with no committed `Config` group in `panopticon.yml` it is claimed by the
  Commons catalog's `Config` category, which in this repo folds into the reported `Commons` group,
  so the next self-scan carries one more file there and a reviewer may now question this repo's own
  bandit `skips=`. The ruling named `.eslintrc.mjs` too; it is not a spelling the legacy cascade
  reads (`.mjs` is flat config, already claimed as `eslint.config.mjs`), so no row. `.eslintcache`
  stays out: the family is still spelled name by name (now seven) precisely to keep generated state
  pruned.
- **The zero-hunk delta gate counts only what the gate would have judged (#1783, #2222, follow-up to
  #2178).** Owner ruling 2026-09-28: the refusal is a statement about findings the empty hunk map
  hid FROM THE GATE, so `delta.zero_hunk_population` re-applies this run's own two policies to the
  active set -- the evidence policy `verdicts._partition_gate` applies, then the `--fail-on` floor,
  which becomes `findings.severity_floor_admits` so the gate and this count have ONE spelling of it
  (`grading.gate_verdict` is now that predicate under `any()`) -- and never the delta scoping that
  empty map broke. Two runs that read INCONCLUSIVE now PASS: an empty `--changes` map whose only
  active findings sit below `--fail-on`, and one whose findings are all unverified under the default
  `confirmed_only` policy. A CONFIRMED finding at or above the floor still reads INCONCLUSIVE, an
  OFF gate is still preserved, and the `coverage_note` clause now says `gate-eligible` instead of
  `active`.
- **dependency-check locates a finding at the build manifest, not the jar (#2225, #1768,
  ARC-1020240040).** The scanner analyses ARTIFACTS, so `location.file` was
  `angus-activation-2.0.1.jar` -- a name that exists nowhere in the reviewed repository, and the
  delta/`--pr` gate, the tool-verify advisor's read grant, grading's group attribution and every
  exclude glob all resolve that against the repo root. Owner ruling: MANIFEST PROXY. The location is
  now the build manifest the scan audited, resolved `pom.xml` -> `build.gradle` ->
  `build.gradle.kts` (`BUILD_MANIFESTS`, the same tuple `is_applicable` selects on) through the
  two routes and the last resort `tools/pip_audit.py` already uses -- the manifest `invoke`
  recorded, else the first one under the root `ingest_tools` names around its parse, else
  `DEFAULT_MANIFEST` ("pom.xml") for a caller holding bytes and no tree. The jar still names the
  vulnerable artifact in `title`, `impact` and `tool_evidence.package_name`; a dependency's
  `includedBy` references are surfaced as `tool_evidence.included_by`, which is EVIDENCE ONLY and is
  never used as a location whatever the tool emits in it -- inert (`inert_text`, like every other
  target-authored string) and bounded to 16 entries with a marked cut, and described in
  `report-schema.json`. Two vulnerable artifacts that share one advisory used to collapse to ONE
  finding once they arrived at the same manifest locus, and BOTH stages that collapse tool findings
  now carry the artifact: `tool_evidence.package_name` joins the aggregate key in
  `synth/findings.aggregate_tool_findings` (which ran first and merged the pair into one
  `occurrences: 2` finding) and splits the rule bucket in `synth/corroborate.dedupe`. Findings
  naming no artifact keep their single bucket at both stages -- every SARIF-path and agent finding.
  `line_start` stays 1 and no argv byte, cwd or `-w` changed, so no real-image round is owed. The
  `PATH_DEBT` register in `tests/tools/test_normalization_contract.py` is empty again: the entry and
  the self-liquidating expiry test that owed it are gone, its meta-tests hold on the empty register.
- **The virtualenv scope leaves `run_tools.py` (#1762, #2306, ARC-2609514778; part 4).** Finding the
  virtualenvs under the target (`pyvenv.cfg` plus the SHAPE of an environment, depth-bounded and
  confined), deciding which of them a scanner's exclusion knob may be handed (the security mode, the
  name allowlist) and rendering that onto each tool's argv move to `skill/scripts/venv_scope.py`
  whole; the rows it produces are still published by `tools_manifest.write_manifest`, and
  `ingest_tools` imports its `has_venv_shape` and `VENV_MARKER` so the scan side and the ingest side
  cannot drift. `run_tools.py` goes from 1136 to 838 lines and the new module is 376, under the
  700-line ceiling; the pin STAYS in `tests/test_flat_module_ceiling.py`, lowered to 838, holding
  docker detection, language detection, selection, the argv and the CLI. No argv byte, no manifest
  row and no message changed -- `tests/test_venv_scope.py` compares the walk, both partitions and
  twenty-four argv shapes (every tool with a repeatable knob, bandit's comma-joined value, a tool
  with none; zero, one and two directories; `target` set and unset) against a golden captured before
  the move, and the patch-rule guard derives all four modules' names from their own ASTs.
- **Malformed OSV and Roslyn records disclose partial coverage (#2105).** Usable sibling
  findings remain available to reports and the security gate. Bounded diagnostics and coverage
  facts distinguish malformed records, including those without an identifiable source file,
  from valid empty results. Invalid top-level capture containers fail ingestion.
- **Separate verdict resolution stages (#2318, #1826).** Matching, evidence and gate partitions
  retain fingerprint identity, delta scope, accounting and suppressed-finding policy.
- **Separate reconciliation decisions (#2317, #1826).** Indexing, recurring matches and close
  checks retain coverage guards, reason text, collision disclosure and output ordering.
- **Share staged report publication (#2316, #1820).** Clean partial staging writes before
  propagating failures; publish report siblings before the main report.
- **A HIGH a verbatim extraction MOVES is pre-existing (moved), not new (#2309).** The pre-merge
  gate's delta pass keys on the path, so a refactor that relocated a `docker kill` call reddened the
  required `scan` check on a diff that changed no behaviour (#2305). After the exact pass, a head
  finding still counted new pairs with ONE unmatched base finding of the same tool, rule and message
  — one the base carried one more copy of than the head has here — and prints under its own
  `pre-existing (moved: …)` heading. One orphan excuses one occurrence: a second copy, or any
  occurrence the base has no orphan left for, is still new and still gates, and the pairing never
  crosses the suppression (a vendored orphan cannot excuse a first-party finding). What it
  establishes is a COUNT, not a verified move; `DEVELOPMENT.md` says what that leaves invisible. The
  strict route's verdict line is byte-identical.
- **roslyn-secguard cites the vendor's CWE for all 31 DotnetariumSCS rules (#1795).** SCS0026 is
  CWE-90 (LDAP injection), not CWE-79 (cross-site scripting, which is SCS0029); 23 of the 31
  rules shipped uncited, and SCS0041 never existed. A test now pins the table's version to the
  Dockerfile's `ARG DOTNETARIUM_SCS_VERSION` pin.
- **Per-repo configuration moved to a root `panopticon.yml` (#1681).** BREAKING for an existing
  tree: the committed matrix lives at `<repo>/panopticon.yml` (or the read-only alias
  `.panopticon.yml`) under `version: 1` with `groups:`, `exclude_paths:` and `settings:` keys, and
  `.panopticon/` now holds run artifacts only. `.panopticon/groups.yml` is no longer read by any
  phase — alone it is an error naming the remedy, beside a root config it is disclosed and ignored —
  and `.panopticon/config.json` is no longer read either, its keys having become `settings:`.
  `python3 skill/scripts/driver.py migrate-config <repo>` writes the root file from the legacy one,
  preserving committed order, refusing if a root config already exists, and leaving the old file for
  you to delete.
- **The single-stage tools image is a decision, and its split is 5.3's (#1772, #2242).** Every
  toolchain installs into one stage, so one upstream break fails the whole build; the accepted cost
  is written down in `Dockerfile` and `DEVELOPMENT.md` now, with 5.3's brief (one stage per
  toolchain, still one published image).
- **Documentation corrections where a reader looks (#2238, #2239, #2240, #2241, #2242, #2243,
  #2244, #2245).** Comments, docstrings and guide prose the code had outgrown: the `nvd-cache.yml`
  workflow ordering claim, the packaging intent in `pyproject.toml`, `integrity._plan_hash`'s
  vanished twin, what `RunResult.denials` counts per host family, why the driver re-derives
  synthesize's verify queue, what else shares synthesize's exit `2`, the `dependencies` gating row,
  the eighth evidence status, and `synthesize.py`'s "stdlib-only" claim. Two of these are pinned:
  `readiness.GATING_ROWS` against the guide's gating sentence, and
  `evidence.EVIDENCE_STATUSES`/`GATE_ELIGIBLE_DEFAULT` against the evidence chapter.
- **Parity pins for the mirrored tables, the fixture corpus and the goldens (#2234, #2235, #2236,
  #2237).** Four LOW/MEDIUM findings, one shape: a definition kept in two places with nothing
  comparing them. `sarif_utils`' hand-mirrored fixture corpus is pinned against `discovery`'s,
  value for value and predicate against predicate, so the #434 tool/agentic parity is a test and
  not a comment (ARC-1496429894). The four parallel legacy-SARIF tables -- `LEGACY_SARIF_TOOLS`,
  `TOOL_CMD`, the registered `LegacySarifAdapter` rows and `sarif_utils.PREFIX` -- are asserted
  EQUAL, as are the tool registry and the recommendable set, which closes the directions nobody
  had pinned (ARC-3428598333, ARC-1125964489). `file_issues` derives its two label tables from
  `evidence.SEV_ORDER`/`EVIDENCE_STATUSES` instead of hand-copying them, and now RAISES on an
  unknown severity or evidence status: a ninth status used to be filed as `evidence:unverified`,
  a label asserting the opposite of what happened (ARC-1576523829). `x0x_report` and
  `strain_report` share one gap predicate and one roster clamp (`ocrdb.is_fallback_code`,
  `ocrdb.clamp_domain`), so `is_fallback` is now CASE-INSENSITIVE and whitespace-stripped, and
  strain's published `domain` can no longer leave the roster enum that its own schema declares
  (ARC-101960059). A `domain` claim that is not a roster domain is still clamped to `ZZZ` and
  disclosed, never reinterpreted as the domain before its first hyphen -- `clamp_domain` validates
  a domain and `roster_domain` is the wrapper for a caller holding a code. `cross_domain` is
  decided on the RAW claims (`ocrdb.domain_claim`), not the clamped ones: two codes claiming two
  different off-roster domains are cross-domain strain, and comparing clamped values would publish
  "same domain". And `tests/test_goldens_provenance.py` refuses any file under `tests/goldens/`
  that names `/mnt/panopticon` or a `.worktrees/` path segment -- no per-file exemption; the
  directory's README was reworded so it no longer needs one -- with today's three offending goldens
  (`bandit.raw`, `gitleaks.raw`, `trivy.raw`) in a shrink-only `PENDING` set that empties when
  #2313 re-captures them against a synthetic corpus (ARC-168995033).
- **The workflow guard sees through setsid, ionice, taskset, flock, chrt and unbuffer (#1795).**
  Each was read as the command itself, so `setsid curl … | sh` and `curl … | chrt 10 sh` passed
  clean. `scripts/shell_wrappers.py`, which now holds the reader's wrapper table, reads each by
  its own grammar and reports what it cannot settle, such as a `taskset -p` pid that may be 0.
  Behind `xargs`, which appends words, a wrapper that runs nothing as written is reported too.
  A download run as a wrapper, as in `curl -o flock …; ./flock 9`, counts as running it.
  A `$` word behind a wrapper is reported even if it ends in a wrapper's name (`sudo "$PWD/env"`).
- **Separate Codex event parsing and usage accounting (#2299, #1826).** Completed turns,
  messages and final results keep recovery ordering, partial usage and host-error precedence.
- **Separate confined read-tool operations (#2298, #1826).** Read, list and search handlers
  retain the common argument/refusal boundary, grant checks and bounded result disclosures.
- **Reuse the published report schema location in tests (#2297, #1821).** Split-report,
  parity and verdict-binding checks use the validator's reference directory and schema name.
- **Derive the health explanation from grading weights (#2296, #1821).** The terminal
  summary reads the canonical severity weights in display order, preserving its current wording.
- **The workflow guard names the step it cannot read, and refuses a heredoc delimiter bash
  must parse (#1793).** A `shell_lex.Unreadable` escaped `main` as a traceback that named no
  step and hid every other step's defect (#2252); it is now that step's defect. A delimiter
  bash parses to spell (`<<$(...)`) was read as code, so a quote left open in its body hid the
  payload after the terminator (#2224); the reader now refuses it, naming the word.
  A `\`-newline before the word no longer reads as an empty delimiter, which hid the payload.
  A `<<`, `<<-` or `<<<` split by a `\`-newline reads as the one operator bash makes (#2291).
  The closing count says "N defect(s)" where it said "N unverified fetch-and-exec step(s)".
- **SpotBugs findings cite the CWE SpotBugs or FindSecBugs assigns to the pattern (#1795;
  COD-1501398192).** `_SPOTBUGS_CWE` was a hand-written table of seven bug patterns; one of
  them, HARDCODED_KEY, named a pattern neither vendor has ever emitted, so a suppressed
  hard-coded password never reached policy C's gate. The table is now the union of core
  SpotBugs 4.8.6's and the FindSecBugs 1.13.0 plugin's own `findbugs.xml` mappings -- 145
  patterns across both vendors; what neither maps stays uncited, on purpose.
- **Keep score-gate imports from changing the search path (#2279, #1823).** Package and flat
  imports retain evidence module identity without modifying `sys.path`. Direct file execution
  remains supported, and the bootstrap allowance is removed from the import guard.
- **Reuse the coverage string-list filter (#2278, #1822).** Coverage delegates list filtering
  to the schema helper while still accepting a lone string. Manifest inputs remain list-only.
- **Share bounded manifest name validation (#2277, #1820).** Tool repairers share object,
  row-count and name checks. Overlong tool identities are still dropped; suppression names are
  still cut and colliding counts summed, with the same warnings and value checks.
- **Use current tool-policy test fixtures (#2276, #1820).** One driver-plan fixture and case
  table cover enforced, advisory, mixed and unknown modes, retaining the report metadata check.
- **The scanner-owned config leaves `run_tools.py` (#1762, ARC-2609514778; part 1 of 3).**
  The staged `bandit.ini`/`.trivyignore`, the suppression posture, the ignore overlays and
  two of the four ledgers the manifest reads back move to `skill/scripts/scanner_config.py`
  whole: `run_tools.py` goes from 2215 to 1774 lines and the new module is 518, under the
  700-line ceiling. No argv, flag, path or message changed — `tests/test_scanner_config.py`
  pins the docker argv of both staged tools, in both security modes, with and without the
  target's own `.bandit`, against a golden captured before the move. `ToolAdapters` gains
  an `Image` layer so the matrix can claim the new files without passing the 48-file cap.
- **The capture path leaves `run_tools.py` (#1762, ARC-2609514778, ARC-3243338950; part 2 of 3).**
  One container run supervised, bounded, classified, redacted and persisted — `_capture_run` through
  `_atomic_write`: the `threading.Timer` watchdog with the `--cidfile` kill that stops the container
  and not just the CLI client, the concurrent stderr drain, the stdout spool under
  `MAX_TOOL_OUTPUT_BYTES` with its truncation marker, the exit-code classification (timeout,
  non-`(0, 1)`, empty-output fail-closed), the semgrep stderr annotator and the one redaction choke
  point — moves to `skill/scripts/tool_capture.py` whole. `_stream_and_write` moved entire rather
  than being split: the watchdog and the kill path are bound by the cidfile contract.
  `run_tools.py` goes from 1774 to 1322 lines and the new module is 524, under the 700-line
  ceiling. No argv, flag, path, byte, message or file format changed — `tests/test_tool_capture.py`
  compares the bytes written, the rows returned and the lines printed for fifteen capture shapes
  against a golden captured before the move, and the patch-rule guard now derives BOTH modules'
  names, and the `run_tools` aliases each test file really binds, instead of a fixed list.
- **The tools manifest leaves `run_tools.py` (#1762, ARC-2609514778; part 3 of 3).**
  `tools-manifest.json`'s schema -- selected/produced/missing, the `excluded_dirs` rows, the run id
  and scope, the eslint `file_coverage` read and the four posture ledgers it reads back -- moves to
  `skill/scripts/tools_manifest.py` whole, and the two ledgers whose only reader is the writer (the
  network posture and the gitleaks ignore-file posture) move with it; `run_tools` binds them back,
  and still clears and fills both where the argv is built. `run_tools.py` goes from 1322 to 1136
  lines and the new module is 265, under the 700-line ceiling. The pin STAYS in
  `tests/test_flat_module_ceiling.py`, lowered to 1136: all three extractions have now landed and
  the module is still over the ceiling, holding detection, virtualenv partitioning, selection, the
  docker argv and the CLI. No manifest key, value, order or byte changed, no argv and no message --
  `tests/test_tools_manifest.py` compares the exact bytes of seven manifests (both security modes,
  `run_id` set and unset, the eslint coverage read, an adapter refused its egress, and the
  docker-absent shape) against a golden captured before the move, and the patch-rule guard derives
  all three modules' names from their own ASTs.
- **Discovery surfaces the dot-paths the shipped catalogs and the SEC floor claim, and both
  discovery paths apply one policy (#1784, #1771; ARC-124841687, ARC-1940929242).** The policy was
  `ALLOWED_DOTDIR_SUBTREES = (".github/workflows",)` plus a blanket skip of every other root
  dot-path, so 73 of the 74 dot-leading globs `skill/data/commons_catalog.yml` claims --
  `.circleci/**`, `.buildkite/**`, `.github/actions/**`, `.github/*.yml`, `.env*`, `.npmrc`,
  `.eslintrc`, `.husky/**`, `.mvn/**`, `.goreleaser.yml`, `.panopticon.yml` and the rest -- named
  files no group could ever receive, and so did the deterministic SEC floor's own `.circleci`,
  `.buildkite/`, `.github/actions/`, `.travis.yml`, `.drone.yml`, `.pre-commit-config.yaml`,
  `.devcontainer/`, `.env`, `.npmrc`, `.netrc`, `.pgpass` and `.htaccess` hints. A file discovery
  never returns is never `Ungrouped` either, so nothing reported the gap: #1508 (top-level
  `.github/*.yml`) and #1838 (the CI and secret-file floor) both rest on claims that could not
  fire. Owner ruling 2026-09-27, allowlist widen in 5.2 (pruning the claims was rejected): one
  policy in `skill/scripts/dot_paths.py` naming exactly the root dot-directories and dot-files
  those two enumerations spell out, and nothing else -- `.git`, `.venv`, `.tox`, the tool caches,
  `.panopticon/` and any unclaimed dot-path stay pruned, as does a dot-directory nested below the
  root. Both paths now ask that one rule on the same segment: the git-listing filter tested each
  ancestor DIRECTORY while the walk tested the whole FILE path, so every file directly under
  `.github/` was reviewable surface on a git target and invisible on a non-git one -- against two
  docstrings that said both methods shared one policy. The durable guard derives its samples from
  the shipped catalog and the floor hints themselves and asserts both paths keep each one, so a
  claim discovery cannot surface fails in the PR that adds it. `_git_listed_files` also swallowed a
  bare `Exception` into `None`, and the caller then walked -- which stops honouring the target's
  `.gitignore`, the surface policy #500 exists for; "not a git worktree" and "git failed on a
  worktree" are now told apart, the failure is named on stderr and published as the discovery
  block's `git_failure`, and the scan still runs. **Discovered file sets grow on every target**:
  CI, config and secret-bearing files now reach a group, so group and cell counts move -- land this
  before a run, not during one.
- **Share synthesis test isolation (#2204, #1822, #1823).** Synthesis tests reuse the cwd
  guard and one autouse isolation fixture at the same package and module scopes. Report tests
  import mocks explicitly, preserving assertions and removing reliance on prior test imports.
- **Share OCRDb report record helpers (#2203, #1822).** Gap and strain reports use one
  occurrence builder and the catalog's raw domain-prefix helper. Missing-file handling, optional
  strain run IDs, each caller's domain policy and flat imports retain their existing behavior.
- **Derive SARIF levels from the adapter severity map (#2202, #1821).** SARIF retains its
  four allowed level names while sharing their grades with tool normalization. Missing and
  unknown levels, metadata precedence and secret grading keep their existing behavior.
- **Share token usage vocabulary (#2201, #1821).** The dispatch ledger imports usage fields
  and phases from the usage collector, keeping totals, checkpoint mapping, model attribution
  and corrupt-row accounting unchanged.
- **A refused `CODEX_HOME` is the remedy readiness and the setup acknowledgment show (#1803;
  COD-1638371699).** `host_disclosure.remedy` named `--emit-host-agents codex`, and
  `setup_ack._remedy_clause` named it or `driver loop --setup --host codex --mode headless`,
  even though the row's own `registration_refusal` meant that exact command would refuse with
  the same message one step later. A refused `CODEX_HOME` reaches both surfaces as UNKNOWN,
  never as REFUTED, so the acknowledgment yields to the refusal on every branch; both read it
  off `hosts.HostSpec`, and `host_disclosure.lines` prints it once rather than once per
  capability line. Every other host, and codex with no refusal, is unchanged.
- **A SIGTERM the driver did not arm ends the Kimi runner's children before the home strip
  (#1805).** The stripper's SIG_DFL/C-installed branch restored the default disposition and
  re-raised the signal without ending the runner's registered children first, so a process whose
  SIGTERM was never wired to the driver's own handler could die and leave them running against a
  home whose guard hooks had just been stripped. It now calls `terminate_children` -- the same
  bounded termination the interrupt path uses -- before the strip; the chained-predecessor branch
  is unchanged.
- **The workflow guard reads comments, continuations and heredocs the way bash does (#1793;
  COD-3418139920, COD-3636110933).** `shell_reader.statements()` settled all three in passes
  that ran before any quote tracking, so a `#` line inside a multi-line string, a `<<WORD`
  inside quotes, in a comment or at the tail of a `<<<`, and a backslash ending a comment or a
  quoted heredoc line each hid a statement bash runs, and the guard reported the step clean.
  `scripts/shell_lex.py` now reads them in one quote-aware forward pass: heredocs queue until
  the newline, a body ends at the line bash compares, and a delimiter bash must parse to spell
  (`<<$(...)`) stays text. A command's `((` is arithmetic or two subshells, whose heredocs are
  real, by the character after its first group, as bash decides it; nesting that would take
  over eight re-readings of the script to decide raises `shell_lex.Unreadable` rather than
  guess. An `a[...]` subscript, where `<<` is a shift, opens only where bash reads an
  assignment -- across lines, and inside `a=(...)` -- so among a command's arguments
  (`echo a[1<<X]`) `<<` is a heredoc. The scanners after the lexer now agree on `\"`
  inside "...", `$'...'` and an apostrophe inside "...": misread, each hid what followed it.
  Every heredoc on a line is read and filed under its descriptor, so the guard reads the
  script `bash -s <<'A' 3<<'B'` runs (#2128).
  A heredoc opened inside a `$(...)`, `<(...)` or `>(...)` that closes before the newline its
  body would follow raises `shell_lex.Unreadable` too: bash 5.2 takes that body from the lines
  below and runs what follows its terminator, which the guard does not model. Inside `$((...))`
  a `$(...)` is read as the commands bash runs there.
- **A Ctrl-C during a fresh run's first phase ends with the `interrupted:` status (#1805).**
  `orchestrate.loop` called `_first_run`, and the resume seam's `_run`, before its own `try`, so
  a Ctrl-C there escaped as a traceback and `_finish` never ran. Both calls now live inside the
  same `try`, so the loop's existing handlers cover them; nothing before `_first_run` changed.
- **One owner reads the committed config; errors refuse and disclosures print on both paths (#2229,
  #2189; ARC-1814846877, epic #1761).** Five readers each normalized the legacy `groups:` list form
  themselves -- `groups_schema.parse_groups`, `discovery.load_catalog`, `_committed_matrix`,
  `_declares_groups` (a DIFFERENT predicate: does any entry carry a name?) and
  `setup_flow.migrate_config` -- three re-implemented the leaf-vs-parent rule, and the two
  `_committed_exclude_paths` copies each printed the disclosure channel the other dropped, with
  docstrings citing each other wrongly. `groups_schema` owns all of it now
  (`normalize_groups_mapping`, `is_leaf_body`, `committed_bodies`) and every reader calls it.
  Per the owner ruling (2026-09-27) a document with `doc.errors` -- unreadable, no `version: 1`, a
  legacy-only tree -- RAISES on every reader instead of reading as "nothing committed" on some of
  them, and every reader prints `doc.disclosures`, so a refused symlink at the config path can no
  longer be visible on the setup path and silent on the run path. `_committed_matrix` is
  `_matrix_catalog` un-flattened rather than a second pass over the authored bodies, which is #2189:
  a scalar `match: src/**` used to become six one-character globs, a name the schema had just
  rejected came back anyway, and a non-mapping `groups:` value, a `match: [1]` or a `tests: [[a]]`
  crashed `driver setup` with an AttributeError and no JSON status. **Behaviour change:** a setup
  run over a config the schema rejects now refuses with the named error and writes no draft
  (`config_refusal`), where it used to merge against the authored bodies exactly as written --
  char-split globs, rejected names and all -- and tell the operator to move the result over their
  own file; a `driver run` still degrades per entry, one bad group at a time. `panels:`/`exclude:`
  come back from the validated domain sets, so a draft -- and `migrate-config`'s own output --
  renders them sorted rather than in authored order.
- **Every integrity failure that sinks certification is named on the terminal summary (#1761;
  ARC-3284703909).** The rule lived in three places with three memberships: `synth/integrity`
  published ~20 `meta.integrity` keys, `tool_axis.reconcile` re-spelled fourteen of them in a
  hand-written `or` chain, and `render_summary` named four — one of which deliberately does not
  gate. So ten of the fourteen sinking keys had no summary line of their own: nine were named
  nowhere on it, and one (`delta_scope_suppressed_git_drivers`) only inside `coverage_note`. The
  reasons went to stderr and the summary said the bare word `incomplete` — the hole #1644 closed
  for `tools_manifest_invalid` alone. The ten: `content_mismatched_files` (the #493 R4 tamper
  check — bytes that no longer match the fan-out snapshot), `content_snapshot_missing`,
  `content_snapshot_unreadable`, `malformed_findings_files`, `empty_dispatch_plans`,
  `invalid_dispatch_plans`, `invalid_verify_queue`, `dispatch_plan_missing`,
  `dispatch_plan_mismatched` and `delta_scope_suppressed_git_drivers`. One `INTEGRITY_KEYS` table
  in `synth/integrity` owns both facts: whether a truthy value sinks `integrity_ok`, and the
  operator sentence the summary prints for it. `reconcile` reads it as a comprehension,
  `render_summary` as one loop, so a key renders on exactly the truthiness that sinks the gate and
  the summary cannot drift from it again; a certification failure now outranks the non-gating
  cross-domain note, and the report schema's own property list is pinned to the table. The gate
  itself is unchanged — the sinking set is pinned key-by-key against the chain it replaced.
  `report.json` always carried the whole section; the HTML report is #2265.
- **spotbugs and pip-audit emit a repo-relative `location.file`, and the contract says so (#1768,
  #2188; ARC-284455831, ARC-2852754506).** SpotBugs nests a `SourceLine` inside the enclosing
  `<Class>` and another inside each `<Method>` before emitting the bug's own as a DIRECT child, so
  the `.//SourceLine` the adapter read was always the class's: on the pinned golden all three
  findings landed on line 11 of a class spanning 11-75 instead of 65, 69 and 66. It reads the bug's
  own now, falls back to the class's span only when the bug has none, and never a `<Method>`'s — a
  `role="METHOD_CALLED"` one names the CALLEE's file, a JDK source in no repository. The
  `sourcepath` beside it is relative to the SOURCE root (`org/dummy/App.java`), never the repo, so
  on a Maven or Gradle layout it matched no diff hunk and no read grant while the adapter's own
  comment claimed it stayed matchable; it is resolved against the target root by probing the
  conventional Maven/Gradle source roots — `src/main/java`, `src/test/java`, `src/main/kotlin`,
  `src/test/kotlin`, `src`, then the root itself — refusing an absolute or `..`
  sourcepath outright and refusing to follow a symlink out of the tree
  (`claim_scope.confined_to_root`, not a fourth copy of it). When nothing resolves the package path
  is kept and the finding says why in `tool_evidence.path_resolution`, so an unplaceable location
  has a stated cause. The `SourceLine start` that names the bug's line is read tolerantly with it:
  the report schema gives `location.line_start` `minimum: 1`, and SpotBugs' own unknown-line
  sentinel is `-1`, so one bug at an unknown line used to make a whole real Java report
  schema-invalid — absent, `-1`, `0` and an unparseable value now all clamp to 1, the way an
  unparseable rank already falls to MEDIUM rather than raising out of `parse` (which ingest reads as
  "unparseable" and loses the whole document). pip-audit stored the ABSOLUTE host path of the
  manifest it audited in its
  ContextVar and `_located_at` returns what it holds — unreachable on the production path, where
  invoke and parse run in different processes, and a scanner-host layout leak for any caller that
  shares one; it records the repo-relative path now, which is npm-audit's shape already. The
  normalization contract asserts a normalized relative `location.file` for EVERY adapter, with
  dependency-check's jar basename recorded as a disclosed debt naming #2225 — a debt, not an
  allowlist: the shape rule still holds it, and a self-liquidating test FAILS, saying to drop the
  entry, the day that adapter stops emitting a bare jar name.
- **No module is loaded twice, and the `sys.path` bootstrap gets a ceiling (#1766; ARC-188610019,
  ARC-2452079063, ARC-3214704952, ARC-11100703).** A driver-shaped process built two module
  objects from one file for NINE modules — `config_schema`, `coverage_model`, `diff_map`,
  `discovery`, `grouping_engine`, `groups_schema`, `model_resolver`, `plan_contract` and
  `repo_config` — each copy with its own module state and its own patch targets, so
  `dispatch.registration_model` ran on a `model_resolver` whose profile cache
  `mock.patch.object(scripts.model_resolver, …)` could not reach. `dispatch.py`,
  `setup_flow.py` and `grouping_engine.py` now import those siblings from the package, which
  retires four of the nine; the five that remain are the flat-import mode's own
  (`discovery.py` and `setup_proposal.py` must still import with only `skill/scripts` on the
  path) and are named, with their owner, in the new guard. `setup_flow.py`'s two CALL-time
  `import dispatch` statements went with them: each minted a second `dispatch`, with its own
  cached template loader, the first time a setup path ran. `synth/report.py`'s unreachable
  `except ModuleNotFoundError: from _version import __version__` arm is gone.
  `tests/test_module_identity.py` pins all four halves: the import-time census; a SHRINK-ONLY
  per-module ceiling on the `sys.path` write sites under `skill/scripts/` and `scripts/`, so a
  third insert inside an already-permitted module fails too, with each site reported against the
  root it adds (the flat root mints a second name; the `skill/` root is what grants the package
  one); the two `scripts` portions being name-disjoint; and no import fallback in a package
  module, keyed on a handler that imports and accepting `ImportError` alongside
  `ModuleNotFoundError`. A site that GOES AWAY fails a separate staleness test, not the ceiling —
  removing a bootstrap is the guard working. `tests/test_phases_child.py` pins the child
  PYTHONPATH contract by what a child can import rather than by the list of roots. Consolidation,
  including the call-time class the census cannot see, continues in #1516.
- **An interrupted or terminated driver ends its phase child and its runner children (#1805;
  COD-869076756).** A phase child (discovery, tools, synthesize) leads its own session, so the
  terminal's Ctrl-C never reached it, and `_run_child` ended its group only on a timeout: an
  interrupt waited out the 5 s reader join, then left the child running and writing into the run
  folder. A SIGTERM (a supervisor's stop, a CI cancel) killed the driver outright and left the
  phase child and every registered runner child running. `_run_child` now ends the group on any
  exception while its readers start or while it waits, and by the owner's ruling a SIGTERM takes
  the Ctrl-C path: the CLI runs `main` under `procgroup.sigterm_as_interrupt`, which raises it as
  the same interrupt and absorbs every later one until `main` returns; a SIGTERM that nothing
  handles prints `driver: stopped by SIGTERM` and exits 143 on every supported Python. The Kimi
  runner's SIGTERM secret-stripper now lets that interrupt run first and leaves the strip to
  `teardown`, after the children its `config.toml` guards are gone; it still strips before a
  default-disposition SIGTERM ends the process, and at an ignored one it no longer strips a run
  that carries on with entries still in flight (`teardown` or `atexit` strips it later).
- **A refused ledger recovery names the issue it could not read (#1805; COD-273223337).**
  Recovering the filed-issues ledger from GitHub refused the whole batch, anonymously, when a
  quoted marker block in one issue's own text tripped the check; `refusing:` now prefixes that
  issue's URL, and the exactly-once marker, source-report and location rules stay unchanged.
- **An empty `CODEX_HOME` means `~/.codex`; a relative one is refused (#1803; COD-1638371699).**
  `hosts.py` fell back to `~/.codex` only when `CODEX_HOME` was unset, so an empty value made the
  Codex registration directory `agents` and a relative one stayed relative, and every Codex consumer
  resolved it against the working directory -- in the documented flow, the reviewed tree. Under an
  empty value, a target shipping `agents/panopticon-*.toml` passed the runner's up-front check and
  supplied every role's `developer_instructions`; the codex probes inspected those shells, readiness
  called them registered, and `--emit-host-agents codex` wrote `agents/` into the working directory.
  Owner ruling 2026-09-27: empty means unset, and a relative value is refused with "CODEX_HOME must
  be an absolute path (it is 'rel/home'); unset it to use ~/.codex" -- by the runner and its shell
  loader, both codex probes, emission (exit 1, nothing written) and the readiness row. An explicit
  directory still wins, and importing `hosts` never raises.
- **One parser for the `findings-<group>-<domain>` cell identity (#1765, ARC-3899903550).** Four
  modules read that name independently and disagreed at the edges: `findings_contract.cell_of` did
  not validate the domain, `synth/coverage_io.present_cells` and
  `synth/integrity._expected_from_filename` did, and `synth/findings.GROUP_RE` also accepted the
  4.x panel names and their retired `-panel_review` / `-lens_sweep-<lens>` suffixes. On an
  off-roster or mistyped domain -- `findings-App-XYZ.json` -- ingest stamped no `_group`, the
  mislabel guard said "nothing wrong", the floor audit could not see the cell, and the defect
  diagnostic claimed a cell for it anyway: every branch failed toward invisible, in four different
  directions. `cell_of` now validates the trailing token against `groups_schema.DOMAINS` and owns
  the parse; the other three call it, and so does `synth/plan.out_of_scope_findings`. The 4.x
  alternation is DROPPED rather than moved into it: the roles retired in #1441, `plan_contract`
  pins every reviewer `out_file` to `findings-<group>-<domain>.json`, and nothing in the 5.x
  pipeline can produce the old spelling. A file whose trailing token is no domain code now names no
  cell: one whose PAYLOAD was rejected is still named without a cell
  (`malformed_findings_files`), and one that parses cleanly is surfaced by
  `unexpected_findings_files` wherever a dispatch plan exists.
- **Setup's flat seed drops the group names a run would refuse (#1788; COD-2612640453).**
  The vocabulary-absent fallback kept every name `parse_groups` returned, even one it only flags
  as an error: a case twin, a chunk twin, or the reserved `Ungrouped` sink. `groups_schema` now
  exposes `colliding_ids`, and the seed drops those names too.
- **`defang` neutralises issue references and URLs in every form GitHub links (#1793;
  COD-3436467706).** `GH-N` links in any letter case beside `/`, `-` or `.`, and `#N`
  shares its "before" boundary: no ASCII letter, digit or underscore immediately
  precedes either, and no word character follows `GH-N`'s number. `http(s)://` links
  unless an ASCII letter (not a digit or underscore) sits right before the scheme. Case
  insensitivity no longer folds those ASCII checks, and the `GH-N` substitution keeps the
  matched text's own letters, as the `http(s)://` one already did.
- **The Kimi probes report a hung doctor, a failing home writer and a malformed config (#1788;
  COD-2149752625).** Three posture probes on `--host kimi` let an exception escape where their
  siblings already turn it into a reported state: `_kimi_home_arms_and_validates` caught only
  `OSError` around `kimi doctor`, so a doctor that outlives its timeout or writes output that
  does not decode escaped as a traceback; `_kimi_hooks_are_armed` caught only
  `(OSError, RuntimeError)` around the per-run home writer, so a `ValueError` or `TypeError` from
  it escaped too; and `probe_kimi_model_alias` let a malformed or unreadable operator
  `config.toml` escape the same way. All three now report instead of raising, and the writer's
  exception tuple is defined once (`kimi_snapshot._HOME_WRITER_EXCEPTIONS`) so the two probes
  that drive it cannot drift apart again.
- **A sentence-final file name reaches the backup's evidence closure (#1793; COD-148287761).**
  `evidence_scope._PATH_RE` vetoed a sentence-final `.` like any other path character, so a claim
  naming a file only at a sentence's end never reached the closure. A `.` now ends a name unless
  another path character follows, so `grading.py.bak` and `notafile.python` still yield nothing.
- **The category-to-CWE table holds only overrides the catalog can deliver (#1795;
  COD-4238512708).** `config`, `logging` and `headers` named CWE ids `cwe-catalog.json` never
  carried, so those three entries never derived a citation and dropping them changes no output.
  A new test now pins every remaining entry in `CATEGORY_CWE_OVERRIDES` to the catalog.
- **One owner for the persisted retry budgets (#1767, ARC-655791509).** Five phase modules
  hand-copied the same read-bump-write over a counter file under `.panopticon/` in the reviewed
  tree, and the #1809 round consolidated only the READ -- `runio._load_state_json` refuses a
  present-but-torn document -- so the arithmetic on top of it kept THREE answers to the same
  planted value. `coverage._bump_scout_attempts`, `discovery._bump_discovery_attempts` and
  `verify._bump_verify_attempts` raised a bare `ValueError` out of `int()`, a message an operator
  cannot act on where the read one line away would have named the file and `--reset`;
  `review._record_attempts` RESET the cell's tally to 1, refunding every attempt the run really
  spent, which is the one outcome #1809 says the ledger exists to prevent; and
  `persist._give_back_attempts` silently `continue`d, which made a planted value
  indistinguishable from a key nothing had ever charged. The new `phases/budget.py` owns the
  arithmetic -- `count` / `bump` / `bump_many` / `give_back` -- and answers all three the same
  way: a value that is not a non-negative `int` (`bool` excluded, since `isinstance(True, int)`
  is True) is UNREADABLE exactly like a torn document, and refuses with the same actionable
  shape, naming the file, the offending key and `--reset`. Never a reset, never a skip. Each
  caller keeps its own file name, key scheme and description, because those are the on-disk
  contract a RESUMED run reads back; reads still go through `runio._load_state_json` and writes
  through `runio._write_json`, so the symlink refusal at an artifact path is not re-implemented
  behind the new names. `review._cell_exhausted` was the sixth site and the quietest: an
  unreadable value read as "not exhausted" made a spent cell dispatchable again, silently.
- **`ci.yml` states its token posture instead of inheriting one (#1784, ARC-3955973987).**
  `tests/test_workflow_pins.py`'s `privilege_defect` asserts the posture the three `ci.yml` install
  exemptions are written against -- unprivileged trigger, read-only token -- but it read an ABSENT
  `permissions:` block as unprivileged, because a block that does not exist grants no `write` scope.
  So "the default read-only token" in those exemptions meant the repository's `GITHUB_TOKEN`
  setting: not in this tree, not reviewable in a PR, and one settings change away from a write token
  that would keep four unpinned installs exempt. A job with no `permissions:` of its own and no
  workflow-level block to inherit is now a defect naming that job; a block at either level satisfies
  it, which is how `codeql.yml`, `nvd-cache.yml`, `security.yml` and `docker-publish.yml` already
  stood. `ci.yml` and `docker-build-pr.yml`, the only two files that declared nothing, now carry a
  top-level `permissions: contents: read` -- neither pushes, logs in to a registry, nor publishes.
- **A zero-hunk active delta gate reads INCONCLUSIVE, not PASS (#2178; refs #1783).**
  #1783 disclosed the shape on stderr and left the policy open. A diff-hunks artifact that resolves
  a base but carries no diff ranges keeps the delta ACTIVE while matching nothing, so under the
  default `--gate-scope on-diff` the gate's source set is not a measured diff, and a change
  carrying active findings reported a green `PASS` on findings that were never gated.
  OWNER RULING 2026-09-27: refuse to certify. `summary.gate` now reads `INCONCLUSIVE` and
  `summary.coverage_note` names the zero-hunk map plus the remedy (regenerate the diff-hunks
  artifact; the driver's discovery phase writes it) -- or names the REJECTED payload instead, when
  that is why the map is empty, rather than sending the operator to compare a known-broken artifact
  against itself. Two carve-outs are part of the ruling: an empty legitimate change with NO active
  findings still passes, and falling back to the wider scope was REJECTED, because a benign empty
  `--changes` run would then go red on pre-existing findings it did not introduce. `ranges == 0` is
  the measure, not `files == 0`: a map that names a file and gives it no range scopes the gate by
  `diff_map.classify`'s two FAIL-OPEN arms, which is not a measured diff either.
  `delta.zero_hunk_gate_gap` is the one place that decides whether there is a gap, and `certify`'s
  new `delta_zero_hunks` reason joins `gate_relevant_gap` -- so a real FAIL and an armed-but-OFF
  gate are untouched, and `coverage_certified` is false either way. No new report key: the reason
  rides the existing certification note, placed after the unreadable-manifest note (which names a
  broken file) and before every other caveat, since an empty gate scope invalidates the gate
  wholesale.
- **One tested reader for the Dockerfile's dependency-check pins (#1774, ARC-261650949).**
  `docker-publish.yml`'s "Resolve NVD data image digest (content-pin the cache)" step and
  `nvd-cache.yml`'s "Read dependency-check version from the Dockerfile" step each re-derived
  `DEPENDENCY_CHECK_VERSION` -- and one of them `DEPENDENCY_CHECK_SHA256` -- with its own
  `grep | head -1 | cut -d= -f2` and its own inline shape check. Both now call `python3
  scripts/dockerfile_args.py read-arg <NAME>`. The shape checks MOVED there, they were not
  dropped: the module is a closed map of ARG name to anchored pattern, it refuses a name with
  no registered shape, and it exits 2 so `set -euo pipefail` still fails the step -- the
  control nvd-cache.yml described as "constrain to expected shapes so a tampered ARG can't
  inject downstream". The version shape is STRICTER than the grep it replaces, which also
  accepted `10.0.3.` and `1..2`, and a value carrying a second `=` is now refused rather than
  truncated to the part before it. `tests/test_dockerfile_args.py` covers the reader, both
  callers, and the committed Dockerfile's own two pins.
- **One owner decides which evidence statuses count as verified (#1774; ARC-3073755386).**
  `html_report` derived it twice, differently. `_render_header` counted an INCLUSION of two statuses
  (`tool_confirmed` + `advisor_confirmed`) while `_render_findings` split the tabs on an EXCLUSION
  of three (`tool_reported`, `needs_more_info`, `unverified`), so five of the ten possible inputs
  fell on one side of the word in the header and the other side in the tabs -- and the exclusion
  form failed OPEN: a status added to `evidence.EVIDENCE_STATUSES` later would have joined the main
  list silently. Both vocabularies are now closed sets in the new
  `skill/scripts/evidence_sections.py`, which partitions `EVIDENCE_STATUSES` and raises at import if
  it ever stops doing so, the way `score_gate.EVIDENCE_FACTOR` already did. They answer two
  different questions, so neither is the other's complement: `VERIFIED_STATUSES` is the header's
  WORD -- a second opinion agreed, which is why `backup_scope_limited` is not in it (#1638 P16) and
  keeps its own disclosed segment -- and `UNVERIFIED_STATUSES` is the report's SPLIT, what the
  collapsed "Unverified findings" section holds. `corroborated`, `rejected` and
  `backup_scope_limited` are the named remainder that stays in the main severity tabs; `rejected`
  cannot reach them anyway, because `synth/report.py` publishes `resolve_findings`'s `active` list
  as `findings` and the rejected half goes to `discarded_claims` and its own section. **Nothing
  moves for the eight known statuses**: both rules were run over each of them and agree, the
  header's count is the same sum of the same two keys, and
  `test_the_eight_known_statuses_do_not_move` pins that table. What changes is the tenth input -- a
  finding whose `evidence.status` is unknown or missing now lands in the "Unverified findings"
  section instead of the main list, disclosed rather than read as reviewed. The sets live in their
  own module rather than in `evidence.py` because that module and `html_report.py` are both pinned
  at their exact current size by the shrink-only ratchet in `tests/test_flat_module_ceiling.py`,
  whose stated remedy for a module that needs room is a new module; `html_report.py` came down two
  lines and its pin came down with it.
- **Give the issue-ledger default one owner (#1821).** Reconciliation now obtains its default
  ledger path from `file_issues.LEDGER`, matching the loader it already shares. Recovery writes
  and the plan CLI keep the same default, and explicit ledger paths behave as before.
- **Use one owner for runner and adapter vocabulary (#1821).** The loop, Codex preparation
  and session instructions share the runner's setup namespace. Brakeman applicability uses the
  same Rails markers as staging. The Semgrep smoke scan reads the production adapter command
  when invoked and substitutes only its fixture target, so adapter flag changes reach the smoke
  check automatically. Existing setup behavior, scanner arguments and security modes are retained.
- **Bound synthesis run metadata before JSON parsing (#1820, #1825).** A shared reader
  limits ordinary run artifacts to 16 MiB and keeps coverage records at their existing 1 MiB
  limit. It refuses final-component symlinks and nonregular files without waiting for a FIFO
  writer, and turns JSON recursion/memory failures into the caller's normal unreadable-input
  path. Strict metadata and tolerant agent-envelope parsing keep their existing formats.
  Callers retain their shape checks, fallback values and invalid-artifact disclosures; an
  unreadable manifest or verify queue cannot become an absent one. Parent-directory aliases
  such as macOS `/var` remain supported. This supplies the shared reader requested by #2081
  and #2082; changing the existing coverage-skip certification policy remains #2080.
- **Align implementation documentation with the current contracts (#1819).** Kimi preparation
  always creates a fresh home, including on resume; the recorded pointer is informational.
  Report grades use health when available and display n/a without reviewed lines to grade; the
  gate keeps its own policy. Repair documentation names the boundaries and distinguishes content
  bounds from byte limits at the caller. These changes affect comments and docstrings only.
- **`file_fixmes.parse` refuses a heading or a rule it cannot parse (#1765, ARC-4143722514).**
  `HEAD_RE` requires an em dash, so `## FIXME-3 - title` did not match it, and with a section open
  the line was appended to the PREVIOUS FIXME's body -- one issue silently lost, another silently
  doubled; a `---` inside a body closed the section and dropped the rest of it. Neither case said
  anything, and these sections become GitHub issues out of a hand-written doc, so input the parser
  could not read became wrong issues. A second regex, `HEAD_LIKE_RE` ("looks like a FIXME
  heading"), now makes the disagreement loud: a line it matches while `HEAD_RE` does not raises
  `ValueError` naming the line of the doc, its text, and the required `## FIXME-<n> — <title>`
  form. A rule while a section is open raises only when body text sits between it and the next
  heading-like line, which is what makes that rule INSIDE the body; a rule followed by blank lines
  and the next heading is a separator and closes the section, and the trailing rule that ends the
  list -- the documented behaviour -- still stops the parse there and leaves the 'Already fixed'
  commentary unfiled. `main` parses before it loads the ledger or reads the `gh` environment, so a
  refusal precedes every GitHub call (now pinned by a test), and no doc under `docs/` or
  `skill/docs/` mentions this script.
- **A whole-file finding no longer has to invent a line number (#1784; ARC-2002725967).**
  `skill/reference/findings-envelope-schema.json` required `location.line_start` on BOTH of its
  finding definitions (`legacyPanelFinding`, `domainRoleFinding`), while the published
  `report-schema.json` requires only `file` there and says in that `location`'s own description
  (#1522) that a whole-file finding -- a missing header, a bad config -- is legitimate and must
  not have a line number invented for it. The envelope is the stricter of the two AND the one
  that governs emission: `phases/persist.py`'s `ROLE_SCHEMAS` maps the `review-cell` role to it,
  `role_schema` hands it to the runner as the CLI's output schema, and
  `ENVELOPE_SHAPES`/`RETRY_PROMPT_BLOCK` re-prompt a refused reply. So on a host whose CLI
  enforces that schema (claude, codex) a legitimate whole-file finding was either refused or
  re-emitted with a fabricated line, in a pipeline whose premise is that evidence is not
  invented. Both `required` lists are now `["file"]`, and `line_start` keeps
  `{"type": "integer", "minimum": 1}` so an invented `0` -- or a string -- still fails. Nothing
  downstream needed changing: `synth/findings.py` already DROPS a `line_start` a finding does not
  carry rather than filling one in, and every other consumer reads it through `.get`. Two
  residuals are disclosed, not fixed, here (follow-up #2174): `synth/report.py` still WARNs
  `missing location.file/line_start` on the now-sanctioned whole-file finding until that check
  is split, and the envelope still requires `location` itself while the report schema does not,
  so a locus-free catalog-gap finding is still refused. `skill/agents/domain-panel.md` now tells
  the reviewer to omit `line_start`/`line_end` entirely (not `null`) for a whole-file finding
  rather than invent one, and the new `test_envelope_location_required_matches_report` pins each
  envelope `location` `required` set to the report schema's, extending #1602's parity guard
  (`tests/test_schema_parity.py`, report vs schema) to the emission envelope.
- **`collect_usage` counts the input it drops, and the summary line says so (#1782,
  ARC-2134807886).** Three drops were silent: `_iter_records` returned on an `OSError` (an
  unreadable transcript yielded nothing at all, and `collect`'s `if not n: continue` then did not
  even count it), it skipped a line `json.loads` rejected, and `_add` ignored a usage value that
  was not an `int` -- so `total` read as authoritative while being a floor, the one thing the
  module docstring promises against ("an absent number stays absent rather than becoming a
  fabricated zero"). `sources` already held the channel and the precedent:
  `subagent_transcripts_truncated` (#1576) is the number that keeps the rest of the document honest
  when the cap binds. Three counters join it, always present and 0 on a clean run.
  `unreadable_transcripts` counts the FILE once, controller or subagent, and deliberately does NOT
  fold into `subagent_transcripts`: that count has to keep re-summing to
  `subagent_transcripts_by_phase` and to the transcripts actually summed, and an unreadable file
  contributed no record to either. `undecodable_lines` counts each torn line, once per file rather
  than once per read -- `classify_transcript` re-reads a subagent transcript for its first prompt
  and is not given the accounting dict. `non_integer_usage_fields` counts each present-but-not-int
  value, a `bool` included: `bool` is an `int` subclass, so `"output_tokens": true` used to pass the
  isinstance check and add one fabricated token, and it now adds none. An ABSENT field is still not
  a drop. The counts surface in `sources`, and so in the report's `meta.cost.tokens.sources`.
  `main` also prints ONE stderr line naming all three when any is non-zero, before the document is
  written or dumped; a clean run prints nothing new. That line reaches a terminal on a DIRECT run
  of the script: synthesize captures the collector's stderr and reads only its exit code -- #1576's
  own FLOOR line is swallowed the same way -- so on the wired path `sources` is the half that
  reaches an operator (follow-up #2171). No schema change was needed: `meta.cost.tokens` is an
  unconstrained object in `report-schema.json` and `load_run_usage` surfaces the document verbatim.
- **A malformed or empty diff-hunks payload is disclosed, not swallowed (#1783; ARC-2340795244).**
  `synth/delta.py`'s loader is total by design -- an unreadable or non-object `diff-hunks.json`
  yields `{}`, a non-object `hunks` becomes `{}`, and every range that is not a two-integer pair is
  dropped -- and it said none of that anywhere. The consequence is asymmetric. A payload with no
  `base` degrades to a full-repo review, which is the WIDER gate; a payload WITH a base and an
  empty hunk map stays an ACTIVE delta that matches no finding at all, so every finding classifies
  off-diff, `--gate-scope on-diff` scopes the gate to that empty set, and a change with findings
  reports a green gate -- indistinguishable from a genuinely empty diff, over an artifact the
  driver hands synthesize on file existence alone, from a fixed path inside the reviewed tree's own
  `.panopticon/`. The loader now returns a `HunksLoad` beside its data (the old name delegates to
  it, so every caller is unchanged), and `from_args` prints in the #957 register: the rejection
  reason with the path, a ZERO HUNKS warning naming what that costs the gate and how to tell an
  empty change from a broken artifact, and a count of the ranges dropped. The warning distinguishes
  the two shapes zero ranges can take, because `diff_map.classify` fails OPEN for a lined finding
  in a file the map NAMES without a range. `meta.coverage.delta` carries the same four facts --
  `hunks_files`, `hunks_ranges`, `ranges_dropped`, `payload_malformed` -- whenever the payload
  resolved a `base`, with `files_changed` left as the artifact's own claim beside the map actually
  classified against; a payload rejected outright leaves the review non-delta and that block null,
  so there only stderr carries it. The gate's scoping RULE is untouched: this is disclosure, and
  what an empty on-diff gate should DO is a policy call.
- **`dispatch.js` refuses an entry marked enforced that names no registered shell (#1783,
  ARC-204863095).** The session-mode Workflow script validated each entry's `id`, `marker` and
  `prompt_file`, then branched on `e.enforced && e.agent` -- so an entry carrying `enforced: true`
  with a missing or empty `agent` fell through to the UNENFORCED branch in silence: no registered
  `panopticon-*` shell, no host-enforced tool grant, no log line, while the request on disk still
  recorded that entry's launch shape as enforced. The driver holds the same rule one level up
  (`loop_batch.refuse_misrouted` refuses a request whose enforced entry does not name the shell its
  output role and checkpoint expect), so the reachable path was a session hand-copying the request's
  entries into `args.entries` -- exactly the reduction the script's own header asks for. The
  validation loop now refuses such an entry in the register of `loop_batch.misroute_refusal`, and it
  refuses THERE rather than in the dispatch loop: an integrity refusal must not leave a batch half
  launched, so no `agent()` call is made for any entry in it. No production path emits such an entry
  (all five request builders set `agent` to the registered name exactly when the entry is enforced),
  so the refusal costs no real request. The pin that had recorded the old fall-through as behaviour
  now pins the refusal, beside an empty-`agent` case and a two-entry case proving the good entry
  ahead of the bad one never launched.
- **The Kimi guard hooks run the driver's own interpreter, and `prepare` refuses one that cannot
  start (#1777; ARC-1774133676).** Both PreToolUse hooks in the per-run `config.toml` named the bare
  word `python3`, and nothing resolved it: the CHILD looks that name up in its own PATH, and the
  launcher rewrites PATH -- `runners/children.py` sanitizes the startup environment and then sets it
  from `executable.resolve`, which drops every entry inside the review root. An operator whose
  `python3` came from the reviewed repo's own `.venv/bin` therefore armed two hooks with a name the
  child resolves differently, or not at all, and a Kimi hook that does not start fails OPEN: read
  and write confinement silently unarmed -- the exact residual the runner's own C3 comment named
  while checking only the guard SCRIPT. The interpreter is `sys.executable` now (this process,
  chosen by neither PATH nor the target -- the binding `read_guard_hook` and `codex_host` already
  use), armed as its `realpath` so a venv symlink resolves to the binary that actually runs and the
  reviewed tree's own `site-packages` never joins the guard's `sys.path`; an empty, relative or
  unrunnable one is REFUSED rather than swapped back for a bare name. One function asks that whole
  question and returns the path it validated, so what was checked
  is what the hooks are armed with; `KimiRunner.prepare` asks it, with the guard script's presence,
  before any child launches, and the two probes that build the same home report the refusal instead
  of ending posture establishment in a traceback. Pinned with PATH emptied, so no `python3` shim on
  the machine running the suite can stand in for the name the child could not resolve, and with the
  interpreter path's own quoting -- it is interpolated into a shell string too, and one under a
  directory with a space in it is ordinary. What remains is stated where it was: a hook can still
  die for a reason no pre-flight sees (script or interpreter replaced mid-run, an exec that fails
  under load, an adjudication past the hook's 30-second timeout), so the shells' tool allowlists
  stay the primary control.
- **The scrub funnel binds a deterministic repo root, and reconcile's comments go through it
  (#1777 ARC-1735086130, #1780 ARC-163067013).** `sanitize._detect_repo_root` fell back to
  `os.getcwd()` and nothing refused a degenerate root. Probed with an empty PATH at `/`, `scrub()`
  deleted every `/` in the text it was handed (the literal `str.replace`), `re.escape("")` left the
  second substitution an empty-match pattern, and `repo_relative` ate the leading slash. The mirror
  is worse: a filer run from another checkout gets a prefix that strips nothing, so the operator's
  absolute paths land in a public, permanent issue, which is the one thing that module exists to
  prevent. Both detection branches now go through one normaliser that REFUSES a filesystem root, a
  non-absolute root and a root that is not an existing directory, and returns a realpath'd prefix
  (realpath normalises an operator-supplied LOGICAL root to the physical form locations carry;
  measured here, `git rev-parse --show-toplevel` and `os.getcwd()` both report the physical path
  already, so it is a no-op on the two detection branches and defence should a git report a logical
  one). `scrub`/`repo_relative` take an explicit `root=` that REPLACES the detected root, normalised
  and refused alike but with its own remedy, since a caller who passed a root cannot act on "pass
  the root explicitly"; the cached detection stays the default, so no filer changes a call. That
  determinism is what the second half needs. The module header claimed `scrub()` is the one point
  every filer shares, but `reconcile_apply._comment_body` posted `action["comment"]` with only
  `neutralize`'s markdown pass -- no path stripping, no redaction -- while the `reason` it
  interpolates is built from report locations that `_source_records` proves can be absolute. The
  comment is now scrubbed BEFORE the `<!-- panopticon-reconcile:KEY -->` marker is appended, so the
  marker (keyed on the raw action, so no receipt is rebound) survives byte-for-byte and
  `_comment_present`, which compares the FULL body on the resume path, reconciles against the
  scrubbed body that was posted. A body that cannot be reproduced is still refused, but the refusal
  now names the likely cause: a comment posted from a different repo root.
- **The fixture runner's two containers launch under `run_tools`' container policy (#1767;
  ARC-3859414366).** `run_tools` owns that policy and its docstrings said so: cap-drop,
  no-new-privileges and the memory/CPU/pids ceilings "applied to every tool/adapter container".
  `run_fixture_tests.py` imported no part of it, so the two could not agree by construction -- and
  the container that runs the whole adapter suite on a developer machine launched with none of them:
  the real scanners over live attacker-shaped inputs (a planted `eslint.config.js` and a shadow
  `node_modules` plugin eslint must refuse to load, a planted `.gitleaks.toml` rule set and a
  `GITLEAKS_CONFIG` hijack gitleaks must ignore) plus the dotnet/MSBuild and JVM toolchains over the
  baked goat trees. The `hostile-csproj` corpus is baked into that image too, but its build is
  opt-in under `PANOPTICON_CONTAINMENT_PROBE=1`, which only the containment lane sets, so
  `evil.csproj`'s `curl` target does not fire on this path. The fixture-presence probe beside it had
  no `--network none` either. The two helpers carry public names now (`privilege_drop_flags`,
  `resource_limit_flags`; the underscore spellings stay identity aliases, so no call site moved) and
  the fixture runner splices both lists into both `docker run` argvs, plus `--network none` on the
  probe. Pinned as parity rather than resemblance: the flags between `run --rm` and the rest of the
  argv are exactly what `run_tools` returns, and one test retunes a ceiling inside `run_tools` and
  watches both launches follow -- a copy passes a spot-check and then drifts. The envelope's failure
  modes now name themselves instead of arriving as a bare number: the probe quotes docker's refusal
  when the daemon rejects a ceiling, rc 137 is reported as the memory ceiling's OOM kill, and rc 124
  as a timeout with the CPU throttle named as the likely cause. What this cannot prove: Docker is
  out of
  reach in the fixing session, and the daily `adapter-integration` workflow runs its own
  `docker run` rather than this script, so the first local `run_fixture_tests.py` is the end-to-end
  check. The ceilings are the ones these same scanners already run under (6g memory, 4 CPUs, 1024
  pids), and all three stay retunable through `PANOPTICON_TOOL_MEMORY` / `_CPUS` / `_PIDS`, an empty
  value dropping that ceiling -- which the fixtures guide now records beside the command.
- **The CLI advisor renderer confines claim locations and pins the review root (#1767, run-14
  ARC-3314534783).** Advisor-prompt assembly existed twice. The driver's two advisor rounds rewrite
  an escaping `location.file` to a redaction marker and pin `Repo root: <review_root>` before
  rendering `advisor.md` (#run8 ARC-F2A); `dispatch.render_advisor_prompts` -- reachable as
  `--render-advisor QUEUE`, and documented -- did neither: the finding went into the claim JSON
  VERBATIM and the root pinned was `os.getcwd()`. An advisor's Read/Grep/Glob are unconfined, so a
  redteam target whose planted `location.file` is `../../../.ssh/id_rsa` steered this path straight
  out of the review tree, on the exact channel the project had already ruled closed. Both halves now
  live in one stdlib-only leaf, `skill/scripts/claim_scope.py`, reached from both sides: the
  confinement predicate moved DOWN out of `phases/runio`, because a leaf is the only module
  `dispatch` and `phases/*` can share -- `runners/*` import `dispatch`, and layout rule 3 forbids
  them from reaching the phases package -- and `runio._confined_to_root` /
  `verify_tools._confine_claim_location` keep their names as aliases whose identity a new test pins,
  so a second implementation cannot reappear behind either. The renderer takes `--review-root` and
  otherwise resolves the root from the queue's own `.panopticon` path, REFUSING when it cannot
  (a wrong root points the advisor at another checkout, which is what the cwd fallback did). The
  driver's own prompts are byte-identical, pin paragraph included.
- **One spelling of the read-scope keys, and the guard hooks' read-scope copies pinned (#1767;
  ARC-1784455652, ARC-2812051140).** The read guards are three deliberate copies of one rule, and
  each of the three runs with no package on sys.path -- the hooks because a hook is invoked by
  absolute path, as its own process, the broker because it is launched `-I`. None of them can
  import a sibling. But only the BINDING half of that copy was pinned, and the read-scope half had
  already drifted in logic. `kimi_guard_hook._load_scope` looped over an inline literal of the
  four scope keys while `read_guard_hook` looped over its `SCOPE_KEYS` constant, so a fifth key
  added to the read guard would have been honoured by Claude's hook and silently ignored by
  Kimi's: one entry, confined two ways. Kimi's loader now reads a `SCOPE_KEYS` of its own, and a
  new parity class pins all seven read-scope helpers plus both constants AST-identical, docstrings
  stripped (each copy explains itself where it stands; prose is what a copy may differ in, code is
  not). That net also caught the one place the Codex broker's `_under` answered a grant
  differently from the hooks': with `/` as a directory grant, `rstrip(os.sep)` left "" and every
  absolute path was admitted, where the hooks' `or os.sep` reads a `/` grant as the root directory
  ALONE. The broker takes the hooks' edge. Two residuals close with it: the write guard's atomic
  writer has a public `atomic_write_json` (the underscore spelling stays an alias, and a source
  pin keeps `runners/batch.py` off the private surface) so a package module no longer reaches into
  a hook script's private function, and a measured flags pin now holds the writers that spell the
  no-follow open by hand -- the three stage-and-rename writers (the two guard hooks' and
  `runners/kimi_home`'s) and `safe_write`'s artifact pair -- with `O_NOFOLLOW` on every one, the
  three stagers identical at mode 0o600, and the artifact pair differing only in the two ways
  that were decided.
- **The codex enforcement shells are encoded by the shared TOML encoder (#1763, run-14
  ARC-981076646).** `emit_host_agents`'s codex branch flattened its policy with a nested
  `emit_values` that spelled every value with a bare `json.dumps` and carried its own copy of the
  bare-key regex, duplicating `skill/scripts/toml_values.py` -- the encoder `codex_host` and
  `kimi_toml` both already go out through. `json.dumps` defaults to ASCII mode, which writes a
  non-BMP character as a surrogate pair, invalid in TOML: one emoji in a template `description`
  registered a shell `tomllib`, and codex's own parser, refuses ("Escaped character is not a
  Unicode scalar value"), and a lone surrogate went out escaped instead of refused. The three
  inputs -- a template description, the codex charter, the resolved model -- are ASCII today, so
  nothing had fired yet. Emission now calls `toml_values.key` / `toml_values.value`, the
  flattener's nested-table-to-dotted-key shape is untouched, and a new test re-emits every ASCII
  role's file through the old flattener and demands the same lines back.
- **The TST global floor now recognises the test-file suffix conventions discovery already
  knows (#1770; run-14 ARC-3682668884).** `coverage_model._TEST_FILE_HINTS` gated the TST floor
  on substring hints -- `.test.`, `/tests/`, `test_` -- and knew none of the SUFFIX conventions
  `discovery.TEST_PATTERNS` has always matched: `AppTest.java`, `AccountTests.cs`,
  `AuthTest.php`, `app_tests.py`. So a flat Java layout and every standard C# or PHP repo drew
  no guaranteed TST cell, while the floor's own docstring promised the opposite -- that a
  mis-reporting scout "cannot suppress a floor domain whose surface objectively exists". For
  three languages it could. `applicable_global_floor`'s TST signal is now the UNION of
  `discovery.is_test_file` and the hints: the hints stay, because they cover the plumbing the
  naming rule misses (`conftest`, a `/tests/` corpus, `.feature`), and the union ends the drift
  between two independent derivations of "is this a test file" -- a convention added to
  `TEST_PATTERNS` floors TST from then on, and a parity meta-test fails if one arrives without
  a fixture. The behavioural ratchet on this repo is nil: every group in the committed
  `panopticon.yml` matrix, and both chunks of the residual sink, already had a TST floor cell.
- **The adapter-integration lanes run as the user production scans run as (#1771, ARC-2930403871).**
  `Dockerfile.fixtures` ends on `USER root` -- right for its build, which installs toolchains and
  writes build artifacts -- and the daily workflow passed no `--user`, so the one gate where the
  adapters meet real tools and real fixtures proved them as uid 0 while every production scan runs
  the tools image as `scanner` (its `useradd -m -u 1000 scanner`, then its closing `USER scanner`).
  A root-only adapter regression, the #1877 class, passed the only gate that could catch it. Both
  jobs now pass `--user scanner` with production's `HOME`, and each asserts `id -u` inside the
  container before running a probe. `Dockerfile.fixtures` says that build-time root is not a runtime
  posture and that the image is no longer local-only; it moves the .NET package cache out of root's
  0700 HOME (`NUGET_PACKAGES`, then `a+rX`) so `project.assets.json` names a path uid 1000 can read;
  and it hands `scanner` back the four cargo subtrees this build dirties as root -- `registry`,
  `git`, `.package-cache`, `.global-cache` -- leaving the RustSec `advisory-db` beside them
  root-owned and read-only, which is what the scan needs and all it needs.
- **The 700-line ceiling now covers the flat modules and the entry scripts (#1761, #1762,
  #1763; run-14 ARC-2609514778).** `tests/test_layout.py` rule 5 ratchets only the `synth`,
  `phases`, `runners` and `probes` packages, so the largest modules in the tree were the
  unmeasured ones: `skill/scripts/run_tools.py` went from 1231 to 2215 lines in the six days
  after that finding was written, because every new scanner policy landed there and nothing
  pushed back. `tests/test_flat_module_ceiling.py` applies the same `LINE_CEILING` to every
  `*.py` directly under `skill/scripts/`, the repo-root `scripts` directory and the `tools`
  adapter package (which rule 5 does not name either), as a shrink-only allowlist: twenty
  modules pinned at the count they have today, each free to shrink and never to grow, and a pin
  that reaches the ceiling has to go. Raising a number is not a fix -- the allowlist is the list
  of splits owed.

- **Requirement hash refreshes preserve extras and environment markers (#1847).** The updater
  replaces hash options while retaining the requirement clause and comments, and requests
  artifact hashes for the base distribution. Root configuration also requires integer
  `version: 1`; YAML `1.0` is refused with the existing version diagnostic. Reconciliation
  rejects boolean `schema_version` values before action planning.

- **The seven residuals this SEC round re-found are written down where each is decided (#1831,
  #1836, #1838, #1839; run-14 SEC-3334394305, SEC-589720899, SEC-882922343, SEC-1915770944,
  SEC-136999130, SEC-3084426934, SEC-2589722723).** All seven are BY DESIGN and the sentences
  describing them were false, in four places. `workflow_guard`'s pin-rule rationale claimed the
  image a `docker run` step executes is pinned by digest elsewhere; it is not -- every workflow
  that consumes it pulls the tools image by its mutable `:latest` tag, which is the residual
  DEVELOPMENT.md already accepts -- and the same claim one level out in `scripts/workflow_forms.py`
  went with it. DEVELOPMENT.md itself said "weekly rebuild" in one place and "monthly" in another
  about an image CI republishes nightly. The rest state the decision where it lives: the floating
  .NET SDK channel joins the Dockerfile's own list of the inputs its hash closure does not cover;
  the report's exclusion line and schema say those globs prune review CELLS, not just the tool
  axis; `family-pr-review.js` says its finders and refuters are unconfined by design, and now
  `JSON.stringify`s the three finding strings `evidence` already went through; and the readiness
  remedy's mutable pull gains the `gh attestation verify` step an operator can take, in the guide,
  the README and GETTING-STARTED. One test was owed and is here: `evil.csproj` must hold exactly
  one target, hooked to `Build` and nothing else, or its `curl` fires on the networked
  fixtures-image builder.
- **Malformed Kimi usage records remain unknown data (#1847).** Invalid counters are skipped
  as a whole record while adjacent valid turns still count. Wire lookup rejects non-string,
  traversal and glob identifiers. Runner refusal diagnostics redact credentials before taking
  their 200-character excerpt, including credentials crossing that boundary (#1853).
- **Gitleaks root ignore file follows the scan mode (#1924).** In `standard`, a
  repository's regular `.gitleaksignore` is honoured. In `redteam`, an existing
  regular file is covered by a scanner-owned empty file mounted read-only at
  `/src/.gitleaksignore`; an absent file needs no mount. The staged file is 0644,
  its private directory stays 0700, and the target is unchanged. A symlink,
  other non-regular mountpoint, or staging failure leaves Gitleaks missing from
  coverage while other scanners continue. A produced Gitleaks scan records
  `ignore_files.gitleaks` as `honoured`, `neutralised`, or `absent` in the
  manifest, separately from inline `suppression_comments`; the gate discloses
  the same observed value. A scan that did not produce output makes no claim.

- **The SEC floor's catalog now names the build/CI surfaces that execute code
  (#1838, SEC-71240568).** Makefiles, setup.py, Terraform, second-tier CI
  systems, MSBuild project files, and lockfiles were live misses -- a target
  omitting SEC and a scout that never asks for it left those files unreviewed.
  The rejected-exclude disclosure now says whether the domain actually ran,
  instead of always claiming it "still runs".
- **A path or artifact this run did not create is not this run's evidence (#1841, run-14
  SEC-579863541 + SEC-3360368617).** `driver setup`'s two done-predicates were bare "does this file
  parse" tests on fixed `.panopticon/` paths a reviewed tree can plant or `git add -f`: a planted
  `setup-proposal.json` made the TARGET's own proposal the ingest's input, and a planted
  `setup-complete.json` satisfied BOTH, so the verb ran no phase and reported "setup complete" over
  a tree nothing classified. They now bind to THIS run with bindings that already existed -- the
  marker's own `run_id` (stamped by the writer, stable across resumes because `run_setup_flow` pins
  the setup manifest once) and git tracked-ness (`runio._manifest_committed`, the #1093 manifest
  guard's non-forgeable signal) -- and the refusal is reported once per invocation, naming the file
  and a remedy that can work. On the other side, `--pr` acquisition checked exactly one thing about
  its deterministic worktree leaf, `os.path.islink`: a pre-created real, EMPTY directory passed, and
  `git worktree add` populates one rather than refusing it, leaving the planter create and rename
  rights inside the tree under review. `acquire_pr` now refuses a leaf it did not make (a directory,
  `os.geteuid`-owned, writable by no one else, empty) before the fetch, creates the leaf itself in
  the statement before the add, and runs the same check on the reuse branch a resume takes. The
  guard is on ownership and group/other WRITE, not on every group/other bit: the tools image runs
  as `scanner` and mounts the review root — which under `--pr` IS that worktree — read-only, so
  traversal by another uid is required, and the leaf's parent must be sticky or private. The path
  stays deterministic, because `--pr` resumability depends on it — and `phases/setup.py` gave back
  the room under its 700-line ceiling before any of it: the #1737 unenforced-scan
  acknowledgement is now `phases/setup_ack.py`.
- **A heredoc handed to an interpreter is read as the script it is, or reported as unread (#1839,
  run-14 SEC-3915165799).** `scripts/workflow_guard.py` is CI's only enforcement of the #1529
  fetch-and-exec rule -- `tests/test_workflow_pins.py` runs it over every `run:` step in
  `.github/workflows/*.yml` -- and its standing requirement is to fail CLOSED: a shell form it
  cannot read is REPORTED, never accepted, and the accepted silent gaps are the list its docstring
  keeps. A script on an interpreter's STANDARD INPUT was in neither (`bash -s <<'EOF' … curl … | sh
  … EOF`, `sh <<'EOF'`, `python3 - <<'EOF'`): the reader filed the body under `Stage.heredoc`, and
  nothing above it asked whose script that body was, so a `curl … | sh` written inside one passed
  the gate clean. The split is the one the parse already knew, with no expansion model added. A
  QUOTED body reaches the interpreter as the text it was written as, so it is now READ -- in place
  and in order, exactly as an `eval '<script>'` string has been since #1697, which is what makes a
  step hardened inside its own heredoc come out hardened rather than unread. An EXPANDING body
  (`<<EOF`) is REPORTED unread instead of read, because its `$(...)` were lifted into the enclosing
  parse's table before that text was reached; so is a body handed to a language this guard has no
  grammar for (`python3 -`), which is the answer a `shell: python` step already gets. A heredoc that
  is a program's INPUT rather than its program is untouched (`bash x.sh <<'EOF'`, `sh -c '…'`, a
  `sha256sum -c` sums list), and so is the `<<<` here-string that is the only heredoc-ish
  construct the fleet writes. The two facts this needed were already parsed and are now carried:
  `shell_reader`'s `Stage.stdin_heredoc` (which body descriptor 0 finally reads and whether it
  expanded, copied in the same lexical redirect order as the output sinks) and
  `workflow_forms.stdin_program` (whether a command's program is its standard input at all, or a
  file, a `-c` string or a `-m` module). No step in the fleet writes the form today, so no check
  changes verdict: what changes is that the next one that does is read or reported, not waved
  through.
- **The rest of the configuration a scanned repository used to choose for the scanners (#1839,
  run-14 SEC-284952751 + SEC-1202454595).** #1924's scan-root class, split in two, because the two
  kinds of in-tree suppression are not the same claim. An ignore FILE the reviewed repository
  commits is scanner CONFIGURATION, and two more of them are now replaced with a scanner-owned one
  in BOTH security modes: trivy runs with `--ignorefile=/panopticon-config/.trivyignore` (a
  constant naming no advisory, staged the way bandit's ini is, in a read-only FILE mount of its
  own). That flag is BELT ONLY: the real-image round measured trivy 0.74.0 resolving the default
  `.trivyignore` against the WORKING DIRECTORY -- a per-launch scratch since #1877 -- so a
  scan-root `.trivyignore` was already not read on main either, and this closes nothing that was
  open. It pins the posture against a version that reads the scan root. And osv-scanner runs with
  `scan --config <its own scratch>/osv-scanner.toml`
  (an empty document; osv-scanner resolves `osv-scanner.toml` per DIRECTORY inside the scanned
  tree, so a committed `[[IgnoredVulns]]` list dropped the target's own advisories -- the one
  adapter of the four SEC-1202454595 named that #1742 left standing). Each file is staged per
  launch and fail-CLOSED: one that cannot be written skips that tool into the manifest's `missing`
  rather than taking the scanners queued behind it down with it. An inline suppression COMMENT is
  the other kind: it lives in the target's SOURCE, in the diff a reviewer reads. Under `--security
  redteam` the tree is untrusted and every scanner whose knob was verified against the pinned
  image stops honouring one (semgrep `--disable-nosem`, bandit `--ignore-nosec`, gitleaks
  `--ignore-gitleaks-allow`); under `standard` it STANDS, because `standard` is an operator
  scanning their own repository, who made a reviewed, in-diff decision. This repository's own CI
  (`security.yml` and the fork-PR `security-fork.yml`) scans in `redteam`, so nothing
  target-authored is honoured on either check. For semgrep the flag is BELT and the INGEST is the
  lever: at the 1.177.0 pin semgrep reports a `# nosemgrep`'d result either way, marked
  `"suppressions": [{"kind": "inSource"}]`, with and without `--disable-nosem`, so
  `sarif_to_findings` is what decides: it DROPS such a result under `standard` and counts it, and
  keeps it under `redteam`. The count is published per tool
  (`meta.coverage.adapters.<tool>.suppressed_in_source`, and on the gate's verdict line beside the
  excluded counts), and every ingest on both paths now carries the run's mode so no two of them
  disagree about which findings exist. It stands DISCLOSED: `tools-manifest.json` carries
  `suppression_comments` (`{"<tool>": "ignored" | "honoured" | "n/a"}`), one row per assessed tool,
  read off whatever decides it -- the argv the runner built for bandit and gitleaks, so taking a
  flag away changes the claim rather than leaving an intention behind, and the run's mode for
  semgrep, whose lever is the ingest and whose flag is belt; a tool with NO row was not assessed,
  which is not the same claim as
  `n/a`. Two residuals are disclosed there rather than guessed at on an argv -- gosec's `#nosec`
  and eslint-security's inline config, whose knobs were not verified at the pin, since a flag a
  scanner rejects is a tool that exits non-zero and writes no SARIF. A `.semgrepignore`
  committed at the scan root still narrows the scan in both modes with no flag to disable
  it at the pin (tracked on #2055). Gitleaks'
  allow-comment flag is appended by the adapter that builds its argv inside the container, so
  every adapter dispatch now names this run's mode as an explicit `--security <mode>` argv pair
  (not an environment variable, which a target's own hooks could set; an unrecognised token fails
  that tool closed).
  Bandit moves the other way in the same breath, by the owner ruling of 2026-09-25 on #1924: the
  bullet below pinned a scanner-owned ini in BOTH modes, which exceeded the ruling, so under
  `standard` a `.bandit` the scanned repository committed is pinned again (`--ini /src/.bandit`,
  explicit, so #run7's multiple-config ERROR stays bypassed) and honoured -- which takes the
  runner's own `-s B101,B404,B110,B112` off that argv, since bandit 1.9.4 exits 2 on a pinned ini
  whose `tests` key overlaps the CLI list and writes no SARIF at all (#1452's
  selected-but-unproduced class): their file chooses the checks. `redteam` keeps the scanner-owned
  ini and the `-s` list, and adds `--ignore-nosec`. `tools-manifest.json` says which of the two
  each run used, in `scanner_config` (`"target .bandit (its skips and tests)"` |
  `"scanner-owned"`). An operator sees: a
  `.trivyignore` or `osv-scanner.toml` committed to the scanned repository no longer decides what
  its own scan reports in either mode, their own `.bandit` is theirs again under `standard`, and
  `tools-manifest.json` says per scanner which config it ran under and whether the repository's own
  suppression comments were honoured. And CI scans in redteam, so the suite's two `shell=True`
  calls name the shell instead of carrying a `# nosec` (`tests/_test_helpers.py`,
  `tests/test_hook_command_quoting.py`: `/bin/sh -c` is what `shell=True` already ran).
- **This repository's own CI scans in `redteam` on both routes** (owner ruling 2026-09-26,
  #1839). Today the mode changes the virtualenv skip (off under `redteam`) and the
  gate's policy-C re-admission of name-suppressed findings; #1839's PR 5 adds the split that
  motivates the switch, where `standard` honours a target's own `.bandit`, `# nosec`,
  `# nosemgrep` and `gitleaks:allow` and `redteam` honours none of them. `standard` is an
  operator scanning their own repository; the fork-PR route (`security-fork.yml`, the required
  `fork-scan` check) scans a fork-authored tree, and the same-repo route (`security.yml`) must
  capture in the same mode because its captures are the baseline the next PR's gate diffs
  against and nothing records the mode. `--security redteam` is now on every scanner run,
  every gate call and the scheduled backstop snapshot (`security-backstop.py report
  --security`, new, so the snapshot counts the population the gate on the same step counts).
  Pinned per step in `tests/test_security_fork_workflow.py`. Measured on main through the
  tools image before the switch: the strict gate sees the same 29 HIGH under either mode and
  the first cross-mode delta run reports zero new.
- **The code-scanning upload now carries the gate's scope, and the bandit ini is a file mount.**
  #2117 stopped bandit honouring the reviewed repository's `.bandit`, which on this repository had
  kept it out of `tests/`; the next security run filed 476 test-suite idioms as open alerts and
  tripped the post-merge audit. `code_scanning_reports.py --exclude` (repeatable, the same
  gitignore-style globs `security_gate.py` takes, matched by the same `groups_schema.matched_glob`)
  drops those results from the Security SARIF only -- the gate still sees `tests/`, no AI
  inventory result is dropped -- and the excluded count is printed and written into the step
  summary.
  The scanner-owned bandit ini is bind-mounted as a FILE (0644) from a scratch directory that keeps
  `mkdtemp`'s 0700: the `chmod 0755` that made the directory traversable for the image's `scanner`
  user is gone, along with the two alerts it earned.
- **Tool and target text is inert wherever it is rendered -- so a scanned repository cannot steer
  the operator's terminal (#1829: SEC-4277410777, SEC-798292895, SEC-2200312865; closes #2069, the
  residual of #1752).** Three surfaces printed strings a target or its scanner wrote, with the
  control bytes still live: the terminal summary's Top-findings line, group line, target path,
  cross-domain note and target-config line; the `target-discovery-surface` probe's `detail` and
  its stderr disclosure; and the stored finding's `title`, `category`, `location.file`, `impact`,
  `remediation` and tool `rule_id`. A crafted SARIF message or a committed filename could
  therefore clear the screen (`\x1b[2J`), overwrite the line just printed (`\r`) and reprint it as
  `driver: all clear` -- `sarif_to_findings` only collapsed WHITESPACE, and the run-9 escape
  covered two fields on the other builder. One neutralizer now lives in `tools/base.inert_text`
  and runs at the normalization boundary -- both finding builders and `normalize_finding`, so
  every renderer inherits it -- with belt-and-braces calls for the target path, the group name,
  the agent-authored cross-domain note and the target's own config values, which normalization
  does not own. What an operator sees changes: a control byte reads as `\x1b` rather than acting,
  over-long target text is cut with a marked ellipsis (never mid-escape), and an ordinary
  multi-line tool message still renders as one line; a PATH is escaped and bounded and otherwise
  kept byte-for-byte, so a real `src/a  b.py` still resolves on disk. The JSON artifact was
  already escaped on disk; what is new is that the STORED strings are inert too, so anything that
  prints a field raw is safe as well.
- **A file the reviewed repository commits no longer chooses what the scanners look at (#1839,
  run-14 SEC-1486247143 + SEC-752508850).** Three levers, all on the path CI's merge gate runs
  (`run_tools.py` -> `security_gate.py`, which has no agentic axis to compensate). A single
  committed `src/pyvenv.cfg` was enough for the runner to hand `src/` to semgrep's `--exclude`,
  trivy's `--skip-dirs` and bandit's `--exclude` in BOTH security modes, untallied: a directory is
  now flagged on the marker only when it also has the SHAPE of an installed environment (an
  interpreter under `bin/`/`Scripts/`, or `lib/python*/site-packages`), and a bare marker beside
  real source is reported as `pyvenv.cfg-without-shape`, walked into, and never skipped. The INGEST
  half of that same lever is closed with it, which is the half the driver's own report reads:
  `ingest_tools` dropped every finding under a marker directory at ANY depth in both modes and said
  nothing at all, so the planted `src/pyvenv.cfg` emptied the report of `src/` even where the scan
  had looked. One predicate now answers for both stages (`run_tools.has_venv_shape`), so a bare
  marker prunes nothing at ingest either; and where a real virtualenv is still pruned there, the
  drop travels the disclosed channel under a `pyvenv.cfg:<dir>` key of the new
  `virtualenv-by-marker` class -- named per directory, counted in `meta.coverage.tools_suppressed`,
  and re-admitted to a `--security redteam` gate when the finding is CRITICAL or secret-class,
  exactly as #1740 does for a directory NAME. An operator's own `--exclude` glob outranks it. A
  directory literally named `*` became `--exclude=*` / `--skip-dirs=*` -- both flags take GLOB
  PATTERNS, so one `mkdir` took the whole tree out of two scanners; a path with any component
  outside `[A-Za-z0-9._-]` is never passed to an exclusion knob, and its manifest row says
  `skipped: false` with a `note` saying why. Under `--security redteam` NO virtualenv now reaches an
  exclusion knob (#1740 ruled
  that for a directory NAME; a file the same target wrote is more attacker-controlled than a name),
  and under `standard` the #1638 P09 walk saving stands but stops being silent: the skipped
  directories are counted as DIRECTORIES under `virtualenv-by-marker` AND `virtualenv-by-name` in
  `meta.coverage.tools_suppressed` -- the name-only skip a bare `mkdir .venv` buys is tallied too,
  because it also produced no finding for anything downstream to disclose -- named on the gate's
  verdict line (`3 directories removed from the scan as virtualenv-by-marker ('.venv', 'env');
  virtualenv-by-name ('venv') -- re-run with --security redteam to scan them`, with every
  target-authored name escaped and the list capped at ten), and on the manifest rows. Redteam trades
  the #1638 P09 walk saving for that re-admission: all three scanners walk `site-packages` in full,
  which is wall-clock and tool-timeout cost rather than report noise (the ingest still drops those
  findings and hands back only the CRITICAL and secret-class ones), and the only knob for it is
  `--exclude '**/.venv/**'` -- gate POLICY, which takes those paths out of scope in every mode and
  is never re-admitted, not a shorter walk. Third, bandit no longer runs with `--ini /src/.bandit`:
  the target's own config set bandit's `exclude`, `tests` and `skips`, so a committed `tests = B999`
  reduced the merge gate's Python SAST to one check. It gets a SCANNER-OWNED ini instead --
  generated per run into a scratch directory, bind-mounted read-only, pinned unconditionally (so
  #run7's multiple-`.bandit` ERROR is bypassed whether or not the target ships one), and carrying a
  CONSTANT text: bandit's own parser defaults plus `.worktrees`, no `tests`/`skips` key, and no
  target-derived string of any kind, since its one job is to pre-empt bandit's `.bandit` discovery.
  This run's virtualenvs ride on the CLI instead, as attached `--exclude=` values, each path
  component checked against an allowlist (`[A-Za-z0-9._-]`, no leading `-`) so a name holding a
  comma, a brace or a newline is scanned and NAMED rather than expressed. This is the first
  increment of #1924's scan-root half. An operator sees: a `pyvenv.cfg` planted on source no longer
  removes it from a scan, a gate verdict line that names every virtualenv the scan skipped, by
  marker or by name, a report that carries a `virtualenv-by-marker` count where the tool axis used
  to go quiet, and bandit reporting the checks panopticon selected rather than the ones the target
  left it.
- **Deleting a run's own integrity evidence is reported, not repaired -- so a substitution
  survives the `rm` that used to launder it (#1832, SEC-377944137).** #1208 made an owed-but-absent
  `out-file-hashes.json` fail closed, because deleting that baseline had been the cheapest way to
  erase evidence of a findings substitution. It did not hold on a live `driver run`: the synthesize
  phase opens by calling both artifact writers, and each re-armed the moment its file went away, so
  the snapshot was simply re-taken OVER THE SUBSTITUTED BYTES -- the tampered findings file became
  its own baseline, `content_mismatched_files` went empty, and the plan was re-created so its
  deletion left no trace either. One file up, absence also still read as "not measured": every check
  keyed on `dispatch-plan-driver.json` treats a missing plan as owing nothing (`_owes_a_snapshot`
  returns False, so #1208's guard goes quiet; the planned-vs-ingested reconciliation returns
  `([], [])` by design; `duplicate_out_files` sees nothing; and `empty_dispatch_plans` counts empty
  LISTS, of which there are none when there are no plan FILES), while `plans_seen` -- the one key
  that noticed -- was not in `integrity_ok`.
  Both artifacts are now OWED ONCE: their writers stamp the run manifest as they write
  (`driver_plan` carries the plan's canonical content hash, `out_file_snapshot` the cell count), the
  stamps are MONOTONE, and a stamped artifact that is gone is never re-created -- the driver says so
  on its own stderr, naming `--reset` for a run folder that was cleared on purpose. Synthesis then
  reports `meta.integrity.dispatch_plan_missing` for a deleted plan and `dispatch_plan_mismatched`
  for one that is present but is not the plan this run wrote (replacing it is the same erasure and
  cheaper: a narrower plan declares fewer cells), both failing the gate closed beside their #1208
  sibling. The manifest is the anchor because a plan cannot attest to its own existence and the
  manifest is the better-defended file (#1727) -- and a durable stamp rather than the rolling
  dispatch-request slot, which read `verify` on any run that verified anything, could be rolled
  BACKWARD to `scout` by the same tamper it was meant to notice, and could not tell a tool-advisor
  verify dispatch from a review one. A run that never wrote a plan -- a direct `synthesize.py` call
  over hand-collected findings, a target with no declared cells, a run resumed across this upgrade
  -- stamps nothing, keeps the benign reading every other key here has, and still gets the #5.0-16
  first-snapshot fallback when its verify phase was vacuously done. **A run already IN FLIGHT across
  this change should be `--reset`, not resumed:** with nothing stamped, its first snapshot is taken
  over whatever bytes are on disk at that moment, so a substitution made before it still reads clean
  -- the one window the old laundering survives in. The obligation is never inferred from the
  findings files present, which the same writer could arrange.
- **A target-committed write allowlist can no longer hand a reviewer a peer cell's findings file
  (#1831, SEC-611772336).** `write_guard_hook.install` carries a still-live grant forward so that a
  re-arm never revokes a concurrent fan-out (#11), but the filter deciding what MAY be carried
  anchored on the `.panopticon` segment and checked a prefix only -- so every path under the whole
  artifact tree qualified. Entry ids are `review-<group>-<domain>` and the target authors
  `panopticon.yml`, so a `.panopticon/write-allowlist.json` committed in the scanned repo and keyed
  with a REAL reviewer id added a PEER cell's `findings-<group>-<domain>.json`, the run's
  `out-file-hashes.json` integrity snapshot and `dispatch-plan-driver.json` to that reviewer's own
  grant: the per-entry confinement #1571 exists to establish, re-opened through the one path that
  fix did not close, on every self-scan and every calibration run started inside the clone. A
  carried path is now kept only when it is EXACTLY the artifact its own entry id declares, in one of
  the RUN FOLDERS (`.panopticon/runs/<tag>/`) this install writes into. The path is DERIVED from the
  id rather than matched against its name -- `review-<cell>` may hold `findings-<cell>.json` and
  nothing else, `verify-<cell>-<stage>` its `verdicts/verdicts-<cell>.json`, `verify-tool-<queue>`
  its `verdicts/<queue>.json`, and `scout-<group>` its `scout-<group>.json` -- so a real reviewer id
  carries that reviewer's own out_file and no peer's, even where one group's name ends with
  another's (`Core` and `X-Core`), and a previous round's tag is not in flight. Deriving per family
  is also what keeps #11: a verify or scout arm carries a concurrent fan-out's grant as readily as a
  review arm does. Everything else is dropped, and the operator is told on one stderr line, counts
  first, with each entry id bounded and quoted (`write guard: dropped 5 carried allowlist path(s) in
  1 entry(ies) -- not this run's folder, or not the artifact that entry itself declares:
  'review-Core-SEC' (5)`) -- a grant narrowed in silence is the #calibration-4 shape, every later
  write denied and nothing pointing at the allowlist, and an id out of a planted file is
  target-authored text that may not forge a line of the guard's own output.
- **A torn retry-budget ledger no longer refunds every attempt the run spent (#1809,
  DAT-3555180994).** Four retry ledgers -- `cell-attempts.json`, `verify-attempts.json`,
  `scout-attempts.json`, `discovery-attempts.json` -- were read at six sites (persist's give-back
  path among them), and every one resolved "absent" and "present but unreadable" to the same empty
  dict, so a file torn by an interrupted write read as a fresh run: a cell that had spent
  `MAX_CELL_ATTEMPTS` became dispatchable again and the count restarted at 1, discovery's "one free
  re-run and no more" stopped bounding anything, and each refund was paid for in launches. One
  reader now draws #run9 COD-B1A's line for all six (`runio._load_state_json`, the rule
  `file_issues.load_ledger` already applies one directory away): `{}` only when the file is ABSENT
  -- a legitimate first run -- and a `DriverError` naming the path and `--reset` for everything
  else, a dangling symlink (`lexists`) and a deeply nested document (`RecursionError`, previously a
  bare traceback) included. `driver run` turns that into an `error` status naming the file from
  every site: the terminal `exhausted_cells` call reads the same ledger and sat outside every `try`,
  so that block speaks the status protocol now too. The remedy the message names is real:
  `verify-attempts.json` and `discovery-attempts.json` join `cell-attempts.json` in the legacy flat
  sweep's `_RESET_GLOBS` (`scout-*.json` already covered the fourth), and a live run's whole folder
  goes. Fail closed rather than fail-quiet -- a false refusal costs one `--reset`, a silent refund
  costs launches and invalidates the run's own bound.
- **The clean-tree baseline is written atomically, and an unusable one is classified instead of
  blamed on the v1 upgrade (#1809, DAT-4027033499).** `tree-baseline.txt` was the one artifact
  writer in `phases/` that truncated in place, and it sits behind an exists-means-done guard that
  must NOT re-probe `git status` on resume (re-probing would baseline the reviewer's own writes as
  clean). A write torn mid-way was therefore PERMANENT: every later resume accepted the partial
  document, the run failed closed at validate forever, and `--reset` -- throwing a paid run away --
  was the only exit. Both baseline writes (the snapshot and the probe-failure sentinel) now confine
  the final name, then stage `<baseline>.tmp` through the same `_open_w_nofollow` and `os.replace`
  it into place -- `runio._write_json`'s shape AND order, byte content and file mode unchanged --
  and on failure remove only the staging file this call opened, or a symlink planted at its name,
  never a file it never opened (with `.panopticon/runs` force-committed as a symlink, that name
  resolves outside the tree). An interrupted process therefore leaves the last complete baseline or
  the new one; nothing here fsyncs, so a power loss can still tear the file, which is what the
  classifier below is for. **Operator-visible:** a present-but-unusable baseline now says which kind
  it is -- CORRUPT for anything that cannot be a porcelain record (a first byte outside the XY
  status set, or JSON that parses to something that is not an object); EMPTY for a 0-byte or
  whitespace-only one (a torn write, or a v1 baseline of a clean tree) -- and both name `--reset`
  as the remedy and deleting `tree-baseline.txt` as the non-remedy it is (the next capture would
  re-baseline the reviewer's own writes as clean). All of them used to read "predates content
  digests (schema v1)": a resume across an upgrade that never happened, with no remedy named -- and
  0 bytes is the likeliest shape the old writer's torn write left behind. A genuine v1 baseline (raw
  porcelain, which always opens with an XY status byte) still reads as v1, a deeply nested one fails
  closed here instead of ending the invocation with a `RecursionError` traceback, and `--reset` now
  also sweeps a staging file orphaned by a SIGKILL. Staging opens
  without `O_EXCL` project-wide (#2093) and an `OSError` from this write still reaches the operator
  as a traceback rather than a status (#2094) -- follow-ups, not fixed here.
- **A catalog gap with no file location is disclosed, not dropped (#1807, DAT-2501524861).** The X0X
  emitter drops a candidate cluster when no finding in it carries a `location.file`, because the
  schema requires a `file` on every occurrence — and a locus-free finding is the CANONICAL shape for
  a repo-wide catalog gap, which `synth/findings.py` produces deliberately (#1522 COD-D1B pops the
  empty location rather than quarantine the finding). So the emitter whose whole purpose is to carry
  catalog gaps into OCRDb's adjudication pool was discarding exactly the repo-wide ones, in silence,
  and `synthesize`'s `X0X artifact: <path> (N candidates)` line printed a count that was quietly
  short. Nothing is invented — a file cannot be. The count the report had to leave out is now
  published as `candidates_dropped_locus_free` (omitted when zero), an optional integer DECLARED in
  `skill/reference/x0x-report-schema.json` so a downstream ingester has a documented field to read;
  that key is the carrier that survives a `driver run`, because the driver keeps a child's output
  only on failure. Run `synthesize.py` yourself and each dropped cluster is named on stderr too —
  the domain, the lead title or, untitled, its finding id, and how many findings the cluster held —
  with the count appended to the `X0X artifact:` line. Every agent-authored field in either
  diagnostic is squeezed to one line, bounded with the cut MARKED, and rendered inert with `%r`, so
  one hostile finding cannot repaint the operator's terminal or forge a line that reads as the
  tool's own honest output. `strain_report.advisor_recode_signals` — the offline catalog-MIS-FIT
  companion, which has no pipeline caller — makes the same disclosure at its own locus-free drop;
  `cross_run_signals`'s line-window join is left alone, being intrinsically file-keyed. Residual,
  filed as #2090: a MIXED cluster still reaches the pool with its locus-free member absent from
  `recurrence`, silently.
- **A run3 that never reviewed the file can no longer corroborate a "fixed" close (#1807,
  DAT-1268532600).** Stage 1 (`skill/scripts/reconcile.py diff`) read "no run3 record on this (file,
  panel)" as evidence of a fix, and its two whole-run guards only fired when run3 was EMPTY or
  shared no path at all with run2 -- so a NARROWER re-run (`--scope-file a.py`, one directory, one
  group, a PR diff) overlaps on a single path, defeats both, and every still-unfixed finding on the
  files it never opened landed in the `closed` cohort, which `scripts/reconcile_apply.py apply
  --confirm-close` turns into a real GitHub close commented "**Reconciliation: fixed (area
  clear).**". That `(file, panel)`-clear read is now gated on ONE further thing, and only that
  thing: run3's own claim to have reviewed the file -- `groups[].files`, merged across the report
  and every part. Nothing stands in for the claim, a record on the file included: a record proves
  some scanner or cell read the path, not that the (file, panel) whose silence is read as a fix was
  reviewed. So the diff refuses three ways: a finding on a file run3 does not list goes to
  `ambiguous` (kept open), reading "<file> was not reviewed in run3 -- absence of findings is not a
  fix", or, when run3 does carry a record on that path, "run3 produced records on <file> but its
  report does not list it among the files it reviewed (groups[].files)" -- an under-stated
  `groups[].files` is a report-side bug, named rather than trusted; a run3 whose report states no
  files at all guards the whole run (`run3_files_unstated`); and a run3 whose report does not
  declare `meta.review_type: "repo"` -- a scoped review, an absent, empty or unreadable value, or a
  part contradicting it -- guards it too (`run3_not_repo_wide`). Missing information fails CLOSED,
  with no flag to opt back into the old reading. Stage 2 words every one of those refusals as
  "**Reconciliation: not corroborated.**", where it used to claim the area was still active and the
  finding probably re-worded -- which for a zero-record or path-drifted run3 was simply false.
  **Operator-visible:** a close now needs a repo-wide run3 that says what it looked at, and the
  summary names an active guard once on its own `guard:` line instead of only repeating it per
  finding; a run3 that is merely NARROWER by file list still closes the findings on the files it
  does list. Still open as follow-ups: #2084 -- a run3 that declared itself repo-wide but LOST cells
  (`meta.coverage.cells.missing_floor` non-empty, `summary.coverage_certified` false) still lists
  every file in `groups`, so it can corroborate closes on files no review cell actually reached; and
  #2087 -- the claim is per FILE and per RUN while the silence read as a fix is per `(file, panel)`,
  so a panel or tool axis that never ran on a listed file still reads as clear.
- **Three run-artifact readers in `synth/` no longer end a run on a file a target can pre-commit
  (#1811, #1812 — DAT-2808086775, DAT-3713947858, DAT-1553408299).** `coverage-*.json`,
  `dispatch-plan-driver.json` and the agent findings files are read back out of the run folder,
  which on the agentic path is globbed out of the SCANNED repository — and all three readers
  announced a "tolerant: never abort a run" contract their guards were narrower than. A deeply
  nested document raised `RecursionError` (a `RuntimeError`, so outside
  `except (OSError, ValueError)`) in every one of them, and nothing bounded the coverage read at
  all; a scalar dispatch plan (`5`, `true`, `null`, `1.5`) raised `TypeError` on the iteration that
  counts review cells; and the out-of-scope counter re-read the findings files with neither the
  parser nor the shape repair the canonical loader uses, so a fence-wrapped file — the shape run-9
  saw from 94 of 95 tool advisors — silently disclosed ZERO out-of-lane findings while the report
  ingested them, and a mistyped `location` (string, list, number) or a non-list `findings` raised
  out of `PlanInputs.load`. That second read now goes through `evidence.load_json_tolerant` and
  `normalize_finding`, the same two the first read uses, so these two readers of the same files
  cannot disagree about what the file IS or about what a row means. **Operator-visible:** a report
  that used to be lost after every dispatch had already been paid for is produced instead — the
  coverage file skipped and NAMED on stderr (its READ bounded to 1 MiB, so a symlink to a bigger
  file or to a character device is bounded too, not just one whose declared size is honest), the
  plan counted as 0 review cells and said so, the fence-wrapped file's out-of-lane findings
  actually counted, and one unusable finding row costing nothing but itself. Scope: these three
  readers. Sibling readers in `synth/plan.py`, `synth/cost.py` (`usage.json`) and
  `synth/integrity.py` still catch only `(OSError, ValueError)` (#2081), a skipped coverage record
  still fails OPEN on the floor audit rather than recording itself in `meta.integrity` (#2080), and
  a FIFO named like an artifact still blocks at `open()` (#2082) — follow-ups, not fixed here.
- **`--max-budget-usd` is re-read after every entry, not once per checkpoint (#1760,
  AGT-4265600920).** The cap was compared with the ledger exactly once per loop iteration, at the
  top and ahead of arming — and a checkpoint is ONE batch, so a whole review round (every pending
  cell, each charged at dispatch) launched before the cap was looked at a second time, where the
  guide promises launching stops once the ledger's cumulative reported cost crosses it. It is now
  the batch's THIRD stop rule, beside the host-outage and identical-launch-failure ones (#1721,
  #1732): the queue is cancelled the moment the ledger reaches the cap, whatever is already in
  flight drains, persists and is charged as usual, and the run still ends on the same terminal
  `--max-budget-usd X reached` error one iteration later, off the same gate and the same ledger. So
  the overshoot falls from the whole checkpoint to the pool — up to `--concurrency` launches
  already in flight, plus the one worker that can turn over while the loop is still ledgering the
  result that reached the cap, which is the bound an outage has. The predicate fails CLOSED on a
  ledger line whose cost cannot be read as money, because `iter_batch` reads a `stop` that raises
  as "carry on" — #1648's fail-open one level down. **Operator-visible:** the batch's stderr line
  names the rule that stopped it as `the --max-budget-usd cap`, where a cap used to be rendered as
  "0 host-class failure(s)" — a host to go and wait out.
- **Two prompt boundaries now bound the untrusted text they quote (#1752,
  AGT-1863884584 and AGT-2822331063).** A retry prompt quotes the rejected
  record's `attempt`, and the tool-aware review map quotes each tool hit's path,
  rule id and title. Both are written by something outside the run — the record
  is a file, and for `driver setup` it is a file at a FIXED path in the flat
  `.panopticon/` (`rejected/setup-scan-1.json`) that a target repo can commit;
  the hits come from scanner output, and `.panopticon/tools/*.sarif` is another
  path a target can commit — and both were interpolated with no type and no
  bound, beside neighbours that had one (`reason` at `REASON_CAP`, the 40-line
  `_TOOL_HITS_CAP`). A planted `attempt` put 10 kB of prose into the prompt, into
  `prompt_file`, and into the entry's `prior_rejection` stamp, which is hashed
  into the dispatch request; one hostile hit put 20 kB into a review prompt under
  "verified independently … do **not** re-file them", and forty put ~760 kB.
  `attempt` is now an int in `1..ATTEMPT_CAP` (99) or nothing at all — the block
  then reads "Your previous attempt was refused", with no number, because an
  unusable field must not be paraphrased into a claim about the run — and
  `prior_rejection` carries that same sanitized value, so the prompt and the
  request cannot disagree. The map's three untrusted columns go through one
  helper at the rendering boundary: `runio._prompt_safe`, whitespace collapse,
  and a per-column cap (200 / 120 / 200) whose cut is MARKED with `…`, so a
  truncated line cannot read as a complete one, and an empty column reads `?`.
  **Residual, filed separately:** the generic SARIF path still leaves control
  bytes in the ARTIFACT's `title`/`rule_id`/`category` (this fix cleans the
  prompt, not the normalization contract; #2069), and `.panopticon/tools/*.sarif`
  is still ingested with no run binding (#2070).
- **The guide now says where the second witness is spent (#1759, AGT-1456823651 /
  AGT-381210818).** A REJECTED advisor verdict was always settled by one advisor — the
  adversarial backup round is summoned only for primary-CONFIRMED findings in categories at or
  above `score_gate.BACKUP_FLOOR`, and the tool axis has no backup round at all — but the
  evidence chapter never stated the asymmetry or why it is deliberate. It does now, beside the
  sentence that says rejected claims keep their full advisor prose in `discarded_claims`.
- **A batch record names its MACHINE, and one record can be discarded without
  the run (#1912).** The owner stamp that `driver loop` recovers a crashed batch
  from carried the pid and `socket.gethostname()`, and a hostname is not a machine
  identity: on macOS the same laptop answers `mac.local`, `mac.lan` or a
  DHCP-assigned name depending on the network it woke up on, so a crash and the
  resume after it saw two different names — the resume read its own record as
  another machine's and offered `--reset`, the whole run of paid cells, as the
  only way forward. The record now carries a hardware machine id
  (`uuid.getnode()`, absent when that function falls back to its random
  multicast value) beside the hostname, and either id matching means this
  machine; a record from before the field, or one whose field is unusable, is
  judged by its hostname exactly as before. Comparing the first DNS label is
  deliberately NOT done — this repo lives on a mounted volume, so `mac.office`
  and `mac.home` really can be two machines sharing one run folder.
  **Operator-visible:** `driver loop --discard-batch N` is a new, narrow remedy
  for the two refusals that mean "the liveness question could not be answered"
  (another machine / no owner stamp). After confirming no other loop is working
  on the folder, it gives record `batch-N.json` exactly the rollback a dead
  owner's gets — artifacts deleted, entries ledgered as cancelled/rolled back,
  attempts refunded, record unlinked — and the invocation carries on with the
  rest of the run. It applies to that one number: a live owner still refuses (no
  flag can help), a dead one needs no acceptance, a second unreadable record
  still refuses, and an absent one is an error naming the folder. Both refusals
  now name `--discard-batch N` first and `--reset` second, the acceptance is
  recorded in `discarded-batches.json` in the run folder (with the owner stamp as
  found) and counted on the run manifest, and `--discard-batch` with `--reset` is
  refused as contradictory.
- **An unenforced claude launch now denies the tools a reviewer must not hold
  (#1753, AGT-4053314873).** An `--agent` launch lands in a registered shell
  whose `tools:` frontmatter the host enforces; the `--model` fall-through
  binds no shell, and `--setting-sources user` deliberately keeps the
  OPERATOR's user-scope `permissions.allow` — so a `Bash(*)` convenience rule
  in the operator's own settings reached a reviewer whose job is reading
  hostile content. That argv now carries
  `runners/claude.UNENFORCED_DENIED_TOOLS` — 24 names, grouped by what each
  would hand a reviewer: code execution, delegation, egress and off-machine
  publication, the write tools no reviewer role is granted, and the two
  read tools its `Read|Grep|Glob` matcher never sees — and deny rules beat
  allow rules, which is the point. **Measured on 2.1.276, and the reason for
  the `=` form:** `--disallowedTools` is VARIADIC, so the space form eats every
  following non-flag token including the prompt — `claude -p --output-format
  json --max-turns 2 --disallowedTools Bash "<prompt>"` exits 1 with no
  envelope and "Input must be provided either through stdin or as a prompt
  argument" — while `--disallowedTools=Bash,Glob "<prompt>"` runs and the
  reviewer reports "I have Read available; Bash and Glob are not in my current
  tool set". One token cannot swallow a neighbour, wherever it is placed. The
  ENFORCED argv is byte-identical to before: it is measured behaviour and its
  shell is already the control. **Residual:** a tool name this list has not
  heard of that the operator has allowed at user scope — a CLI upgrade is how
  one arrives. MCP tools are not part of it, since the same argv passes
  `--strict-mcp-config` with no `--mcp-config`.
- **`driver setup` refuses an unenforceable setup-scan (#1737, AGT-B1D).** The
  one dispatch that reads the whole untrusted tree was the only role with no
  registered shell: its tool grant was whatever the host hands a
  general-purpose agent, and the template's `Read, Grep, Glob` travelled as
  advisory prose in the brief. `setup_scan` is a driver role now, so
  `--emit-host-agents` writes `panopticon-setup-scan` for every host that
  registers shells (tools `Read, Grep, Glob`; **no bound model** — the
  session's own model runs the classification, R-F4-2), `registered-shell-tools`
  proves it grants no Bash, and the `scan` checkpoint dispatches that shell and
  only that one. `enforced` is derived from this invocation's measured posture
  like every other dispatch, and both entrypoints — `driver setup` as much as
  `driver loop --setup` — probe the host for themselves before the gate reads
  the evidence. **Operator-visible:** on a machine that has not registered its
  shells, `driver setup` now stops and names two remedies —
  `python3 skill/scripts/dispatch.py --emit-host-agents <host>` (the fix) or
  `--allow-unenforced` (the acceptance, recorded in
  `.panopticon/setup-unenforced-ack.json` and discarded once the posture
  proves enforcement). Registering the shells is a one-time step; until it is
  done `tool_policy_enforced` reads REFUTED for review runs too, which is the
  registry honestly reporting itself incomplete. The refusal names the remedy
  that can actually change the answer: emitting shells where the capability is
  REFUTED, and `driver loop --setup --host <h> --mode headless` where nothing
  measured it at all — on Codex that is the ONLY invocation that can, since its
  tool-policy probe needs a headless settings path and `driver setup` has no
  `--mode`. Probing costs no paid turn and, Kimi's `kimi --version` and `kimi doctor` reads aside,
  launches no host CLI at all: everything `driver setup` measures is a
  filesystem read.
- **`usage_ledger` follows the mode.** The probe is now `usage-source` (was
  `transcript-dir`): in headless mode it measures the launch envelope path —
  a run folder that can hold `dispatch-ledger.jsonl`, the host CLI on PATH,
  that CLI's `--help` advertising the runner's own `ENVELOPE_FLAGS` (`-p`,
  `--output-format`; an executable merely named `claude` is refuted), and,
  once launches are ledgered, their envelopes having carried usage — and never
  consults transcripts; in session mode it measures the session's transcript
  directory exactly as before. A headless run launched from any directory
  without transcripts (every fresh target) used to be *refuted* while its
  ledger was exact. The `--help` interrogation goes through the runner's own
  launcher, the seam the suite refuses real launches at.
  `runners.base.LEDGER_FILE` is the one owner of the ledger's name (the
  `Ledger` and `usage.json`'s `source` both read it); the remedy line names
  both modes' fixes.
- **`driver loop --reset` resets once.** The flag reached `driver.run` on every
  iteration, so each one cleared the run folder and re-minted the manifest and
  the loop re-launched its first checkpoint until `--max-iterations` (this
  branch's second real run: the same three scouts ten times). The first call
  consumes it.
- **`prompt_file` is granted to the entry's read scope.** The guide let a host
  point an agent at `prompt_file` (marker line first, pointer second), but every
  entry's `scope.reads` was empty, so the read guard denied the agent its own
  prompt. Stamping the file now grants it through `reads`.
- **The SEC cell may read the checklist its prompt points at.** The first real
  headless run's ledger recorded the SEC reviewer's Read of
  `skill/reference/security-checklists.md` as a denial: the prompt named the
  file, the scope did not. `review._cell_reads` grants it through `reads`,
  from the one path the pointer is rendered from.
- **Session-mode dispatch on Claude Code is templated.** `skill/workflows/dispatch.js`
  runs one workflow subagent per pending entry — inside its registered shell
  when the entry is enforced, on the entry's model otherwise — marker line
  first, and returns replies keyed by id, a skipped or dead subagent under
  `missing`; SKILL.md mandates it over one-off Agent calls. The read-guard
  probe's round trip now also binds a fake subagent through the Workflow
  transcript layout (16 rows).
- **The suite refuses the real `claude` binary by default.**
  `runners.claude.DEFAULT_RUNNER` is read at construction and `tests/conftest.py`
  swaps it for a refusal on every test (was per-test discipline; #1616); only a
  launcher a test injects explicitly runs, and none injects the real one. The
  same file now also points `HOME` at one throwaway directory for the whole
  process, before the registry expands `~`, so no probe or test reads the
  operator's real `~/.claude`.
- **`Glob`'s pattern is adjudicated (#1917).** Both read guards decided a
  `Glob` on its `path` alone, and the pattern is a PATH pattern expanded
  against it, so `Glob(path=<granted dir>, pattern="../Src/*")` could name
  entries outside the `dirs` grant — names, not content, since a following
  `Read` still meets the per-file rule, but it was the one read primitive whose
  second argument nothing looked at. Over a granted directory a pattern that is
  absent, empty, non-string, absolute, `~`-rooted or holds a `..` segment is now
  denied. `Grep`'s pattern is a regex over content and stays unadjudicated.
- **In-tree hard links keep their directory `Grep` (#1917).** The walk behind a
  directory read grant recorded every regular file with `st_nlink > 1`, so a
  `cp -al` fixture or a pnpm store — whose links all sit inside the review
  root, naming content the grant already covers — denied every directory
  `Grep`/`Glob` above it for nothing. It now counts the in-tree names of each
  inode and records a file only when its link count EXCEEDS them. A `git clone
  --local` target is deliberately NOT cleared: its links name the source
  repository's objects, it still overflows the cap and still loses its
  directory `Grep`, with `--no-hardlinks` named on stderr as the remedy.
  **Operator-visible:** the walk is now always complete (the count is only
  known at the end), so `CAP` bounds the findings rather than the files walked.
- **`read-guard-armed` measures the planted hard link (#1917).** The Claude
  readiness probe now does what the Codex one has done since #1642: it plants a
  hard link inside a directory grant naming a file outside it, records it with
  the driver's own walker, and requires the directory `Grep` to be refused **by
  the hard-link rule** rather than merely denied. A volume that cannot plant a
  link — or that plants one and then reports `st_nlink=1`, as some FUSE and
  network mounts do — makes that sub-check `unknown` instead of refuting a
  healthy host.
- **The guide is an index plus one chapter per section.**
  `skill/docs/PANOPTICON.md` keeps Overview, Required sub-skills, Modes and
  Global flags plus a Contents list; each H2 lives in `skill/docs/guide/`
  (`docs/guide` is symlinked onto it), wrapped at 100 columns with no prose
  changed. `driver readiness`'s `guide` row is true only when every chapter
  file is present (`hosts.guide_documents()`), and its remedy names the
  missing ones.

## Unreleased — 5.2 grouping engine, plan 1

Setup now front-loads the grouping work so every later run reuses it
(spec: panopticon-docs `superpowers/specs/2026-09-06-panopticon-5.2-grouping-engine-design.md`).

- **Catalogs, full prose:** the capability roster grows from the R1 13 to 45
  entries harvested from the 5.2.0 vocab panel (>= 10 repos each), every entry
  carrying `definition`/`boundary`/`aliases`/`examples`; a 9-entry **layer**
  catalog (`layer_vocabulary.yml`) for splitting one oversize vertical; a
  `tests_catalog.yml` for the test-tree seeds. Both catalogs render into the
  setup-scan brief in full — the calibrated prose finally reaches the
  classifier (#1500). Proposed labels normalize through aliases. The reserved
  names `Tests`, `Commons`, `Ungrouped` and `Core` may not be catalog entries,
  aliases, or proposed layers; a proposal may name a `Tests` group (a committed
  `Tests` suppresses the run-time sweep) but not `Commons` or `Ungrouped`,
  which the engine mints.
- **Proposal v2:** per group, optional `layers` (`{layer, match}`) and a
  `profile` (`purpose`, `surfaces`, `entry_points`, `trust_boundaries`);
  `custom:` groups and catalog entries without an affinity row get their
  review floor from the profile's surfaces (#1490 for setup-time groups).
- **Size policy (stage 3)** — superseded by #1681, which moved both keys out of
  `.panopticon/config.json` and under `settings:` in the root `panopticon.yml`:
  cap = `--max-per-group` > `config.json
  max_per_group` > 48; ceiling = `--max-groups` > `config.json max_groups` >
  `max(4, 2 * ceil(code_files / cap))`. A layer under 6 files merges back, a
  vertical over the cap splits by its layers (residual `Core`), over the
  ceiling the smallest layers collapse first, verticals are never merged.
  Committed groups always win; the outcome is written to `setup-report.md`
  / `setup-report.json`.
- **Setup engine fixes (from the first 5.2 self-scan, run-11):** the ceiling
  budgets CODE leaves only — `Tests` and the Commons categories hold exactly
  the files its numerator subtracts, so charging them to it made any repo of
  <= 96 code files with two verticals "over ceiling" by construction and told
  the owner to merge verticals (#1506). `chunk_files` packs to decided sizes,
  so an oversize group splits into exactly `ceil(files / cap)` near-equal
  chunks whatever its directory shape — it used to emit a phantom cell, and a
  starved trailing chunk, depending only on directory names (#1503). The
  Commons `CI` category claims the top level of `.github` (`*.yml`, `*.yaml`,
  `*.sh`, `*.json`), so `labels.yml` and friends stop reading as a catalog
  coverage gap (#1508). Globs: a trailing-slash directory pattern (`docs/`)
  now compiles as gitignore reads it instead of silently matching nothing,
  and a character class (`*.[ch]`) is refused at validation time instead of
  being escaped into a literal that claims the wrong files (#1501).
- **Tests axis:** a vertical's wildcard `tests` glob is scoped (under its
  `match` dirs or naming the vertical/an alias); the cross-cutting test trees
  form a `Tests` group last, at run time, from the leftovers.
- **Stage 1 spine:** `setup-spine.json` — depth-2 tree, languages, manifests
  and frameworks, already-claimed counts, test trees and the size arithmetic,
  bounded and sanitized (#1120) — is computed once with the sizes pinned in
  `setup-manifest.json` and rendered into the brief.
- **Compatibility (5.1 -> 5.2)** — superseded by #1681: the schema below is
  unchanged, but the file moved to the root `panopticon.yml` under a `groups:`
  key, so an upgrade now runs `driver migrate-config` rather than nothing. The
  original note: the `groups.yml` schema is unchanged and a
  5.1 setup proposal still validates; re-running `driver setup` is optional
  and never overwrites a committed `groups.yml`. Three run-time behaviours DO
  change without re-running setup: a wildcard `tests:` glob (`**/*_test.go`)
  is scoped to the vertical's own directories and files that name it (the
  files it used to credit elsewhere are reported once, to stderr and
  `scoped_tests_warnings`); leftover test-tree files sweep into a `Tests`
  group; a committed `Tests` (or `Tests:*`) suppresses that sweep. Escape
  hatch when the old crediting was intended: move the glob from `tests:` to
  `match:`.
- Deferred: `driver run --max-per-group` still chunks at run time and does
  not read `config.json`; the durable profile (`profiles.yml`) and the scout
  short-circuit, and `--seats` calibration, are plan 2.

## 5.1.0 — Measurement

The release where the scanner's own numbers became worth reading. 231 commits,
37 issues.

- **A grade that discriminates:** the max-severity rollup had SATURATED — ten Ds
  and one F across eleven runs, unable to tell any two codebases apart. It is
  replaced by a bounded health index (#1473, #1456, #1146).
- **A cost ledger that reproduces:** `meta.cost.tokens` goes from usually-null to
  collected automatically, over a window bounded at BOTH ends, so a run's ledger
  still reproduces after the fact (#1450, #1453, #1494).
- **Grouping becomes controllable rather than implicit:** `--max-per-group` is
  exposed and defaulted to 48 after a measured cap series (#1462, #1488),
  subgroups roll up to their parent in the report (#1305), and a chunk states its
  parentage instead of having it inferred from its name (#1480).
- **Per-run folders** (#1130) and **X0X catalog-gap emission** (#1132) land as
  planned. Tool-aware review ships as a SEC-cell proof of concept (#1307); the
  full treatment is deferred to 5.2 (#1131).
- **The tool axis is repaired end to end:** dependency-check no longer certifies
  off a build file alone (#1474), a tool verdict is keyed to its dispatched cell
  rather than an echoed id (#1475), and the void gosec axes were re-measured
  rather than caveated (#1477).
- **The remaining 136 fixes** are self-scan remediation from runs 6-10, plus the
  calibration apparatus that made five targets measurable — including two
  pre-registered predictions, one of which failed and was recorded as failed.

## 5.0.1 — Honest instrumentation

The first 5.0 point release: the residuals surfaced by the BursarBuddy
calibration and the 5.0 PR sweep, all keeping the pipeline's self-reporting and
gating honest.

- **Honest cost ledger:** `meta.cost` enumerates every 5.0 driver dispatch class
  from its own on-disk artifact — review cells, verify primary/backup, the tool
  round, and the scan — instead of only scout + a lumped advisor row (#1030).
- **Cheaper verify:** the second-witness backup re-reads only its scoped claims'
  files (not the whole cell), and the per-finding tool-advisor runs on a lighter
  model — the biggest cost lever, with zero coverage loss (#1029).
- **Honest tool certification:** coverage certifies against the runner's
  deterministic adapter manifest (`selected/produced/missing`), not the scout's
  free-form tool list, so a scout naming an absent/inapplicable tool no longer
  sinks the gate (#1031); `eslint-security` reports empty-valid on a
  nothing-to-lint target instead of a skip (#984).
- **Nightly image health:** a push-triggered keep-alive re-enables the
  `panopticon-tools` schedule, and a freshness heartbeat fails loudly on a stale
  image (#1032).
- **Driver robustness:** the clean-tree tamper guard reads `git status -z` and
  checks both rename endpoints, plus atomic manifest writes, spawn-error
  wrapping, and a tools crash-vs-skip marker (#1033).
- **OCRDb consumer & matrix hardening:** a distinct exit code for a corrupt
  bundle, a `ZZZ-X0X` sentinel for a domainless code, `code_domain_mismatch`
  disclosure, and the `{criteria}` advisor lens — the domain-advisor now grades
  against a code's explicit pass/fail criteria where defined (#1034, #1035).
- **Config dedup:** `model_resolver` is the single owner of the host
  role→model map; the duplicate `EMIT_MODEL_POLICY` is retired (#1036).
- **Severity discipline:** an explicit CRITICAL-vs-HIGH bar in the reviewer
  prompt so CRITICAL is earned, not defaulted-to (#1038).
- **OCRDb feedback groundwork:** an `x0x-report-schema.json` — Panopticon's
  catalog-gap findings as candidate records for OCRDb's new-code pool (schema
  only; emission wires up in 5.1).

## 5.0.0 — The matrix flagship

- Review is now a single resumable **driver** (`skill/scripts/driver.py`,
  subcommands `setup`/`run`/`next`) that the host drives through a status
  protocol; the legacy orchestrator is retired (P6 collapse). Phases:
  discovery → coverage → tools → review → verify → synthesize → validate.
- **Coverage:** per-group `scout` profiles widen a committed capability floor;
  the universal-tier floor `{COD,DAT,TST,ARC}` is injected but **surface-gated**
  per group — a testless / db-free / single-module group drops the floor cells
  it has nothing to review, disclosed at `global_floor_suppressed` (#5.0-19).
- **Verify:** every finding is adjudicated by an independent advisor; gate-
  eligible findings get a second (backup) witness, and deterministic tool
  (SARIF) findings are routed through a per-finding advisor so they can reach
  `tool_confirmed` and stop forcing spurious `INCONCLUSIVE` (#5.0-03).
- **Integrity:** driver-path anti-tamper controls are wired —
  `dispatch-plan-driver.json` declares every review cell (undeclared-file
  reconcile) and `out-file-hashes.json` snapshots each cell's bytes at the
  review→verify boundary (content-substitution check) (#5.0-16).
- **Enforcement:** fan-out reviewers/advisors hold a write-guarded, single-file
  `Write`; hostile-target path confinement and status-protocol crash hardening
  across the #1014–1027 series.
- **Reporting:** every report carries `meta.cost` (dispatch ledger) and
  `meta.integrity`; the CI gate keys on `summary.gate` + `summary.coverage_certified`.
- Validated end-to-end against the BursarBuddy answer-key corpus: recall 8/11,
  precision 1.0, perfect decoy discrimination, all controls firing on a real
  hostile target.

## 4.3.2 — 4.x freeze closer

- Added `meta.cost` dispatch ledger — `{phase, role, model, count}` rows derived
  from scout profiles, dispatch-plan union, and verify queue, plus a `tokens`
  slot reserved for host-reported usage.
- Fixed a ledger bug: `dispatch.build_plan` stamped `security_mode` on
  `lens_sweep` but omitted it from `panel_review`, so `plan_contract` rejected
  every plan with a panel and synthesize silently dropped all fan-out rows.

## 4.3.1 — External review point release

- Path-variant clustering: `evidence.norm_path` is the single owner of finding-path
  normalization so prefix/backslash dressing cannot split clusters.
- Delta discovery uses `--find-renames` for rename-semantics parity with
  `diff_map.hunk_map`.
- Un-loadable verdicts count as a gate-relevant coverage gap: a PASS with lost
  verdicts reads `INCONCLUSIVE`.

## 4.3.0 — 4.x series wrap

- Codex host support: `codex` model profiles, `--emit-host-agents codex`, and
  codex-runner wiring.
- Added `meta.integrity.empty_dispatch_plans` to the certification gate.

## 4.2.0 — Tool-policy enforcement

- Uniform read-only/return-JSON role contracts for every reviewer role.
- `--emit-host-agents` generates registered enforcement shells (claude/kimi
  dialects) from host-neutral templates.
- Per-role `enforced` plan entries dispatched via `subagent_type`;
  `meta.coverage.tool_policy_mode` records the runtime posture.
- Added clean-tree check in the validate step.

## 4.1.0 — Claude Code port

- Deterministic rendered prompts: dispatch-plan entries carry `prompt`, and
  `--render-advisor` renders verify-queue entries.
- Agent templates get host-neutral frontmatter (`tool_policy` as data);
  advisory-by-prompt on raw-prompt hosts.
- Explicit host selection (`--host`) with fixed env fallback (`CLAUDECODE`).

## 4.0.0 — Epistemics core

- Two-axis severity × evidence model: severity is never mutated; evidence.status
  is the pipeline verdict.
- Verification moved out of synthesize into an orchestrator-dispatched verify
  phase (`--emit-verify-queue` → advisor fan-out → `--verdicts-dir`).
- Gate/grades key on confirmed evidence by default, with `--gate-unverified` opt-in.
- Reinforced (tool+agent) findings gate as `tool_confirmed`; legacy confidence
  bumps removed.

## 3.0.0 — Multi-model reviewer dispatch

- Added role-based dispatch layer: `scout`, `lens_sweep`, `panel_review`, `advisor`.
- Added `scripts/model_resolver.py` for cross-platform model selection (Kimi / Claude / OpenRouter).
- Added `scripts/depth_planner.py` for depth-aware lens spawning.
- Added `scripts/dispatch.py` to emit `DispatchPlan` JSON for agent fan-out.
- Added `scripts/synthesize.py` advisor trigger and verdict application.
- Added Kimi Code custom agent files under `agents/`.
- Updated `SKILL.md` frontmatter and fan-out step.
- Added CI workflows for tests, lint, CodeQL, and full static-analysis scans.
- Updated `pyproject.toml` with project metadata; added `LICENSE`, `README.md`, `CODEOWNERS`, `CONTRIBUTORS.md`, `CONTRIBUTING.md`.

## Earlier releases

See [DEVELOPMENT.md](DEVELOPMENT.md) for the detailed pre-3.x version history.
