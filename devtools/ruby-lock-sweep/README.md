# Gemfile.lock reader vs Bundler: a differential sweep

- **What it compares.** `sweep.py` builds about 50,000 malformed variants of one `Gemfile.lock` (inserted junk, deleted and replaced characters, reordered and duplicated sections) and asks two parsers whether each one parses: the lock reader in `skill/scripts/first_party_advisory.py`, in-process, and `Bundler::LockfileParser`, through `bundler_parse.rb`. It prints every lock the reader ACCEPTS and Bundler REJECTS, which is the direction that reads better than the truth, and every spec Bundler saw that the reader did not.
- **Versions.** Written and last run against system Ruby 2.6.10p210 with Bundler 1.17.2 (macOS `/usr/bin/ruby`). Set `RUBY` to use another.
- **How to run.** `python devtools/ruby-lock-sweep/sweep.py <checkout> [bad.json]`. Offline: it parses lock text only; nothing is installed or fetched. About 30 seconds.
- **Result at 4abe642c.** 50,337 locks; Bundler rejects 20,319; both accept 9,576, with no spec or source kind Bundler saw that the reader missed; the reader is stricter on 20,442; the reader accepts 1 that Bundler rejects, `BUNDLED WITH 117.2`, which Bundler 1.17.2 refuses only for being written by a newer Bundler, not for its shape.
- **Status.** A development tool, not a test, kept with this branch for the day #3623 returns to Ruby. The branch's PR (#3692) is closed and nothing here is merged.
