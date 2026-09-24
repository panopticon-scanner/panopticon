---
name: Bug report
about: Something in the tool misbehaved (the driver, a scanner adapter, the report, a workflow)
title: ""
labels: bug
assignees: ""
---

**What happened**

<!-- One or two sentences. What you ran, what you expected, what you got. -->

**How to reproduce**

```
# host (claude / kimi / codex / generic), panopticon commit, and the exact command
python3 skill/scripts/driver.py ...
```

**Readiness output**

<!-- Paste the table from `python3 skill/scripts/driver.py readiness . --host <host>`. It launches nothing and writes nothing. -->

**Run artifacts, if any**

<!-- The run tag from `.panopticon/runs/`, the `driver:` stderr lines, and the relevant part of the report (`summary`, `meta.coverage`, `meta.integrity`). Redact anything from the reviewed tree that is not yours to share. -->

**Anything else**

<!-- A hostile-target reproduction that makes the tool do something it should not is a security report: use the Security tab instead of this template (see SECURITY.md). -->
