"""Per-family host probes (#1627).

`host_probes.py` stays the entry module -- it holds `PROBE_IDS`,
`PROBE_CAPABILITY` and `run_probes`, and assembles them from these modules by
module attribute. This package holds the probes themselves: `common` for what
every family shares, `claude` / `codex` / `kimi` for what each family proves
about itself.

Docstring only, like every other package here: a registry in an `__init__`
is a second place for a name to live.
"""
