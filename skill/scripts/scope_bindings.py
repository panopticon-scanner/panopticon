"""Small, per-entry read-scope documents for headless host launches.

The read guard keeps its shared map because session fan-outs need one durable
registry. A headless child already carries an entry id, so binding it to only
that row prevents a large batch from turning the registry into one oversized
Codex MCP input.
"""
import os

import scripts.phases.requests as requests
import scripts.guard_rules as guard_rules
import scripts.read_guard_hook as read_guard_hook
import scripts.safe_write as safe_write


class EntryScopes:
    """Write and remove the exact scope documents this process owns."""

    def __init__(self, shared_path):
        stem, extension = os.path.splitext(shared_path)
        self.directory = stem if extension else shared_path + "-entries"
        self.paths = {}
        self.transient = set()

    def path(self, entry_id):
        component = requests.entry_file_component(entry_id)
        return os.path.join(self.directory, component + ".json")

    def write(self, scopes):
        """Write normalized ``{entry id: scope}`` rows one file at a time."""
        for entry_id, scope in scopes.items():
            path = self.path(entry_id)
            safe_write.confine_artifact_path(path)
            guard_rules.atomic_write_json(path, {entry_id: scope})
            self.paths[entry_id] = path

    def ensure(self, entry):
        """Return one entry's binding, materializing an unarmed probe safely."""
        entry_id = entry.get("id") if isinstance(entry, dict) else None
        if entry_id not in self.paths:
            scopes = read_guard_hook.scope_from_plan([entry])
            if entry_id not in scopes:
                raise ValueError("entry %r carries no read scope" % entry_id)
            self.write(scopes)
            self.transient.add(entry_id)
        return self.paths[entry_id]

    def clear(self, entries=None):
        """Remove this fan-out's files plus any transient probe binding."""
        entry_ids = (set(self.paths) if entries is None else {
            entry.get("id") for entry in entries if isinstance(entry, dict)})
        entry_ids.update(self.transient)
        for entry_id in entry_ids:
            path = self.paths.pop(entry_id, None)
            if path is None:
                continue
            try:
                safe_write.remove_artifact(path)
            except (OSError, ValueError):
                pass
        self.transient.difference_update(entry_ids)
        try:
            safe_write.confine_artifact_path(self.directory)
            os.rmdir(self.directory)
        except (OSError, ValueError):
            pass
