"""Helpers shared by the tests/probes/ modules (#1627)."""
import os


def _shell(directory, name, tools, block_list=False):
    """Write a registered shell with the given `tools:` line (inline or block list).

    If block_list=True, emits YAML block format: tools:\n  - Read\n  - Grep
    Otherwise, emits inline format: tools: Read, Grep
    """
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, name)
    if block_list:
        block_items = "\n".join("  - %s" % t for t in tools)
        content = ("---\nname: %s\ndescription: probe fixture\ntools:\n%s\n"
                   "---\n\nbody\n" % (name[:-3], block_items))
    else:
        content = ("---\nname: %s\ndescription: probe fixture\ntools: %s\n"
                   "---\n\nbody\n" % (name[:-3], ", ".join(tools)))
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    return path
