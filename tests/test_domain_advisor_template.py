import dispatch

def test_domain_advisor_is_read_only():
    meta, body = dispatch.load_template("domain-advisor.md")
    assert meta["tool_policy"]["allowed"] == ["Read", "Grep", "Glob"]
    assert meta["tool_policy"]["forbidden"] == ["Bash", "Edit", "Write", "Agent"]

def test_domain_advisor_returns_bundle_not_writes():
    _, body = dispatch.load_template("domain-advisor.md")
    assert "{out_file}" not in body           # read-only: returns, never writes
    assert "verdicts" in body                 # returns a verdict bundle
    assert "_panopticon" in body
    assert "finding_id" in body

def test_domain_advisor_renders_with_driver_mapping():
    prompt = dispatch.render_prompt("domain-advisor.md", {
        "domain": "SEC", "group": "app", "file_list": "- a.py",
        "findings": "[]", "menu": "SEC-A1A n (HIGH)", "run_id": "RID",
        "stage": "primary"}, "claude")
    assert "SEC" in prompt and "RID" in prompt
