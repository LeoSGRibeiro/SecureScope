def compute_diff(current_findings: list[dict], previous_findings: list[dict]) -> dict:
    """Compare two lists of finding dicts and return new, resolved, and unchanged sets.

    Identity key: (title, module) — severity is intentionally excluded because
    the same vulnerability may be re-scored between scans.
    """
    def key(f: dict) -> tuple:
        return (f.get("title", ""), f.get("module", ""))

    prev_keys = {key(f) for f in previous_findings}
    curr_keys = {key(f) for f in current_findings}

    new = [f for f in current_findings if key(f) not in prev_keys]
    resolved = [f for f in previous_findings if key(f) not in curr_keys]
    unchanged = [f for f in current_findings if key(f) in prev_keys]

    return {"new": new, "resolved": resolved, "unchanged": unchanged}
