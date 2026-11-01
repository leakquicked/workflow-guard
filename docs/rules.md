# Rule reference

- **WG001 (high):** no explicit top-level permissions block. Add least-privilege token scopes.
- **WG002 (medium):** external action is not pinned to a full 40-character commit SHA. Tags can move; review pinned source updates.
- **WG003 (high):** privileged `pull_request_target` trigger. The trigger alone is not proof of a vulnerability; avoid checking out or executing untrusted PR content.
- **WG004 (high):** common attacker-controlled event data is interpolated directly into a shell script. Use environment variables and validate/quote values.
- **WG005 (medium):** checkout credentials are explicitly persisted. Disable unless a later step needs Git authentication.
- **WG006 (high):** `write-all` token permissions. Replace with explicit minimal scopes.

## Limitations
This is a heuristic static checker, not a complete taint analyzer. It does not resolve reusable workflows, inspect action source code, evaluate all expressions, or verify repository settings. Findings require human review; false positives and missed cases are possible.
