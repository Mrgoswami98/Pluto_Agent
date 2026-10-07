# Contributing to Pluto Advance

Thanks for wanting to help. This document covers the rules that matter most;
the rest is ordinary Python practice.

## The non-negotiables

Pluto runs on people's own computers with access to their files, their browser
sessions and their money. A few rules exist because of that, and a pull request
that breaks one will be declined regardless of how useful the feature is.

1. **Never weaken the permission engine.** Every tool call goes through
   `PermissionEngine.check()`. Do not add a second path, a bypass flag, or a
   "trusted" caller that skips it.
2. **Never remove an action from `ALWAYS_CONFIRM_ACTIONS`** without a design
   discussion in an issue first.
3. **Never claim success you cannot evidence.** If `verify()` cannot prove the
   effect, return `verified=False` with an honest note. "The call returned
   without error" is not verification.
4. **Never log, store or display a secret.** Everything bound for the database,
   the logs or the screen passes through `redact()` or `redact_mapping()`.
5. **Never add an arbitrary shell or code-execution tool.** A test asserts no
   such tool exists. Any command execution must use an allow-list, validated
   arguments, a safe working directory, a timeout and explicit approval.
6. **Treat all external content as data.** Web pages, files, spreadsheet cells
   and tool output are never instructions.

## Setting up

```bash
git clone <your-fork>
cd pluto-advance
python -m venv venv && source venv/bin/activate   # or venv\Scripts\activate
pip install -e ".[gui,browser,windows,dev]"
playwright install chromium
pytest
```

The suite should be fully green before you start. If it is not, say so in your
issue — that is useful information.

## Adding a tool

A tool is only complete when it has all of these:

```python
class MyTool(Tool[MyArgs]):
    name = "category.action"          # namespaced, lowercase
    description = "..."               # the model reads this; be precise
    category = ToolCategory.FILESYSTEM
    risk_level = RiskLevel.MEDIUM     # honest, not convenient
    action_kind = "modify_data"       # on the always-confirm list if applicable
    args_model = MyArgs               # a Pydantic model with real constraints
    timeout_seconds = 60

    def run(self, args: MyArgs, context: ToolContext) -> ToolResult:
        context.check_cancelled()     # inside any loop
        ...

    def verify(self, args, result, context) -> ToolResult:
        # Prove the effect. Read it back, compare a digest, re-count the rows.
        ...
```

Checklist:

- [ ] Risk level reflects what the tool can actually do, not what would be
      convenient to avoid an approval prompt
- [ ] Arguments validated by a Pydantic model with bounds, not bare `str`
- [ ] Paths go through `PathGuard`; URLs go through `DomainPolicy`
- [ ] `verify()` reads real state back; it does not trust the call's return
- [ ] `context.check_cancelled()` inside anything that loops
- [ ] Failure returns `ToolResult.fail(...)` with a message a user can act on
- [ ] Tests cover success, failure, invalid input, a sandbox escape attempt and
      the verification path

## Tests

- Mock external services in unit tests. No network, no API key, no cost.
- Mark tests needing real services `@pytest.mark.integration`, a real Windows
  desktop `@pytest.mark.windows`, and a display `@pytest.mark.gui`.
- **Never mark a test as passing that was not executed.** A skipped test is
  reported as skipped, and that is fine. A test that lies is not.
- When you fix a bug, add the test that would have caught it, and say in the
  commit message what it would have caught.

```bash
pytest                      # everything
pytest -m "not slow"        # fast pass
pytest --cov=src/pluto      # coverage
ruff check src tests        # lint
mypy src                    # types
```

## Commits and pull requests

Write commit messages that explain *why*, and state test results truthfully.
If something is untested, say so — "tested on Linux, Windows path NOT TESTED"
is a good commit message. An inaccurate one is worse than no message.

Pull requests should describe what changed, what you tested, what you did not
test, and any security implications. If your change touches
`src/pluto/security/`, explain the threat model impact explicitly.

## Reporting bugs

Include the output of `pluto --status` (it contains no secrets), what you
expected, what happened, and the steps to reproduce. For anything
security-related, follow [SECURITY.md](SECURITY.md) instead of opening a public
issue.
