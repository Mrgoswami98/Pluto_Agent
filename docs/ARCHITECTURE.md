# Architecture

## Layers

```
┌─────────────────────────────────────────────────────────────┐
│  UI (PySide6)   chat · tasks · approvals · activity          │
│                 permissions · memory · settings              │
└───────────────────────────┬─────────────────────────────────┘
                            │  all slow work via QThreadPool
┌───────────────────────────▼─────────────────────────────────┐
│  PlutoApplication          builds the object graph once      │
└───────────────────────────┬─────────────────────────────────┘
                            │
┌──────────────┬────────────┴───────────┬─────────────────────┐
│  AI          │  Agent                 │  Tools              │
│  client      │  orchestrator          │  registry           │
│  planner     │  (deps, retries,       │  files              │
│  prompts     │   budgets, verify)     │  spreadsheet        │
│              │                        │  browser · windows  │
└──────┬───────┴────────────┬───────────┴──────────┬──────────┘
       │                    │                      │
       │        ┌───────────▼──────────────────────▼─────────┐
       │        │  SECURITY — every tool call passes here     │
       │        │  PermissionEngine · PathGuard               │
       │        │  CredentialStore · untrusted content        │
       │        └───────────────────┬────────────────────────┘
       │                            │
┌──────▼────────────────────────────▼─────────────────────────┐
│  Data        SQLite · migrations · repositories (redacting)  │
└─────────────────────────────────────────────────────────────┘
```

## The rule that makes it safe

`ToolRegistry.execute()` is the only way to run a tool, and it always calls
`PermissionEngine.check()`. There is no second path and no bypass flag.

That matters because of what it means for prompt injection. The model may be
fully convinced by a malicious web page; it may emit a plan that calls
`file.delete` and claims the step is harmless. Neither helps, because:

- the engine reads the tool's **own declared** risk, not the plan's claim;
- the **always-confirm list** is keyed on the action kind, not on risk;
- the planner **recomputes** every step's risk from the registry before the
  plan can run.

Detection reports injection attempts. Containment is what actually holds, and
the test suite proves it holds even assuming detection fails completely.

## Request lifecycle

```
request
   │
   ├─► Planner ──────────► model proposes a plan
   │        │
   │        └─► validate: unknown tools rejected
   │                      arguments schema-checked
   │                      RISK RECOMPUTED from registry
   │                      dependency graph acyclic
   │
   ├─► Orchestrator ─────► resolve ready steps (deps satisfied)
   │        │
   │        ├─► Registry.execute()
   │        │        ├─ validate arguments
   │        │        ├─ PermissionEngine.check()  ← the gate
   │        │        │     ├─ emergency stop?      → DENY
   │        │        │     ├─ tool disabled?       → DENY
   │        │        │     ├─ observe mode?        → DENY if mutating
   │        │        │     ├─ valid approval?      → ALLOW
   │        │        │     ├─ always-confirm?      → REQUIRE APPROVAL
   │        │        │     └─ risk vs mode         → ALLOW / REQUIRE
   │        │        ├─ run with timeout + cancellation
   │        │        ├─ verify()  ← reads real state back
   │        │        └─ audit (success AND refusal)
   │        │
   │        └─► step COMPLETED only if success AND verified
   │                     otherwise PARTIAL, honestly reported
   │
   └─► report: completed · unverified · failed · skipped · awaiting
```

## Why a step can be "partial"

Most agents report success when a call returns without error. Pluto does not,
because "the function returned" and "the thing happened" are different claims.

Each mutating tool implements `verify()` by reading real state back:

| Tool | How it proves the effect |
|---|---|
| `file.write` | Reads the file and compares content exactly |
| `file.copy` | Compares SHA-256 digests of source and destination |
| `file.move` | Destination exists **and** source is gone |
| `sheet.export` | Re-opens the file and counts the rows |
| `browser.navigate` | Compares the landed host to the requested host |
| `browser.submit` | Requires the page to have actually changed |

If a tool cannot prove its effect, the result is `verified=False`, the step
becomes `PARTIAL`, and the user is told plainly rather than reassured.

## Threading

| Concern | Approach |
|---|---|
| GUI responsiveness | All slow work on `QThreadPool`; workers never touch widgets |
| Worker → UI updates | Queued, drained by a GUI-thread timer |
| Tool timeouts | Each tool runs in a pool future with a deadline |
| Playwright | **Thread-affine** — the session owns one browser thread and marshals every call onto it |
| SQLite | One connection per thread; shared single connection for in-memory tests |
| Cancellation | Cooperative via `threading.Event`, checked at every step boundary and inside tool loops |

## Key design decisions

**Risk lives on the tool, not the plan.** A plan is model output and therefore
untrusted input. The registry is code and is trusted.

**Approvals are scoped and expiring.** An approval covers one action kind at
one risk level. It cannot be replayed for something else, and a stale yes is
not a yes.

**Default deny everywhere.** No folders, no domains, no applications, no
screenshots. A fresh install can do nothing until the user grants something.

**Redact at write and at display.** Repositories redact before persisting, and
the approval UI redacts again, because an in-memory object has not been through
a repository.

**Honest refusal over silent no-op.** Off Windows, the desktop tools raise
`UnsupportedPlatformError` with a clear message rather than quietly doing
nothing.
