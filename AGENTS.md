# Triplebit Portal agent contract

Project Memory is the source of truth for roadmap, decisions, architecture,
review state, and recurring pitfalls. Generic role prompts are subordinate to
the user's current request and the project-specific sources below.

## Start every non-trivial task

1. List project skills. Load `stay-on-spec`; also load `verify-like-ci` for
   implementation, review, verification, or milestone claims.
2. Read `.agentsroom/memory/INDEX.md`, then only the notes whose descriptions
   match the task. Always include `agent-operating-contract`,
   `decision-register`, `roadmap`, and the owning feature note. Reviews also
   load `code-review-methodology`; security reviews load
   `security-review-methodology`.
3. Capture `git status --short` and `git rev-parse HEAD`. Establish the
   objective, authority, version boundary, exclusions, and completion evidence.

Never edit files under `.agentsroom/memory/`. They are a read-only mirror.
Create or update Project Memory only through the AgentsRoom memory tools.

## Safe actions do not need confirmation

Do not ask permission before reading or searching repository files, loading an
attached skill, listing or reading Project Memory, making a read-only MCP call,
inspecting Git with status/log/diff/show, creating and removing your own unique
detached review worktree, or running non-destructive repository checks. Perform
these actions immediately when they are relevant.

Ask only when a material product choice cannot be recovered safely, or before
an external write, destructive action, purchase, credential submission, or
meaningful expansion beyond the requested scope.

## Repository ownership

Ponytail is the sole repository writer unless the user explicitly designates
someone else for a scoped task. Every reviewer, security agent, architect, QA
agent, and specialist is read-only with respect to repository files.

Milestone reviews operate on an exact committed SHA in a unique detached
worktree. Reviewers may write disposable scratch data, team notes, required
session metadata, and requested Project Memory findings. They must not fix,
stage, commit, generate into, or otherwise mutate the shared checkout.

## Use memory efficiently

- Read the index first and retrieve only relevant notes; do not load the whole
  library by default.
- Update the existing owning feature/area note instead of creating review-round
  or session-history notes.
- Store durable architecture, decisions, pitfalls, current state, exact commit
  provenance, verification evidence, and explicit open/closed/deferred status.
- Do not store transient diagnostics, progress narration, generic advice,
  secrets, or facts easily recovered from the code.
- After committed work or a completed review changes durable state, use
  `memory-closeout` to update the owning note and remove stale linked claims.

## Verification and precedence

Use repository Make targets and the `verify-like-ci` result labels. A passing
subset, silently skipped database tests, or an environment-blocked command is
not a full pass. Do not advance a milestone while a linked current review note
still has an open blocker.

Precedence is: current user instruction; locked decisions; roadmap and owning
feature memory; code/tests at the named version boundary; review evidence;
generic personas and checklists. D12 forbids adding generic scanners or linters
merely because a role prompt recommends them.
