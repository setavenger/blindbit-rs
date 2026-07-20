---
name: subagent-orchestration
description: >-
  Default orchestration pattern for all agent work. Use proactively on every
  task — delegate context-heavy research, exploration, implementation, and
  review to subagents so the main session stays lean. Prefer fast/cheap models
  (e.g. Composer 2.5 Fast) for research and read-only work.
---

# Subagent Orchestration

**Active every session.** Main agent orchestrates; subagents absorb context-heavy work. Do not revert to doing broad research, file spelunking, or isolated implementation inline unless the task is trivial (one file, one lookup, under ~2 minutes).

## Why

File reads, grep sweeps, web research, multi-file edits, and review dumps fill the main context with low-value noise. The user loses the master overview and must reset sessions sooner. Subagents run in isolated context and return summaries — the main thread keeps strategy, decisions, and synthesis.

## Default: delegate

| Work type | Delegate to | Model hint |
|-----------|-------------|------------|
| Codebase exploration, "where is X?", broad search | `explore` subagent | `composer-2.5-fast` |
| Web/docs research, comparisons, fact-finding | `generalPurpose` subagent | `composer-2.5-fast` |
| Shell/git/CI commands | `shell` subagent | default |
| Isolated implementation chunk (one feature, one module) | `generalPurpose` subagent | match complexity; prefer fast when straightforward |
| Code review | `bugbot` or `security-review` subagent | readonly |
| PR CI failure triage | `ci-investigator` subagent | default |

**Prefer fast/cheap subagents** (`composer-2.5-fast`) for read-only and research tasks. Reserve slower/deeper models for subagents only when the task genuinely needs it (architecture tradeoffs, subtle bugs, security).

## Main agent keeps

- User intent and plan
- Tradeoff decisions and clarifying questions
- Synthesizing subagent results into action
- Final edits that must stay coherent across the session
- Short, targeted reads (one known file, one signature)

## How to delegate

1. **Launch early** — before a research spiral fills main context.
2. **Be specific** — give the subagent a focused task and what to return (paths, summary, recommendation).
3. **Parallelize** — independent subagents in one message (e.g. explore auth + explore billing).
4. **Trust summaries** — act on subagent output; re-read files in main context only when verifying a specific edit.
5. **Resume** — use `resume` for follow-ups on the same subagent thread instead of re-explaining from scratch.

## When inline is OK

- Single known file, small localized edit
- User explicitly wants work in main thread
- Subagent already failed twice on same task — diagnose, then retry or do minimal inline fix

## Anti-patterns

- Reading 5+ files in main context to "understand the codebase"
- Running broad `grep` / `glob` sweeps before delegating explore
- Implementing a whole feature in main thread while also researching dependencies
- Choosing a slow model for a simple "find where X is defined" task
