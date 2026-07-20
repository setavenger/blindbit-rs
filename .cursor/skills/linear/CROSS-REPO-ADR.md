# Cross-repo architecture documents

Linear cloud agents trigger **one repo per issue**. Cross-repo features break if each issue carries its own copy of the API contract — they drift.

**Rule:** shared architecture lives in a **Linear Document** attached to the **project**. Repo issues link it; they do not repeat it.

Repo-local ADRs (`docs/adr/` in a single repo) stay for decisions that affect only that repo. Cross-repo contracts, integration patterns, and shared data models → **project-level Linear Document**.

## When to create a shared doc

Create (or update) a project Linear Document when **any** of these are true:

| Trigger | Doc type |
|---------|----------|
| Two+ repos implement the same feature | Feature ADR |
| API contract between services | Contract doc |
| Shared event/message schema | Contract doc § Events |
| Cross-repo rollout order | Feature ADR § Rollout |
| Ubiquitous language spanning repos | Glossary doc (or link repo `CONTEXT.md` files) |

If only one repo is involved → repo-local ADR or `N/A` in the issue. Do not create a Linear Document.

## Document hierarchy

```
Initiative (e.g. Billing Suite)          ← mission/container; not ADR home
└── Project (e.g. Subscription digests)  ← feature; ADRs attach here
    ├── Linear Document: ADR-0042 Subscription API     ← shared truth
    ├── Linear Document: ADR-0043 Dedupe strategy      ← optional second doc
    ├── Issue ENG-15 (api-service)  → links ADR-0042 only
    ├── Issue ENG-16 (worker)         → links ADR-0042 only
    └── Issue ENG-17 (web-app)        → links ADR-0042 only
```

**Never** attach the canonical contract to an issue (`parent: issue`). Always attach to the **project** so it is not "owned" by one repo's ticket.

## Naming convention

```
ADR-{NNNN}: {Short title}
```

- `NNNN` = zero-padded sequence **per project** (0001, 0002, …).
- Scan existing project documents via `list_documents` before assigning the next number.
- Slug-friendly title for search: `ADR-0042 Subscription API`.

Other doc types (no ADR prefix) when not a decision record:

- `Contract: {name}` — pure API/event spec
- `Glossary: {project name}` — shared ubiquitous language

## Document template

Use `save_document` with `project` set. Content:

```md
# ADR-{NNNN}: {Title}

**Status:** proposed | accepted | deprecated
**Project:** {project name}
**Repos:** api-service, worker, web-app

## Context

{Why this exists. 2–4 sentences. Problem spanning repos.}

## Decision

{What we chose. Bullets OK.}

## Contract

{The sync point — both/all repo issues reference this section.}

### Data model

{Tables, entities, IDs shared across repos.}

### REST / API

{Method, path, request, response, error codes. Or link to OpenAPI file in a designated repo.}

### Events / messages

{Event name, payload schema, ordering guarantees, idempotency.}

### Rollout order

| Step | Repo | Issue | Delivers |
|------|------|-------|----------|
| 1 | api-service | ENG-15 | Schema + API |
| 2 | worker | ENG-16 | Consumer + digest |
| 3 | web-app | ENG-17 | UI |

## Consequences

{Non-obvious downstream effects, monitoring, backwards compatibility.}

## Changelog

| Date | Change |
|------|--------|
| {YYYY-MM-DD} | Initial draft |
```

Keep it concise. Value = **one place** both issues point to, not ceremony.

## Workflow

### 1. New cross-repo feature

```
list_documents (project) → check existing ADRs
save_document (project, title, content) → create ADR-NNNN
save_issue × N → one per repo, each links ADR in **Design** and ADR § Consequences in **Effect**
```

Order matters: **document first**, then issues. Issues created before the doc must be updated immediately.

### 2. Contract change

```
get_document → edit Contract section → save_document
save_comment on each affected issue: "ADR-NNNN updated — see § Events"
```

Do **not** edit contract text inside issue descriptions. Update the doc; issues stay stable.

### 3. Repo-local decision

Decision affects one repo only → `docs/adr/` in that repo. Issue links `path/to/adr` in **Design** or **Implementation** (unless it changes the shared contract — then update the Linear Document).

## MCP usage

| Task | Tool |
|------|------|
| List project docs | `list_documents` (filter by project) |
| Read doc | `get_document` |
| Create / update | `save_document` with `project` + `title` + `content` |
| Notify subscribers | `save_comment` on related issues after doc update |

## Splitting work across issues

| Shared doc contains | Issue A (api-service) contains | Issue B (worker) contains |
|---------------------|-------------------------------|---------------------------|
| Full API schema | "Implement per ADR § REST" | "Call API per ADR § REST" |
| Event payload | "Emit per ADR § Events" | "Consume per ADR § Events" |
| Rollout order | Row 1 in table | Row 2 in table |

Use `blockedBy` / `blocks` to mirror **Rollout order**. Sibling issues list each other under **Design**; cross-repo impact links **ADR § Consequences** under **Effect**.

### Quoting a frozen snapshot (optional)

An issue may quote the relevant slice of the ADR inline, in addition to linking it — mark it explicitly as a snapshot:

```md
> **Frozen snapshot of ADR-0042 § REST as of 2026-07-13. If the ADR changes, re-sync this block.**
> `POST /subscriptions` → `{ "userId": "uuid", "feedId": "uuid" }` → `201 { "id": "uuid" }`
```

Keep excerpts short. When the ADR changes, update every issue's snapshot in the same pass.

## Migrating pre-existing repo-committed ADRs

When a repo already has markdown ADRs (`docs/adr/0001-*.md`) covering a feature being moved into Linear, mirror them as Linear documents on the relevant project:

```md
> Mirrored from `api-service/docs/adr/0007-subscription-fsm.md` (source file is the historical record; this Linear doc is canonical for active work going forward).
```

## Project description

Project descriptions follow [PROJECT-FORMAT.md](./PROJECT-FORMAT.md). Index shared docs under **Design § Architecture documents** and integration branches under **Implementation § Git branches**.

## Anti-patterns

| Don't | Do instead |
|-------|------------|
| Paste API schema in two issue descriptions | One Linear Document, two links |
| Put cross-repo ADR on issue ENG-15 | Attach to project |
| "See ENG-16 for API details" | Link shared doc; ENG-16 is sibling only |
| One mega-issue with two repo labels | Split; one label each |
| Change contract only in one repo's issue | Update Linear Document + comment on siblings |

## Relation to domain-modeling skill

- **Ubiquitous language** in a single repo → `CONTEXT.md` per [domain-modeling](../domain-modeling/SKILL.md).
- **Cross-repo language** → project Glossary doc or links to each repo's `CONTEXT.md` from the shared ADR.
- **Hard-to-reverse integration choice** → Linear Document ADR (cross-repo) or repo `docs/adr/` (single-repo). Same three criteria as [ADR-FORMAT.md](../domain-modeling/ADR-FORMAT.md).
