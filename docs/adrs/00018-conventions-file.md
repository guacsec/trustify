# 00018. Conventions File and Performance Anti-Pattern Standards

Date: 2026-05-14

## Status

ACCEPTED

## Context

Trustify needs a single, explicit reference for coding patterns, naming rules, error-handling idioms, testing practices, and architectural norms. Contributors and reviewers use it during implementation and review; the same clarity also helps AI-assisted workflows (Claude Code, Copilot, and similar tools) when those tools load project context.

### Current Situation

Today, project conventions are scattered across tribal knowledge among maintainers,
code-review feedback, and implicit patterns in existing code. This leads to:
- **Inconsistent contributions**: new code diverges from established patterns (e.g., different error handling in different modules)
- **Repeated review feedback**: maintainers correct the same convention violations across PRs
- **AI hallucination**: AI tools infer conventions from files they happen to read which leads to adopting anti-patterns from older code
- **Onboarding friction**: new contributors don't have a quick reference

### What a Conventions File Provides

A `CONVENTIONS.md` file at the repository root serves as a reference for project-wide coding conventions. It:
- Lives next to the code it governs, evolving with the project
- Is automatically loaded by AI tools (Claude Code reads `CONVENTIONS.md` as context)
- Provides a reviewable, diff-able record of convention decisions
- Serves both as a contributor guide and an AI prompt artifact

## Decision

Review and update the `CONVENTIONS.md` file at the repository root that documents the project's coding conventions, patterns, and practices. The file is maintained as living documentation — updated through the normal PR process as conventions evolve.

### Scope

The conventions file covers:

| Section | Purpose | Examples |
|---------|---------|---------|
| **Language and Framework** | Technology stack and core dependencies | Rust edition, Actix-web, SeaORM, Tokio |
| **Code Style** | Formatting and lint rules | `rustfmt` defaults, clippy flags, `unwrap()` policy |
| **Naming Conventions** | Naming patterns for all code elements | Structs, functions, modules, endpoints, OpenAPI IDs |
| **File Organization** | Workspace layout and module structure | Domain module pattern (endpoints/service/model) |
| **Error Handling** | Error type design and propagation | `thiserror` enums, `ResponseError` mapping, `From<DbErr>` |
| **Testing Conventions** | Test infrastructure and patterns | `TrustifyContext`, test placement, assertion style |
| **Commit Messages** | Commit format and trailers | Conventional Commits, Jira references |
| **Pre-commit Workflow** | CI-equivalent local checks | `cargo xtask precommit` steps |
| **Dependencies** | Dependency management policy | Workspace-level pinning, key crate choices |
| **Endpoint Patterns** | HTTP endpoint conventions | `configure()`, authorization, transactions, OpenAPI |
| **Entity Model Patterns** | ORM model conventions | `DeriveEntityModel`, relations, `Linked` structs |
| **Migration Patterns** | Database migration conventions | Idempotency guards, naming, raw SQL loading |
| **Rust Idioms** | Preferred Rust patterns | Type inference, iterator ownership, `.zip()`, capacity |
| **SeaORM Query Patterns** | ORM query conventions | `.is_in()`, chunking |
| **Observability** | Tracing and instrumentation | `#[instrument]` usage, span conventions, error levels |

### Content Principles

1. **Prescriptive, not descriptive**: each convention states what to do and what to avoid, with concrete code examples
2. **Derived from existing code**: conventions are extracted from established patterns in the codebase, not invented
3. **Minimal and actionable**: each entry should be short enough that a contributor (or AI tool) can apply it without reading surrounding prose
4. **Reference implementations**: share canonical examples
5. **No duplication with tooling**: don't restate what `rustfmt` or `clippy` already enforce — reference their configuration instead

### Maintenance Process

- **Updates via PR**: convention changes follow the same review process as code changes
- **ADR linkage**: significant convention changes that reflect architectural decisions should reference the relevant ADR
- **Deprecation**: when a convention is superseded, update the section rather than appending contradictory guidance
- **Scope creep guard**: the file documents *conventions* (how to write code), not *architecture* (why the system is designed this way) — architecture belongs in ADRs

### AI Tool Integration

The conventions file is designed to be consumed by AI coding assistants:
- Claude Code automatically loads `CONVENTIONS.md` from the repository root as part of its project context
- The file uses markdown with code blocks, making it parseable by any LLM
- Conventions are structured as clear rules with examples, optimizing for AI instruction-following
- When a `CLAUDE.md` file is present (for tool-specific configuration), `CONVENTIONS.md` complements it — `CONVENTIONS.md` focuses on language and framework patterns that apply regardless of the tool

## Consequences

### Positive

- **Better AI output**: AI tools generate code that matches project style from the first attempt
- **Onboarding**: new contributors can read one file to understand "how we write code here"
- **Consistency**: single source of truth reduces convention drift across modules and contributors
- **Faster reviews**: reviewers can reference specific convention sections instead of explaining patterns from scratch
- **Accountability**: convention changes are tracked in git history with review

### Trade-offs

- **Living document**: conventions are not set in stone — they evolve through the ADR and PR process to improve how we work. When a convention changes, existing code is refactored to align. The goal is continuous improvement, not rigid enforcement
- **Completeness tension**: too few conventions and the file is unhelpful; too many and it becomes noise that contributors (and AI tools) ignore
- **Convention vs. enforcement gap**: not all conventions can be enforced by CI — some rely on review discipline

### Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| File becomes outdated | Treat convention violations in review as a signal to update the file |
| File grows too large for contributors and AI context windows | Keep entries concise; split into linked files if needed |
| Conventions conflict with each other | PR review process catches contradictions before merge |
| Over-prescription stifles judgment calls | Focus on patterns with clear consensus; leave room for discretion |

## References

- [Trustify CONVENTIONS.md](../../CONVENTIONS.md) — the conventions file introduced by this ADR
- [TC-4289](https://redhat.atlassian.net/browse/TC-4289) — Jira task for architectural standards
