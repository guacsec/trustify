# 00024. PatternFly Elements for a Full-Stack Rust UI

Date: 2026-11-04

## Status

PROPOSED

## Context

Trustify is a Rust project, but its main UI is not. Two UIs are built and embedded in the server on the `main` branch today:

| UI | Stack | Served at | Location |
|---|---|---|---|
| Trustify UI | TypeScript, React, PatternFly React, built with npm | `/` | separate repository (`guacsec/trustify-ui`), consumed as the `trustify-ui` crate |
| Trustify Console | Rust, Yew, `patternfly-yew`, built to WebAssembly with Trunk | `/console/` | this repository (`ui/`, crate `trustify-correlation-ui`) |

Both are optional Cargo features of `trustd` (`trustify-ui` and `ui-console`), and both are enabled by
default on `main`. The Console is a proof of concept (POC): it is part of the default build of `main`,
but it is not intended for release branches. It declares `patternfly-yew` as a dependency in
`ui/Cargo.toml`, and it also uses npm to obtain PatternFly CSS and Font Awesome assets
(`ui/package.json`). It is built as an application with Trunk, not with a JavaScript bundler.

The Console is a Rust/Wasm UI for the correlation engine. It shows that a Rust UI can be built and
embedded in the server. Its component layer is `patternfly-yew`, which is the question this ADR
addresses.

This is not the first Rust UI in the project. The first generation of Trustify (the Trustification
project) used Yew and `patternfly-yew` for its UI, and ran in production with it. That UI needed more
advanced components than `patternfly-yew` provided at the time. Component coverage, not the Rust/Wasm
approach itself, is therefore the main lesson from that experience, and it is why this ADR requires a
full coverage assessment (see Validation) before accepting a component layer.

The current setup has the following problems:

1. **Split tech stack.** The project needs Rust and TypeScript/React skills, two toolchains, two test
   setups and two release flows for the UI, and ships two UIs built on different stacks. The React UI
   lives in a different repository from the API it consumes, so API changes and UI changes cannot be
   built, tested and released together.

2. **No dedicated UI team.** The project has no UI team, and help from additional UI developers has not
   materialised. Every UI dependency is therefore maintenance work for backend engineers.

3. **npm maintenance burden.** The React UI brings a large transitive npm dependency tree. Keeping it
   free of known vulnerabilities is a recurring, mostly mechanical effort. The Console's npm use is
   much smaller (CSS and font assets) but still requires Node in its build.

4. **Downstream.** Downstream products are aligned with PatternFly. Any change to the UI stack must not
   make the downstream build, support or UX alignment harder.

A Rust/WebAssembly UI removes the second stack, but it needs a component layer that provides the
PatternFly look and feel. The usual answer is a Rust wrapper crate such as `patternfly-yew`. A wrapper
has to follow every PatternFly release, is tied to one Rust UI framework, and is not maintained by the
PatternFly project. In practice only one Trustify contributor is currently working on `patternfly-yew`,
so keeping it current with PatternFly depends on a single person. Using it means either depending on a
library the project does not control or spending UI resources it does not have.

Web components offer another way. They are a browser standard supported by all major browsers
(including Declarative Shadow DOM), they are used by large design systems, and Red Hat publishes the
PatternFly design system as web components: [PatternFly Elements](https://patternflyelements.org)
(PFE). A web component is used like any HTML element (for example
`<pf-v6-button variant="primary">`) and does not depend on a UI framework, so it can be used from
Rust/Wasm with a small amount of `web-sys` glue.

This ADR concerns only the choice of the component layer for a Rust UI. It does not decide the fate of
either existing UI. The status of the Console is described under Consequences.

## Decision

Trustify adopts a **full-stack Rust UI** built on **web components**, using PatternFly Elements for the
PatternFly look and feel, in this repository.

In detail:

1. **Rust UI in this repository.** The UI is written in Rust, compiled to WebAssembly, and built as part
   of the Trustify workspace (adding the `wasm32-unknown-unknown` target). It is embedded in and
   served by `trustd`.

2. **Web components as the component layer.** PatternFly Elements is used as standard HTML elements,
   with small `web-sys` glue where needed (for example for complex properties such as table rows).
   Trustify does not develop or maintain a Rust PatternFly component library, and does not depend on a
   Rust wrapper crate for PatternFly.

3. **Pre-built, pinned assets.** PFE is a JavaScript library, so its assets are consumed as pinned,
   pre-built files, not by running a JavaScript build in the Trustify build.

4. **Framework choice is separate.** This ADR does not pick between Yew, Leptos and Dioxus. The choice
   is made during the validation prototype below, and can be changed later because web components do
   not depend on the framework.

5. **Standards over wrappers.** When a UI element is needed, the order of preference is: a standard web
   component (PFE), then plain HTML and CSS using PatternFly tokens, and only then a project-owned
   component.

6. **Commitment and validation.** The decision is conditional on the validation below. If the exit
   criteria are not met, the status changes and the project reconsiders the alternatives.

### Validation

Before the status moves to ACCEPTED, the following is done:

- **Migration scope.** Define the planned migration: the list of pages and features of the existing
  UI that the Rust UI is expected to replace. The coverage matrix is built against this scope, not
  against the prototype page.
- **Coverage matrix.** List every PatternFly component used by the pages in the migration scope
  (tables, toolbars, filters, modals, select, tabs, pagination, and so on), taken from the existing
  React UI, and mark each one as available in PFE for PF6, available with caveats, or missing. For
  each component that is not fully available, record one of:
  - an acceptable workaround, with its estimated size and the maintainer who owns it, or
  - a fallback (a project-owned component, plain HTML and CSS with PatternFly tokens, or a deferral of
    the feature) that the maintainers have explicitly approved, with the reason, the estimated cost
    and the owner.
  The matrix is reviewed and approved together with this ADR, and its approval is recorded in the
  ADR or linked from it.
- **Prototype.** Build one non-trivial page (for example the SBOM list with table, filters and
  pagination) with PFE and a Rust UI framework. This includes the `web-sys` glue for complex
  properties, authentication and the API client.
- **Build.** Measure CI build time, the size of the Wasm and JS assets, and the first page load.
  Confirm that the build works with the project's offline and downstream build setup.
- **Accessibility and i18n.** Confirm the keyboard, screen reader and localisation behaviour of the
  components used.
- **Roadmap.** Obtain the PatternFly team's PFE roadmap for PF6 coverage.

### Exit criteria

The decision stands if:

- The coverage matrix shows that every component needed for the planned migration has acceptable PFE
  coverage, or an explicitly approved fallback. A component without either blocks acceptance.
- The total project-owned component work implied by the approved fallbacks is small enough that it
  does not amount to maintaining a PatternFly component library, which is what this ADR sets out to
  avoid. The maintainers state the accepted limit when they approve the matrix.
- The prototype page works with the available PFE components.
- The glue code is limited and does not amount to a de facto component library.
- The build fits into the Trustify build and the downstream build without a JavaScript build.
- Load time and asset size are acceptable.

## Alternatives

### Keep React and PatternFly React

- Pros: the component set is complete and current, and it is the mainstream PatternFly path. A large
  pool of developers know it.
- Cons: the project keeps two stacks and the npm vulnerability workload. No UI team exists to maintain
  it.

### Rust UI with `patternfly-yew`

- Pros: Rust-only, idiomatic for Yew, used in production by the first generation of Trustify, and
  used by the Console POC on `main`.
- Cons: a Rust-specific wrapper that the project depends on and would need to maintain or update for
  PF6. The first generation UI needed more advanced components than it offered. Only one Trustify
  contributor currently works on it, so it is a single point of failure. It ties the UI to one Rust
  framework.

### Write and maintain Rust components in Trustify

- Pros: full control.
- Cons: the same maintenance cost as a wrapper crate, with no sharing outside the project.

### Move the React UI into this repository

- Pros: keeps the UI and API together for building, testing and releasing.
- Cons: solves the repository split but not the stack split or the npm workload. It is compatible with
  this ADR as an interim step but does not replace it.

## Considerations

- **PFE coverage.** PFE is moving to PF6 and its coverage is not yet complete. The coverage matrix is
  the main risk and the first piece of work.
- **Glue code.** Web components take properties and events in the DOM. Complex values such as table
  rows need `web-sys` code. This is a cost, and it should be isolated in a small module.
- **Wasm in production.** From the server's point of view the compiled UI is a static asset. The
  trade-offs are the initial download size, a smaller ecosystem than React, and a smaller pool of
  developers who know Rust UI frameworks.
- **Downstream.** PFE follows the same PatternFly design language and tokens as PatternFly React. The
  component code differs. Downstream impact has to be confirmed with the downstream owners.
- **Multi-tenancy and other future directions.** Authentication, tenant context and routing live in the
  API and a small client layer (API client, token handling, tenant selection), not in the component
  library. The choice of PFE does not constrain them, but they should be considered when the client
  layer is designed.
- **Shared types.** A Rust UI in the same repository can reuse the API types, which reduces drift
  between the API and the UI.
- **Existing UIs.** Neither the React UI nor the Console POC is removed or changed by this ADR. Any
  migration or removal is a separate change, taken when the Rust UI covers the required functionality.

## Consequences

- The Console POC remains in the default build of `main`, with `patternfly-yew` and its npm-provided
  assets, until a separate change removes it or ports it to PFE. It is not intended for release
  branches. This ADR does not remove it, and documentation must keep describing it as present on
  `main`.
- The project does not adopt `patternfly-yew` for any release. New Rust UI work targets PFE.
- The React UI continues to ship at `/`, including in release branches, in the meantime.
- A coverage matrix for the whole planned migration and a prototype are produced before the decision
  becomes final. The decision is not accepted on the strength of the prototype alone.
- The project avoids owning a PatternFly component library for Rust.
- The project accepts a dependency on PFE's PF6 roadmap and coverage.
- The long-term effect on the React UI (keep, freeze or retire) is left to a later ADR.
- If the validation fails, the project stays on its current split, or reconsiders the alternatives
  above.

