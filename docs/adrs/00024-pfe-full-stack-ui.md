# 00024. PatternFly Elements for a Full-Stack Rust UI

Date: 2026-11-04

## Status

PROPOSED

## Context

Trustify is a Rust project, but its production UI uses TypeScript, React, and PatternFly React.
It is maintained in the separate `guacsec/trustify-ui` repository, consumed as the `trustify-ui`
crate, and served at `/`.

The repository also contains a Console proof of concept (POC) using Rust, Yew, and `patternfly-yew`,
integrated with the Actix-based server. It demonstrates a lighter, in-repository approach to building
and serving a UI. Although included in the default build on `main` and served at `/console/`, it is
not the production UI foundation proposed by this ADR.

The POC illustrates both the appeal and the limitations of this approach. Rust enables closer
integration with the backend, but the Rust-specific PatternFly wrapper introduces component-coverage
and maintenance risks. The first-generation Trustification UI also used Yew and `patternfly-yew` in
production and encountered requirements beyond the components available at the time. Relying on this
approach for Trustify's upstream and downstream production UIs would therefore require a
component-development and maintenance commitment that the project is not proposing to undertake.
The limitation is the component layer, not Rust/WebAssembly or the server framework.

This ADR evaluates whether PatternFly Elements can retain the benefits of an integrated Rust UI
while avoiding a Rust-specific PatternFly component library. Its suitability remains subject to the
coverage assessment and prototype validation below.

The current setup has the following problems:

1. **Split tech stack.** The project needs Rust and TypeScript/React skills, two toolchains, two test
   setups and separate backend and UI release flows. The React UI lives in a different repository
   from the API it consumes, so API changes and UI changes cannot be built, tested and released
   together.

2. **Skills mismatch.** The current UI stack (TypeScript/React) overlaps little with the team's
   existing Rust/backend skills. The project has only one full-stack engineer leading the UI, and
   help from additional UI developers has not materialised, so UI maintenance also falls to backend
   engineers working outside their main area of expertise.

3. **npm maintenance burden.** The React UI brings a large transitive npm dependency tree. Keeping it
   free of known vulnerabilities is a recurring, mostly mechanical effort.

4. **Downstream.** Downstream products are aligned with PatternFly. Any change to the UI stack must not
   make the downstream build, support or UX alignment harder.

5. **UX backlog.** The current UI has a backlog of UX improvements and gaps, including information
   users need that is not currently presented. A new UI should be designed around prioritized user
   needs rather than treating the existing React UI as a specification to reproduce page for page.
   This UX work is a product-design concern; choosing PFE does not by itself resolve it.

A Rust/WebAssembly UI removes the second stack, but it needs a component layer that provides the
PatternFly look and feel. The usual answer is a Rust wrapper crate such as `patternfly-yew`. A wrapper
has to follow every PatternFly release, is tied to one Rust UI framework, and is not maintained by the
PatternFly project. In practice only one Trustify contributor is currently working on `patternfly-yew`,
so keeping it current with PatternFly depends on a single person. Using it means either depending on a
library the project does not control or spending UI resources it does not have.

Web components offer another way. They are a browser standard supported by all major browsers
(including Declarative Shadow DOM), they are used by large design systems, and Red Hat publishes the
PatternFly design system as web components: [PatternFly Elements](https://patternflyelements.org)
(PFE). Web components provide a standardized, framework-independent layer for consistent UX. They
should keep the additional learning curve lower than adopting and maintaining a Rust-specific
PatternFly component library. Yew can render PFE elements directly. When a custom-element property
expects a DOM object rather than an HTML attribute, application code can set it with `web-sys` and
`js-sys`, as illustrated here:

```rust
use js_sys::Reflect;
use wasm_bindgen::JsValue;
use web_sys::{Element, HtmlFormElement};
use yew::prelude::*;

#[function_component(PfeForm)]
fn pfe_form() -> Html {
    let form_ref = use_node_ref();
    let button_ref = use_node_ref();

    {
        let form_ref = form_ref.clone();
        let button_ref = button_ref.clone();
        use_effect_with((), move |_| {
            if let (Some(button), Some(form)) = (
                button_ref.cast::<Element>(),
                form_ref.cast::<HtmlFormElement>(),
            ) {
                // Assumes this PFE button exposes a `form` DOM property.
                let _ = Reflect::set(
                    button.as_ref(),
                    &JsValue::from_str("form"),
                    form.as_ref(),
                );
            }
            || ()
        });
    }

    html! {
        <>
            <form ref={form_ref}></form>
            <pf-v6-button ref={button_ref} variant="primary">{"Submit"}</pf-v6-button>
        </>
    }
}
```

This illustrates where application-level glue would live if a PFE component exposed a DOM-object
property. The specific property must be supported by the chosen PFE element; this is illustrative,
not a claim that `pf-v6-button` itself exposes a `form` property. PFE's JavaScript assets must
register the custom element. The prototype and coverage assessment below will validate the actual
PFE integration and component coverage.

This ADR concerns the choice of the component layer for a production Rust UI and the intended,
gated transition from the React UI. It does not itself change existing UIs, put the React UI into
maintenance-only mode, or authorize a default switch or retirement.

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

- **Initial UI scope.** Define the initial user workflows and capabilities for the new UI. This is
  not a page-for-page migration plan: use the existing React UI as a reference for current behaviour
  and functionality, while identifying UX gaps and prioritizing what the new UI should provide.
- **Coverage matrix.** List every PatternFly component needed by the agreed initial UI scope
  (tables, toolbars, filters, modals, select, tabs, pagination, and so on), informed by the existing
  React UI but not limited to its current pages. Mark each one as available in PFE for PF6, available
  with caveats, or missing. For each component that is not fully available, record one of:
  - an acceptable workaround, with its estimated size and the maintainer who owns it, or
  - a fallback (a project-owned component, plain HTML and CSS with PatternFly tokens, or a deferral of
    the feature) that the maintainers have explicitly approved, with the reason, the estimated cost
    and the owner.
  The matrix is reviewed and approved together with this ADR, and its approval is recorded in the
  ADR or linked from it.
- **Prototype.** Build a representative, non-trivial workflow from the agreed initial UI scope with
  PFE and a Rust UI framework. The prototype validates the component layer and integration approach;
  it is not a migration of an existing React page. Include the `web-sys` glue for complex properties,
  authentication and the API client.
- **Build.** Measure CI build time, the size of the Wasm and JS assets, and the first page load.
  Confirm that the build works with the project's offline and downstream build setup.
- **Accessibility and i18n.** Confirm the keyboard, screen reader and localisation behaviour of the
  components used.
- **Roadmap.** Obtain the PatternFly team's PFE roadmap for PF6 coverage.

### Exit criteria

The decision stands if:

- The coverage matrix shows that every component needed for the agreed initial UI scope has
  acceptable PFE coverage, or an explicitly approved fallback. A component without either blocks
  acceptance.
- The total project-owned component work implied by the approved fallbacks is small enough that it
  does not amount to maintaining a PatternFly component library, which is what this ADR sets out to
  avoid. The maintainers state the accepted limit when they approve the matrix.
- The representative prototype demonstrates that the agreed workflow can be implemented with the available PFE components.
- The glue code is limited and does not amount to a de facto component library.
- The build fits into the Trustify build and the downstream build without a JavaScript build.
- Load time and asset size are acceptable.

### Transition strategy

The intended path is a staged replacement of the React UI, conditional on successful validation.
Stages are gated by evidence and recorded approval, not calendar dates. Accepting this ADR validates
the component-layer choice; it does not by itself authorize the later transition gates. Owners,
release milestones, and implementation tasks are tracked separately.

1. **Validate the stack.** Agree the initial workflows, assess component coverage, build the
   representative prototype, and select the Rust UI framework. The React UI remains supported and
   the default throughout validation.
   **Gate:** the maintainers approve the validation evidence and exit criteria above, and the ADR
   moves to ACCEPTED. If validation fails, retain the current production UI and reconsider the stack.

2. **Establish the foundation.** Build the application shell, routing, authentication, API client,
   design conventions, and test/build integration in this repository. Define boundaries between
   shared core services, supported workflows, and opt-in UX experiments without committing to a
   plugin platform. The React UI remains the default.
   **Gate:** a usable, tested foundation has named maintainers, and the preview scope and its
   enablement and support policy are approved by the maintainers and product/UX owners, with
   downstream owners involved where their builds or support are affected.

3. **Deliver an opt-in preview.** Implement prioritized workflows alongside the React UI, document
   limitations, and gather user feedback. Preview access must not change the default UI or prevent
   users from returning to it. Propose maintenance-only status for the React UI at an explicitly
   agreed preview milestone, not automatically on merging or accepting this ADR. That policy must
   name maintainers, identify affected release branches and downstream commitments, and preserve
   security, critical bug, and necessary API-compatibility fixes; new UX work would normally target
   the new UI.
   **Gate:** before crossover, the maintainers, product/UX owners, and affected downstream owners
   approve the replacement scope and readiness evidence described below. Until then, the React UI
   remains the supported default, whether or not maintenance-only status has been approved.

4. **Switch the default.** Make the new UI the supported default only after the crossover gate is
   approved. Publish deployment and user transition guidance and test the rollback path. Agree
   whether the React UI must remain available for a transition period, its duration, and its support
   obligations before switching; upstream and downstream need not switch in the same release.
   **Gate:** the agreed transition obligations are met and affected owners explicitly approve
   retirement in a follow-up decision.

5. **Retire the React UI.** Remove obsolete embedding, dependencies, and build/release work only for
   the approved scope. Communicate the end of support and preserve any obligations for older
   supported branches or downstream releases. Default switching and retirement are separate changes.

The initial validation scope is not automatically the replacement scope. Before crossover, review
required production workflows with product/UX and downstream owners: each must be supported,
deliberately replaced, or explicitly approved for removal or deferral, with user impact documented.
Extend the coverage matrix for the replacement scope and review any additional fallback cost.
Readiness evidence must cover those workflows, authentication and authorization, accessibility and
localisation, build and deployment compatibility, performance, and a tested rollback path. A working
prototype alone is not sufficient. If a later gate is not met, pause the transition rather than
switching or retiring the supported UI.

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
  framework. Adopting the Console's component stack as the production foundation would require a
  component-development and maintenance commitment the project is not proposing to undertake.

### Write and maintain Rust components in Trustify

- Pros: full control.
- Cons: the same maintenance cost as a wrapper crate, with no sharing outside the project.

### Move the React UI into this repository (not considered a realistic option)

- Pros: keeps the UI and API together for building, testing and releasing.
- Cons: this solves only the repository split; it retains the TypeScript/React stack and npm
  maintenance burden, and leaves backend engineers responsible for UI maintenance without a
  dedicated UI team. It is therefore not considered a realistic path forward or an interim step for
  this ADR.

### Provide a CLI instead of a web UI

- Pros: avoids maintaining a browser-based UI and builds on Rust skills already present in the
  project. A CLI can suit scripting, automation and users who prefer terminal workflows.
- Cons: it does not provide the graphical, interactive experience needed by users who rely on a web
  interface, and it would not address the existing web UI's UX needs for those users. A CLI is
  therefore not a substitute for the web UI; it could be considered as a complementary interface.

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

## Consequences

- `patternfly-yew` is not selected as the component layer for the proposed production UI. New
  production Rust UI work targets PFE, subject to validation.
- The React UI continues to ship at `/`, including in release branches, until an approved default
  switch for the affected releases. Preview work does not change this default.
- A coverage matrix for the agreed initial UI scope and a representative prototype are produced
  before the decision becomes final. The decision is not accepted on the strength of the prototype
  alone. This validation does not require migrating the existing React UI.
- The project avoids owning a PatternFly component library for Rust.
- The project accepts a dependency on PFE's PF6 roadmap and coverage.
- The intended React UI replacement follows the transition strategy above. Maintenance-only status,
  default switching, and retirement each require explicit follow-up approval; none is triggered by
  merging or accepting this ADR.
- If the validation fails, the project stays on its current split, or reconsiders the alternatives
  above.

