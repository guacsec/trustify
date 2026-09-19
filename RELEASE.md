# Release cheatsheet

The CI handles most of the release process. All that is required is pushing a tag in the form of `v{semver}`. Where
`{semver}` is a semantic version (e.g. `0.1.3`). This may include a pre-release part (e.g. `0.1.3-alpha.1`).

> [!IMPORTANT]
> The CI will check if the version of the tag matches the version of the crates. If they don't align, the release build
> will fail. See below for more information.

## What we promise

Right now everything is in flux. We do not make any promises on the API (internal Rust APIs or external HTTP APIs).

We simply release `0.x` versions as we see fit. And it is ok to directly go from an `alpha` pre-release to a proper
release. We don't honor the semver promises (sorry).

Right now, we use the following pre-release modifiers (this might change in the future):

* `alpha` – for any pre-release
* `rc` – for something we plan to properly release

We also don't publish to crates.io, only release a tag, binary artifacts and container images.

For `1.0.0` and beyond, this should work differently. Maybe even before. However, there are no plans for that yet.

## Performing the release

### 1. Prepare release (automated)

The [prepare-release](https://github.com/guacsec/trustify/actions/workflows/prepare-release.yaml) workflow automates
the release preparation. It bumps versions, updates dependencies, and regenerates schemas and the OpenAPI spec.

1. Go to [Actions → prepare-release](https://github.com/guacsec/trustify/actions/workflows/prepare-release.yaml)
2. Click **"Run workflow"**
3. Select the target branch (`main` or a `release/*` branch)
4. Choose the bump type (`rc`, `patch`, `minor`, `alpha`, `beta`) or provide a full version override
5. Click **"Run workflow"**

The workflow creates a PR against the selected branch. Review, pass CI, and merge.

> [!NOTE]
> On `release/*` branches, only `alpha`, `beta`, `rc`, and `patch` bumps are allowed. Minor bumps would break the
> release stream.

> [!NOTE]
> Only maintainers can trigger this workflow.

### 2. Update release branch

* Cherry-pick the commits from the release preparation PR to the release branch
* Update the versions again, ensuring that `trustify-ui` gets updated from the corresponding release branch
* Create (and merge) another PR against the release branch

### 3. Tag and publish

Switch to release branch and make sure your local checkout is up-to-date.
```shell
> git switch release/<stream>
> git fetch --all
> git rebase upstream/<stream>
```

Create (signed) tag.
```shell
> git tag -S v0.0.0-alpha.1
```

Push tag, which triggers GitHub release workflow.
```shell
> git push upstream v0.0.0-alpha.1
```
Congratulations, the release is now building - [monitor](https://github.com/guacsec/trustify/actions) the outcome!

## Manual release preparation (fallback)

If the automated workflow is unavailable, you can prepare the release manually.

### Prerequisites

* You have some common developer tools for Rust installed (e.g. `cargo`, `git`)
* Your local `main` branch is in sync with the upstream `main` branch. The git remote for upstream is named `upstream`.
* There's a `release/<stream>` branch (e.g. `release/0.3.z`) which is up to date:
    * This includes having backported all relevant changes to this branch
* You have `cargo release` installed. This can be done using `cargo install cargo-release`.

### Steps

Switch to main branch and make sure your local checkout is up-to-date.
```shell
> git switch main
> git fetch --all
> git rebase upstream/main
```

Checkout branch to prepare release from.
```shell
> git checkout -b prepare/0.0.0-alpha.1
```

Dry run to check that we can safely bump release.
```shell
> cargo release version 0.0.0-alpha.1
```

If all looks good bump release.
```shell
> cargo release version 0.0.0-alpha.1 -x
```

Ensure Cargo dependencies are up-to-date.
```shell
> cargo update
```

Normal lint check and ensure openapi up-to-date.
```shell
> cargo xtask precommit
```

Commit (and sign) changes.
```shell
> git commit -S -a -m"chore: prepare release 0.0.0-alpha.1"
```

Push commit.
```shell
> git push upstream prepare/0.0.0-alpha.1
```

Raise a PR, pass CI, review and merge.

## If things go wrong

### Unaligned versions

If the current crate versions have already been released, then you need to bump the versions upfront.

### Broken stuff

Technically, it is possible to make changes to the tag and just force-push it again.

However, in most cases, it might be easier to accept defeat and try again with a new version.

## Test/personal release

To test, you can push a release tag to your personal fork of the repository. By default, this will run the release
workflow in your personal repository, and create a release there. If that's ok for your fork, you can push and force
push tags as you like, to fix and test the release process.

## Branches and Cargo.toml

When branching off a "release branch" change the `Cargo.toml` files as follows:

Replace:

```cargo
trustify-ui = { git = "https://github.com/guacsec/trustify-ui.git", branch = "publish/main" }
```

by:

```cargo
trustify-ui = { git = "https://github.com/guacsec/trustify-ui.git", branch = "release/x.y.z" }
```
