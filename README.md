# Trustify

[![ci](https://github.com/guacsec/trustify/actions/workflows/ci.yaml/badge.svg)](https://github.com/guacsec/trustify/actions/workflows/ci.yaml)

Trustify provides a single, searchable abstraction over all cyclonedx/spdx SBOMs - cross referencing against public security advisories to help identify and respond to software security threats & vulnerabilities.

## How Trustify Helps
Trustify tackles some of the problems developers and companies face when keeping software safe and organized. Here’s how it helps:
- Deploy applications with fewer vulnerabilities
- Meet compliance regulations for SBOM management and archiving
- Know that trusted components are in use as early as possible
- Reduce alert fatigue with fewer false positive by getting vendor vulnerability information from the actual vendor (VEX)
- Analyze applications without downloading and installing

## Architecture
Trustify is an evolution of the [Trustification](https://github.com/trustification) project.
We changed the architecture to [modulith](https://dzone.com/articles/architecture-style-modulith-vs-microservices) approach, to build a simpler-to-deploy more responsive system that can flexibly meet the needs of the company and our customers going forward.

The general architecture is as follows:

### The System
- REST APIs to support operations for ingesting and retrieving supply-chain data.
- Comes with a set of default importers to public available vulnerability data

### A single SQL database
- PostgreSQL.
- Extensible data-model to support all aspects of supply-chain data.
- OIDC provider

![image](https://github.com/user-attachments/assets/f251c0ef-9693-485c-9ebd-8deefe2c244c)

## Quick start

Let's call this "PM mode":

```shell
AUTH_DISABLED=true cargo run --bin trustd
```

If you haven't setup your Rust development environment yet, i.e. you
don't have `cargo`, you can alternatively use the latest "trustd-pm"
[release binary](https://github.com/guacsec/trustify/releases).

That will create its own database in your current directory beneath
`.trustify/`.

* To use the **GUI**, navigate to: <http://localhost:8080>.
* To use the **REST API**, navigate to: <http://localhost:8080/openapi/>.

### Data

The app's not much fun without data, e.g. SBOM's and Advisories. There are a few ways to ingest some:

#### Datasets

There are some bundles of related data beneath
[etc/datasets](etc/datasets). You can use any HTTP command line
client, e.g. curl, wget, or [httpie](https://httpie.io/) to ingest a
zipped archive of SBOMs and/or Advisories like so:

```shell
cd etc/datasets
make
http POST localhost:8080/api/v2/dataset @ds1.zip
```

#### Upload

There is an "Upload" menu option in the GUI: http://localhost:8080/upload

You can also interact with the API directly in a shell:

```shell
cat some-sbom.json | http POST localhost:8080/api/v2/sbom
cat some-advisory.json | http POST localhost:8080/api/v2/advisory
```

#### Importers

You may configure importers to regularly fetch data from remote
sites. See [modules/importer/README.md](modules/importer/README.md)
for details.

### Authentication

When testing the app using "PM mode", it may be convenient to set an
environment variable, `AUTH_DISABLED=true`, to bypass all auth checks.

By default, authentication is enabled. It can be disabled using the
flag `--auth-disabled` when running the server.  Also. by default,
there is no working authentication/authorization configuration. For
development purposes, one can use `--devmode` to use the Keycloak
instance deployed with the compose deployment.

Also see: [docs/oidc.md](docs/oidc.md)

HTTP requests must provide the bearer token using the `Authorization`
header. For that, a valid access token is required. There are
tutorials using `curl` on getting such a token. It is also possible
the use the `oidc` client tool:

Installation:

```bash
cargo install oidc-cli
```

Then, set up an initial client (needs to be done every time the client/keycloak instance is re-created):

```bash
oidc create confidential trusty --issuer http://localhost:8090/realms/chicken --client-id walker --client-secret ZVzq9AMOVUdMY1lSohpx1jI3aW56QDPS
```

Then one can perform `http` request using HTTPie like this:

```bash
http localhost:8080/purl/asdf/dependencies Authorization:$(oidc token trusty -b)
```

## Repository Organization

### Sources

#### `common`

Model-like bits shared between multiple contexts.

#### `entity`

Database entity models, implemented via SeaORM.

#### `migration`

SeaORM migrations for the DDL.

#### `modules`

The primary behavior of the application.

#### `server`

The REST API server.

#### `trustd`

The server CLI tool `trustd`

### Et Merde

#### `etc/test-data`

Arbitrary test-data used for unit tests

#### `etc/datasets`

Integrated data bundles that show off the features of the app.

#### `etc/deploy`

Deployment-related (such as `compose`) files.

## Development Environment

### Rust

If you haven't already, [get started!](https://www.rust-lang.org/learn/get-started)

#### If test failures on OSX

Potentially, our concurrent Postgres installations during testing can
exhaust shared-memory.  Adjusting shared-memory on OSX is not
straight-forward.  Use [this
guide](https://unix.stackexchange.com/questions/689295/values-from-sysctl-a-dont-match-etc-sysctl-conf-even-after-restart).

### Postgres

Unit tests and "PM mode" use an embedded instance of Postgres that is
installed as required on the local filesystem. This is convenient for
local development, but you can also configure the app to use an
external database.

Starting a containerized Postgres instance:

```shell
podman-compose -f etc/deploy/compose/compose.yaml up
```

Connect to PSQL:

```shell
env PGPASSWORD=trustify psql -U postgres -d trustify -h localhost -p 5432
```

If you don't have the `psql` command available, you can also use the `podman-compose` command:

```shell
podman-compose -f etc/deploy/compose/compose.yaml exec postgres psql -U postgres -d trustify
```

Point the app at an external db:

```shell
cargo run --bin trustd api --help
RUST_LOG=info cargo run --bin trustd api --db-password trustify --devmode --auth-disabled
```

## Notes on models

### Package

A package exists or it does not. Represented by a pURL. No source-tracking required.

Rework to Package. VersionedPackage. QualifiedVersionedPackage. and VersionRangePackage for vulnerable references.
Plus appropriate junction tables.

### CPE

Platonic form of a product may have 0+ CPEs/pURLs.
Platonic form of a product may have 0+ known hashable artifacts.

### CVE

A CVE exists or it does not. Represented by an identifier. No source-tracking required.

### CWE

A CWE exists or it does not. Represented by an identifier. No source-tracking required.

### Advisory

An Advisory exists or it does not. Represented by a location/hash/identifier.
Source tracked from an Advisory Source.

There is probably always an advisory from NVD for every CVE.

### Advisory Source

Something like GHSA, Red Hat VEX, etc. Maybe?
Based on source URL? Regexp!
Still unsure here.

### Scanners don't exist

They should just point us towards first order advisories to ingest.
OSV just tells us to look elsewhere.
They are helpers not nouns.

### Vulnerable

Package Range + Advisory + CVE.

### NonVulnerable

QualifiedPackage + Advisory + CVE.

Both impl'd for pURL and CPE.

### SBOM

hashed document that claims things about stuff.
All package/product relationships exist only within the context of an SBOM making the claim.

### Describes

CPE (Product?) and/or pURLs described by the SBOM

## Related Projects

* [Trustify user interface](https://github.com/guacsec/trustify-ui)
* [Helm charts used for the Trustify deployment](https://github.com/trustification/trustify-helm-charts)
* [OpenShift Operator used for the Trustify deployment](https://github.com/trustification/trustify-operator)
* [Ansible playbooks used for the Trustify deployment](https://github.com/trustification/trustify-ansible)
* [Trustify API & user interface test suite](https://github.com/trustification/trustify-tests)
* [Trustify load tests runner](https://github.com/trustification/trustify-load-test-runs)
* [Trustify load test suite](https://github.com/trustification/scale-testing)
* [Trustify GitHub CI helpers](https://github.com/trustification/trustify-ci)
* [Trustify release tools](https://github.com/guacsec/trustify-release-tools)
