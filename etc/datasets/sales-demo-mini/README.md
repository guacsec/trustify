# Sales Demo Dataset (Compact)

A compact demo dataset with 49 SBOMs and matching vulnerability data.
Use this for fast ingestion during live demos.

For the full dataset with RHEL SBOMs and broader advisory coverage, see `sales-demo/`.

## Contents

| Type | Count | Size |
|------|-------|------|
| SBOMs (SPDX, bz2) | 49 | ~57 MB |
| CSAF/VEX advisories | ~86 | ~37 MB |
| CVE records | ~52 | <1 MB |
| OSV advisories | ~52 | <1 MB |

**Total size:** ~95 MB

## Products Covered

### Core demo products
- **RHTPA 3.0** — Trusted Profile Analyzer
- **RHACS 4.10** — Advanced Cluster Security
- **Quarkus 3.27 / 3.33** — Java framework
- **Quay 3.18** — Container registry
- **OpenShift GitOps 1.21** — Argo CD operator
- **OpenShift Pipelines 1.15** — Tekton operator
- **RHEL AI 3.4** — RHEL for AI workloads

### Older versions for vulnerability comparison
- **RHTPA 2.2**, **RHACS 4.9**, **Quay 3.9 / 3.10 / 3.12**
- **GitOps 1.19 / 1.20**, **Pipelines 1.20 / 1.21**

### Flagship Red Hat products
- **OpenShift 4.12 / 4.16 / 4.18 / 4.22** — full platform lifecycle
- **RHEL 7 ELS** — legacy with many CVEs
- **Ansible Automation Platform 2.4 / 2.5 / 2.7**
- **Ceph Storage 4 / 5.3 / 7.1 / 8.1** — storage lifecycle
- **JBoss EAP 7.4 / 8.1**, **JWS 5 / 6** — middleware
- **Red Hat Build of Keycloak 26.4 / 26.6** — identity
- **RHTAS 1.3 / 1.4** — artifact signing
- **CNV 4.12 / 4.16 / 4.20** — virtualization
- **RHACM 2.11 / 2.14** — cluster management
- **AMQ Broker 7.13 / 7.14** — messaging
- **RHOAI 2.25 / 3.3** — AI/ML platform
- **Satellite 6.16**, **Developer Hub 1.9**, **Logging 6.0**

## Loading

```shell
pushd etc/datasets/sales-demo-mini
zip -r ../sales-demo-mini.zip . -x '*.DS_Store'
popd
http POST localhost:8080/api/v3/dataset @etc/datasets/sales-demo-mini.zip
```
