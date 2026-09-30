# Datasets

## DS1

The original.

Create it:

```shell
rm ds1.zip
pushd ds1
zip -r ../ds1.zip .
popd
```

## DS2

An OSV based example for generating dumps. Used in combination with `cargo xtask generate-dump`

## DS3

A variant of DS1, including the corresponding CVE files.

```shell
rm ds3.zip
pushd ds3
zip -r ../ds3.zip .
popd
```

You can also create just a collection of SBOMs from this dataset

```shell
make ds3-sboms
```

You can then upload it to the existing instance like

```shell
http POST localhost:8080/api/v3/dataset @etc/datasets/ds3-sboms.zip
```

## DS4

This dataset contains the following data:

* Red Hat SBOMs
* CVEs since 2020
* GHSA since 2020
* Red Hat CSAF since 2020

You can generate database dump based on this, by using the command like

```shell
cargo xtask generate-dump --input etc/datasets/ds4.yaml --output dump-ds4.sql
```

The dump can be loaded to the database like:

```shell
cat dump-ds4.sql | env PGPASSWORD=trustify psql -U postgres -d trustify -h localhost -p 5432 -v ON_ERROR_STOP=1
```

## DS7

Hand-written CycloneDX 1.7 SBOMs. Small enough to read and edit, but between them they
cover the ingestion paths we care about, plus the fields that 1.7 added on top of 1.6
(`component.isExternal`, `component.versionRange`, `component.patentAssertions`,
`metadata.distributionConstraints.tlp`, top-level `citations`,
`algorithmProperties.algorithmFamily` / `.ellipticCurve`, and `relatedCryptographicAssets`).

| File | Covers |
|---|---|
| `acme-application-1.7.json` | purls, CPEs, license expressions, hashes, `evidence.identity`, external components with a `vers` range, patent assertions, citations |
| `acme-container-1.7.json` | container/operating-system/file components, RPM purls, `provides` (→ `GeneratedFrom`), pedigree ancestors and variants |
| `acme-cbom-1.7.json` | cryptographic assets: PQC (ML-KEM, ML-DSA), classical (AES, ECDSA) and weak (RSA-1024, SHA-1) algorithms, a TLS protocol asset, a certificate and key material |
| `acme-aibom-1.7.json` | a `machine-learning-model` component with a model card |
| `acme-licensing-1.7.json` | `LicenseRef` licenses with plain and base64 text, a license expression referring to one, SPDX ids and name-only licenses |

The algorithms in the CBOM are picked so that the PQC policy produces one of each verdict:
ML-KEM/ML-DSA are compliant, RSA-1024 and SHA-1 are non-compliant, AES and ECDSA warn.

Create the archive:

```shell
make -C etc/datasets ds7.zip
```

And upload it to a running instance:

```shell
http POST localhost:8080/api/v3/dataset @etc/datasets/ds7.zip
```
