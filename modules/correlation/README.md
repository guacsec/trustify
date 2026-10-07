# Correlation

Links SBOM components to advisory vulnerability assertions through evidence,
then resolves the evidence into verdicts.

See [ADR 00022](../../docs/adrs/00022-correlation-engine.md) for the design.

## API

### Get correlation verdicts for an SBOM

```shell
http GET localhost:8080/api/v3/correlation/sbom/{sbom_id}
```

Example:

```shell
http GET localhost:8080/api/v3/correlation/sbom/550e8400-e29b-41d4-a716-446655440000
```

### Query advisories by identifier

```shell
http GET localhost:8080/api/v3/correlation/query kind==cpe q=='cpe:2.3:o:wago:wago_os_linux:4.8.9:*:*:*:*:*:*:*'
```

CPEs are matched against the CPE patterns (and version ranges) of advisories.
CPE 2.2 URIs (`cpe:/o:wago:wago_os_linux:4.8.9`) are accepted as well.
