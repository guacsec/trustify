# Analysis Graph

## Get a root component

```bash
http localhost:8080/api/v3/analysis/root-component/B
```

## Get a component

With the name `B`:

```bash
http localhost:8080/api/v3/analysis/component/B
```

With the PURL ``:

```bash
http localhost:8080/api/v3/analysis/component/B
```

## Status

You can get information about the graph status using:

```bash
http localhost:8080/api/v3/analysis/status
```

You can also request more details using:

```bash
http localhost:8080/api/v3/analysis/status?details=true
```
