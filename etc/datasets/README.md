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
