# Snapshots for tests

Some tests require not only a database, but also an imported dataset. Depending on the dataset, the import can run
for several minutes, even hours, before the actual test runs. In order to speed this up, it is possible to leverage
BTRFS' subvolumes and snapshots.

The idea is to run the import once, but then, before running tests, create a snapshot of it. Tests then run against
a freshly instantiated snapshot from that import. This takes seconds rather than minutes or hours.

## Requirements

* Run on Linux, with BTRFS available
* Have the `btrfs` command line tool installed
* Have a BTRFS volume mounted, with the following options: `defaults,user,exec,user_subvol_rm_allowed`
* Set `TRUST_TEST_BTRFS_STORE` to a directory which is on such a volume, otherwise the current working directory is used, which must be on a BTRFS volume with those options

If the requirements are not met, tests will automatically fall back to creating a temporary directory per test and
run import operations every time. This is slower, but still does run tests.

## Maintenance

It may happen that, at the end of a run, subvolumes don't get cleaned up. You can check using the following command:

```bash
sudo btrfs subvolume list .
```

Subvolumes in `templates` are expected to be kept, while the ones in `running` and `prepare` are expected to be
short-lived and removed after a test was run.

## Alternatives

The temporary directory will be the system temporary directory, but can be overridden by using the `TMPDIR` variable.
