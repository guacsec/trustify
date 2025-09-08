# Generating SBOMs From Container Images Using Syft

## Using the Container

**Prerequisites:**

* `podman`
* [`config.json`](https://github.com/google/go-containerregistry/tree/main/pkg/authn#docker-config-auth)
  in the current working directory
* `TPA_SERVICE_URL`, holding the URL to the running TPA service, e.g.
  `my.tpa.instance.abc:8765`
* `TPA_AUTH_TOKEN`, holding the valid authorization token, e.g.
  `Bearer XXXXXXXXXX`

**Running:**

```
# Assume `images.txt` is a list of images (one image per line) in the current
# working directory

# Generate SBOMs from `images.txt` and ingest them:
podman run --rm -v "${PWD}":/gensbom:Z -e 'TPA_*' gensbom:latest images.txt
```

**Output:**

* `${PWD}/sboms` directory with the generated SBOMs
* `${PWD}/sboms.zip` archive with the generated SBOMs

## Using the Script

**Prerequisites:**

* `awk`
* Bash
* `curl`
* `sha512sum`
* [`syft`](https://github.com/anchore/syft/releases)
* `zip`
* [`config.json`](https://github.com/google/go-containerregistry/tree/main/pkg/authn#docker-config-auth)
  in the current working directory
* `TPA_SERVICE_URL`, holding the URL to the running TPA service, e.g.
  `my.tpa.instance.abc:8765`
* `TPA_AUTH_TOKEN`, holding the valid authorization token, e.g.
  `Bearer XXXXXXXXXX`

**Running:**

```
# Assume `images.txt` is a list of images (one image per line) in the current
# working directory

# Generate SBOMs from `images.txt` and ingest them:
./gensbom.sh images.txt
```

**Output:**

* Same as in the previous case

## Troubleshooting

### Where Can I Get the `config.json` file?

For Quay.io:

1. Log in to your account
1. Go to your user profile
1. Click `Account Settings`
1. Click `Generate Encrypted Password`
1. Select `Docker Configuration`
1. Click `Download {your_username}-auth.json`
1. Run `mv {path-to-the-downloaded-file} config.json`

For other container image registries the process may be similar.

> [!WARNING]
> Every time you generate encrypted password to your Quay.io account, do not
> forget to update also `config.json`.

## Developer Section

### Building the Container Image

1. `cd` to the directory with the `Containerfile`
1. Run `podman build -t gensbom -f Containerfile .`

The `Containerfile` build arguments:

* `SYFT_REGISTRY`, holding the container registry from which the `syft`
  container is pulled (default: `ghcr.io/anchore`)
* `SYFT_IMAGE`, holding the `syft` container image name (default: `syft`)
* `SYFT_TAG`, holding the `syft` container image tag (default: `latest`)

## References

* [Docker Config Auth](https://github.com/google/go-containerregistry/tree/main/pkg/authn#docker-config-auth)
* [Syft](https://github.com/anchore/syft)
* [Syft: Private Registry Authentication](https://github.com/anchore/syft/wiki/private-registry-authentication)
