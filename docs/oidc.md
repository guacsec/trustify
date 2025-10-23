# OIDC

By default, Trustify requires an OIDC server. You will need to understand OIDC and set up a secure instance.

There are a few options to make your life easier. However, they all have some implications.

## Development Keycloak

You can start the pre-configured Keycloak instance using podman compose:

```bash
podman compose -f etc/deploy/compose/compose.yaml -f etc/deploy/compose/compose-sso.yaml up
```

Use the `--devmode` flag to start the server with the default values.

> [!WARNING]
> This setup contains well-known credentials, which are not secure!

> [!NOTE]
> If you encounter the error `/init-sso/init.sh: Permission denied`, make sure to set the `SELINUX_VOLUME_OPTIONS` variable to `:Z`


### GitHub Identity Provider

In order to configure GitHub as an external Identity Provider, the init scripts allow setting the `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET` environment variables.
If present, the integration will be configured at startup.

Make sure to create an [OAuth App](https://github.com/settings/developers) in GitHub beforehand.

- Use the Client ID as `GITHUB_CLIENT_ID`
- Generate a Client Secret and use it as `GITHUB_CLIENT_SECRET`
- Homepage URL: `http://localhost:8080/`
- Authorization callback URL: `http://localhost:8090/realms/trustify/broker/github/endpoint`

## Embedded OIDC server

You can enable an embedded OIDC server instead of using an external one.

> [!CAUTION]
> The embedded OIDC server is just a mock server. This may be ok for demo purposes, but it is a serious security issue
> in most other cases.

It needs to be enabled during compilation using `--features pm` and can then be enabled using the `--embedded-oidc`
flag. Enabling the feature will automatically enable it when running in "PM mode".

## Disable authentication

You can start `trustd` with `--disable-auth` option disable authentication altogether.

> [!CAUTION]
> Disabling authentication may be ok for demo purposes, but it is a serious security issue in most other cases.

## External Keycloak

If you want to authenticate with an existing Keycloak instance, configure the following parameters to integrate the server with your OIDC provider.

|Env Var|CLI param|Description|
|-------|---------|-----------|
|`AUTHENTICATOR_OIDC_CLIENT_IDS`|`authentication-client-id`|Comma-separated list of client IDs for authentication with the OIDC provider.|
|`AUTHENTICATOR_OIDC_ISSUER_URL`|`authentication-issuer-url`|The base URL of the OIDC provider used to request access tokens.|
|`AUTHENTICATOR_OIDC_REQUIRED_AUDIENCE`|`authentication-required-audience`|Specifies an expected audience that must be present in access tokens.|
|`AUTHENTICATOR_OIDC_TLS_INSECURE`|`authentication-tls-insecure`|**(Insecure)** Allow connections to the OIDC provider without verifying TLS certificates. **Only use for testing.**|
|`AUTHENTICATOR_OIDC_TLS_CA_CERTIFICATES`|`authentication-tls-certificate`|Path(s) to additional CA certificates for validating the OIDC provider. Supports multiple values (comma-separated).|
|`AUTH_CONFIGURATION`|`auth-configuration`|Path to an external authentication/authorization configuration file. Cannot be used with individual authentication parameters.|

### Using a dedicated configuration file

When using `--auth-configuration`, you must specify a JSON configuration file.
Unlike the CLI-based configuration, the `scopeMappings` field must be explicitly defined in the file.
The CLI alternative provides predefined scope mappings that cannot be customized.

```json
{
  "disabled": false, // default value
  "authentication": {
    "clients": [
      {
        "clientId": "frontend",
        "issuerUrl": "http://localhost:8090/realms/trustify",
        "scopeMappings": {
          "create:document": [
            "create.advisory",
            "create.importer",
            "create.metadata",
            "create.sbom",
            "create.weakness",
            "upload.dataset"
          ],
          "read:document": [
            "ai",
            "read.advisory",
            "read.importer",
            "read.metadata",
            "read.sbom",
            "read.weakness",
            "read.systemInformation",
          ],
          "update:document": [
            "update.advisory",
            "update.importer",
            "update.metadata",
            "update.sbom",
            "update.weakness"
          ],
          "delete:document": [
            "delete.advisory",
            "delete.importer",
            "delete.metadata",
            "delete.sbom",
            "delete.vulnerability",
            "delete.weakness"
          ]
        }
      }
    ]
  }
}
```
