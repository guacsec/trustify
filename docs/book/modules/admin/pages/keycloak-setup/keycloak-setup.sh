#!/bin/bash

# Helper function for kcadm
kcadm() {
  local cmd="$1"
  shift
  "$KCADM_PATH" "$cmd" "$@" --config /tmp/kcadm.config
}

# Error handling helper
die() {
  echo "$*" 1>&2
  exit 1
}

# Usage function
usage() {
  cat <<EOF
Usage: $0 [OPTIONS]

Required options:
  --kcadm-path PATH              Path to kcadm.sh script
  --keycloak-url URL             Keycloak server URL
  --keycloak-admin USER          Keycloak admin username
  --keycloak-admin-password PWD  Keycloak admin password
  --base-hostname HOSTNAME       Base application domain for redirect URIs
  --init-data PATH               Directory containing client JSON files

Optional options:
  --namespace NAMESPACE          Namespace for the application (used in redirect URIs)
  --sso-frontend-url URL         External URL for Keycloak (if different from internal)
  --trusted-admin-username USER  RHTPA admin username (default: admin)
  --trusted-admin-password PWD   RHTPA admin password (default: admin123456)
  --cli-client-secret SECRET     CLI service account secret (auto-generated if not provided)
  --testing-manager-secret SEC   Testing-manager service account secret (auto-generated if not provided)
  --testing-user-secret SECRET   Testing-user service account secret (auto-generated if not provided)
  --show-secrets                 Display auto-generated secrets in stdout (insecure, for debugging only)
  --help                         Display this help message

Example:
  $0 --kcadm-path /path/to/kcadm.sh \\
     --keycloak-url https://sso.example.com \\
     --keycloak-admin admin \\
     --keycloak-admin-password secret \\
     --base-hostname apps.example.com \\
     --namespace tpa \\
     --init-data /path/to/client-json
EOF
  exit 0
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --kcadm-path)
      KCADM_PATH="$2"
      shift 2
      ;;
    --keycloak-url)
      KEYCLOAK_URL="$2"
      shift 2
      ;;
    --keycloak-admin)
      KEYCLOAK_ADMIN="$2"
      shift 2
      ;;
    --keycloak-admin-password)
      KEYCLOAK_ADMIN_PASSWORD="$2"
      shift 2
      ;;
    --base-hostname)
      BASE_HOSTNAME="$2"
      shift 2
      ;;
    --init-data)
      INIT_DATA="$2"
      shift 2
      ;;
    --namespace)
      NAMESPACE="$2"
      shift 2
      ;;
    --sso-frontend-url)
      SSO_FRONTEND_URL="$2"
      shift 2
      ;;
    --trusted-admin-username)
      TRUSTED_ADMIN_USERNAME="$2"
      shift 2
      ;;
    --trusted-admin-password)
      TRUSTED_ADMIN_PASSWORD="$2"
      shift 2
      ;;
    --cli-client-secret)
      CLI_CLIENT_SECRET="$2"
      shift 2
      ;;
    --testing-manager-secret)
      TESTING_MANAGER_SECRET="$2"
      shift 2
      ;;
    --testing-user-secret)
      TESTING_USER_SECRET="$2"
      shift 2
      ;;
    --show-secrets)
      SHOW_SECRETS=true
      shift
      ;;
    --help)
      usage
      ;;
    *)
      echo "Unknown option: $1"
      usage
      ;;
  esac
done

# --- Configuration Variables ---
# Set defaults for optional parameters
REALM="${REALM:-trust}"
TRUSTD_ROLE_NAME="${TRUSTD_ROLE_NAME:-trustd}"
NAMESPACE="${NAMESPACE:-}"
SSO_FRONTEND_URL="${SSO_FRONTEND_URL:-}"
TRUSTED_ADMIN_USERNAME="${TRUSTED_ADMIN_USERNAME:-admin}"
TRUSTED_ADMIN_PASSWORD="${TRUSTED_ADMIN_PASSWORD:-admin123456}"
CLI_CLIENT_SECRET="${CLI_CLIENT_SECRET:-}"
TESTING_MANAGER_SECRET="${TESTING_MANAGER_SECRET:-}"
TESTING_USER_SECRET="${TESTING_USER_SECRET:-}"
SHOW_SECRETS="${SHOW_SECRETS:-false}"

# Validate required parameters
if [[ -z "$KCADM_PATH" ]]; then
  die "Error: --kcadm-path is required"
fi

if [[ -z "$KEYCLOAK_URL" ]]; then
  die "Error: --keycloak-url is required"
fi

if [[ -z "$KEYCLOAK_ADMIN" ]]; then
  die "Error: --keycloak-admin is required"
fi

if [[ -z "$KEYCLOAK_ADMIN_PASSWORD" ]]; then
  die "Error: --keycloak-admin-password is required"
fi

if [[ -z "$BASE_HOSTNAME" ]]; then
  die "Error: --base-hostname is required"
fi

if [[ -z "$INIT_DATA" ]]; then
  die "Error: --init-data is required"
fi

# Create secure output file for generated secrets
SECRET_OUTPUT="/tmp/keycloak-secrets-$$.txt"

# Auto-generate secure secrets if not provided
if [[ -z "$CLI_CLIENT_SECRET" ]]; then
  CLI_CLIENT_SECRET=$(openssl rand -hex 32)
  echo "CLI_CLIENT_SECRET=$CLI_CLIENT_SECRET" >> "$SECRET_OUTPUT"
  if [[ "$SHOW_SECRETS" == "true" ]]; then
    echo "Generated CLI_CLIENT_SECRET: $CLI_CLIENT_SECRET"
  else
    echo "Generated CLI_CLIENT_SECRET (saved securely)"
  fi
fi

if [[ -z "$TESTING_MANAGER_SECRET" ]]; then
  TESTING_MANAGER_SECRET=$(openssl rand -hex 32)
  echo "TESTING_MANAGER_SECRET=$TESTING_MANAGER_SECRET" >> "$SECRET_OUTPUT"
  if [[ "$SHOW_SECRETS" == "true" ]]; then
    echo "Generated TESTING_MANAGER_SECRET: $TESTING_MANAGER_SECRET"
  else
    echo "Generated TESTING_MANAGER_SECRET (saved securely)"
  fi
fi

if [[ -z "$TESTING_USER_SECRET" ]]; then
  TESTING_USER_SECRET=$(openssl rand -hex 32)
  echo "TESTING_USER_SECRET=$TESTING_USER_SECRET" >> "$SECRET_OUTPUT"
  if [[ "$SHOW_SECRETS" == "true" ]]; then
    echo "Generated TESTING_USER_SECRET: $TESTING_USER_SECRET"
  else
    echo "Generated TESTING_USER_SECRET (saved securely)"
  fi
fi

# Secure the secrets file if any secrets were generated
if [[ -f "$SECRET_OUTPUT" ]]; then
  chmod 600 "$SECRET_OUTPUT"
  echo ""
  echo "⚠️  Auto-generated secrets have been saved to: $SECRET_OUTPUT"
  echo "⚠️  Please store these securely and delete the file after retrieval."
  echo ""
fi

# Exit cleanly on interrupt
trap 'echo ""; echo "Script interrupted by user. Exiting..."; exit 130' INT

while ! kcadm config credentials --server "$KEYCLOAK_URL" --realm master --user "$KEYCLOAK_ADMIN" --password "$KEYCLOAK_ADMIN_PASSWORD" &> /dev/null; do
  echo "Waiting for Keycloak to start up..."
  sleep 5
done

echo "Keycloak ready"

# Create/update realm
REALM_OPTS=()
REALM_OPTS+=(-s enabled=true)
REALM_OPTS+=(-s "displayName=Trusted Content")
REALM_OPTS+=(-s registrationAllowed=true)
REALM_OPTS+=(-s resetPasswordAllowed=true)
REALM_OPTS+=(-s loginWithEmailAllowed=false)

# if Keycloak has an internal name, set the external name here
if [[ -n "$SSO_FRONTEND_URL" ]]; then
  REALM_OPTS+=(-s "attributes.frontendUrl=${SSO_FRONTEND_URL}")
fi

if kcadm get "realms/${REALM}" &> /dev/null; then
  # exists -> update
  kcadm update "realms/${REALM}" "${REALM_OPTS[@]}"
else
  # need to create
  kcadm create realms -s "realm=${REALM}" "${REALM_OPTS[@]}"
fi

# Create realm roles
kcadm create roles -r "$REALM" -s name="$TRUSTD_ROLE_NAME" || true
# add TRUSTD_ROLE_NAME as default role
kcadm add-roles -r "$REALM" --rname "default-roles-${REALM}" --rolename "$TRUSTD_ROLE_NAME"

MANAGER_ID=$(kcadm get roles -r "$REALM" --fields id,name --format csv --noquotes | grep ",$TRUSTD_ROLE_NAME" | cut -d, -f1)

# Create scopes
# shellcheck disable=SC2043
for i in read:document; do
  kcadm create client-scopes -r "$REALM" -s "name=$i" -s protocol=openid-connect || true
done

for i in create:document update:document delete:document; do
  kcadm create client-scopes -r "$REALM" -s "name=$i" -s protocol=openid-connect || true
  ID=$(kcadm get client-scopes -r "$REALM" --fields id,name --format csv --noquotes | grep ",${i}" | cut -d, -f1)
  # add all scopes to the TRUSTD_ROLE_NAME role
  kcadm create "client-scopes/${ID}/scope-mappings/realm" -r "$REALM" -b '[{"name":"'"$TRUSTD_ROLE_NAME"'", "id":"'"${MANAGER_ID}"'"}]' || true
done

# Create frontend client (public client)
ID=$(kcadm get clients -r "$REALM" --query exact=true --query "clientId=frontend" --fields id --format csv --noquotes)
CLIENT_OPTS=()
CLIENT_OPTS+=(-s "redirectUris=[\"https://server-${NAMESPACE}.${BASE_HOSTNAME}\",\"https://server-${NAMESPACE}.${BASE_HOSTNAME}/*\"]")
if [[ -n "$ID" ]]; then
  kcadm delete "clients/${ID}" -r "$REALM"
  kcadm create clients -r "$REALM" -f "${INIT_DATA}/client-frontend.json" "${CLIENT_OPTS[@]}"
else
  kcadm create clients -r "$REALM" -f "${INIT_DATA}/client-frontend.json" "${CLIENT_OPTS[@]}"
fi

# Create service account clients
for client in cli testing-manager testing-user; do
  ID=$(kcadm get clients -r "$REALM" --query exact=true --query "clientId=${client}" --fields id --format csv --noquotes)
  CLIENT_OPTS=()
  if [[ -n "$ID" ]]; then
    kcadm delete "clients/${ID}" -r "$REALM"
    kcadm create clients -r "$REALM" -f "${INIT_DATA}/client-${client}.json" "${CLIENT_OPTS[@]}"
  else
    kcadm create clients -r "$REALM" -f "${INIT_DATA}/client-${client}.json" "${CLIENT_OPTS[@]}"
  fi
  # now set the client-secret and roles
  ID=$(kcadm get clients -r "$REALM" --query exact=true --query "clientId=${client}" --fields id --format csv --noquotes)
  if [ "${client}" == "cli" ]; then
    kcadm add-roles -r "$REALM" --uusername service-account-${client} --rolename "$TRUSTD_ROLE_NAME"
    kcadm update "clients/${ID}" -r "$REALM" -s "secret=${CLI_CLIENT_SECRET}"
  fi
  if [ "${client}" == "testing-manager" ]; then
    kcadm add-roles -r "$REALM" --uusername service-account-${client} --rolename "$TRUSTD_ROLE_NAME"
    kcadm update "clients/${ID}" -r "$REALM" -s "secret=${TESTING_MANAGER_SECRET}"
  fi
  if [ "${client}" == "testing-user" ]; then
    kcadm add-roles -r "$REALM" --uusername service-account-${client} --rolename "$TRUSTD_ROLE_NAME"
    kcadm update "clients/${ID}" -r "$REALM" -s "secret=${TESTING_USER_SECRET}"
  fi
done
# Create user
ID=$(kcadm get users -r "$REALM" --query exact=true --query "username=$TRUSTED_ADMIN_USERNAME" --fields id --format csv --noquotes)
# the next check might seem weird, but that's just Keycloak reporting a "user not found" in two different ways
if [[ -n "$ID" && "$ID" != "[]" ]]; then
  kcadm update "users/$ID" -r "$REALM" -s enabled=true
else
  kcadm create users -r "$REALM" -s "username=$TRUSTED_ADMIN_USERNAME" -s enabled=true -s email=test@example.com -s emailVerified=true -s firstName=Admin -s lastName=Admin
fi

# set role
kcadm add-roles -r "$REALM" --uusername "$TRUSTED_ADMIN_USERNAME" --rolename "$TRUSTD_ROLE_NAME"

# set password
ID=$(kcadm get users -r "$REALM" --query exact=true --query "username=$TRUSTED_ADMIN_USERNAME" --fields id --format csv --noquotes)
kcadm update "users/${ID}/reset-password" -r "$REALM" -s type=password -s "value=${TRUSTED_ADMIN_PASSWORD}" -s temporary=false -n

echo Keycloak initialization complete
