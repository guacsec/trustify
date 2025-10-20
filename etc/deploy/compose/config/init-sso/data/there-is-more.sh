#!/usr/bin/env bash

# This file is "sourced" from `init.sh`, so we can use everything that was declared in there. It is intended to
# add additional configuration which should only be present in a local development or testing deployment.

# reset CLIENT_OPTS, to keep using the same pattern
CLIENT_OPTS=()

# create testing client, as this script is expected to only run in a local developer setup, we ignore the
# re-running aspect
kcadm create clients -r "${REALM}" -f "${INIT_DATA}/client-testing-user.json" "${CLIENT_OPTS[@]}"
kcadm create clients -r "${REALM}" -f "${INIT_DATA}/client-testing-manager.json" "${CLIENT_OPTS[@]}"

# default role for service account of services
kcadm add-roles -r "${REALM}" --uusername service-account-testing-manager --rolename trustify-manager

# create a non-admin user
kcadm create users -r "${REALM}" -s "username=user" -s enabled=true
kcadm add-roles -r "${REALM}" --uusername "user" --rolename trustify-user
ID=$(kcadm get users -r "${REALM}" --query exact=true --query "username=user" --fields id --format csv --noquotes)
kcadm update "users/${ID}/reset-password" -r "${REALM}" -s type=password -s "value=user123456" -s temporary=false -n
