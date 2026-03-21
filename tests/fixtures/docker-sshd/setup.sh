#!/bin/bash
# Install tools needed by E2E tests on the test SSH container.
# This script runs as a custom-cont-init.d script in linuxserver/openssh-server.

set -e

apk add --no-cache \
    procps \
    net-tools \
    coreutils \
    findutils \
    iproute2 \
    bind-tools \
    curl \
    git \
    bash

# Create test directory for E2E tests
mkdir -p /tmp/mcp-ssh-bridge-tests
chown 1000:1000 /tmp/mcp-ssh-bridge-tests

echo "E2E test environment ready."
