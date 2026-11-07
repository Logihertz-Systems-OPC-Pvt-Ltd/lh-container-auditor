# ==============================================================================
# Product:       lh-container-auditor (lh-container)
# Module:        tests.conftest
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Shared test fixtures for lh-container-auditor."""

from __future__ import annotations

import pytest


@pytest.fixture
def sample_clean_dockerfile() -> str:
    """Return a hardened, compliant Dockerfile string."""
    return (
        "FROM alpine:3.19.1\n"
        "RUN apk add --no-cache curl ca-certificates\n"
        "USER 10001:10001\n"
        "EXPOSE 8080\n"
        "HEALTHCHECK --interval=30s CMD curl -f http://localhost:8080/health || exit 1\n"
    )


@pytest.fixture
def sample_vulnerable_dockerfile() -> str:
    """Return a Dockerfile with multiple security misconfigurations."""
    return (
        "FROM ubuntu:latest\n"
        "ENV AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE\n"
        "RUN apt-get update && apt-get install -y curl\n"
        "RUN curl -fsSL https://get.docker.com | sh\n"
        "ADD app.tar.gz /app/\n"
        "ADD helper.sh /bin/helper.sh\n"
        "EXPOSE 22 2375\n"
        "RUN echo 'dev ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers\n"
        "RUN chmod 4755 /bin/helper.sh\n"
        "USER root\n"
    )


@pytest.fixture
def sample_compose_yaml() -> str:
    """Return a Docker Compose file with security issues."""
    return """
    services:
      web:
        image: nginx:1.25
        privileged: true
        network_mode: "host"
        volumes:
          - /var/run/docker.sock:/var/run/docker.sock
        ports:
          - "22:22"
        environment:
          - API_KEY=secret_key_12345
    """
