# ==============================================================================
# Product:       lh-container-auditor (lh-container)
# Module:        src.lh_container_auditor.__init__
# Role:          Package Initialization & Public API Declarations
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""lh-container-auditor: Enterprise container security auditor.

Audits Dockerfile, Docker Compose, and OCI image configurations for security
vulnerabilities, misconfigurations, and supply-chain risks.

Developed by Logihertz Systems (OPC) Private Limited.
"""

from __future__ import annotations

from lh_container_auditor.models import (
    AuditReport,
    Finding,
    FindingCategory,
    FindingSeverity,
    ScanTargetResult,
    TargetType,
)

__version__ = "0.1.0"

__all__ = [
    "AuditReport",
    "Finding",
    "FindingCategory",
    "FindingSeverity",
    "ScanTargetResult",
    "TargetType",
    "__version__",
]
