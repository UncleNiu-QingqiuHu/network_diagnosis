"""Active Directory 域与组策略（Windows）。"""

from network_diagnosis.domain.collect import fetch_domain_identity, run_domain_diagnosis, run_gpresult
from network_diagnosis.domain.operations import (
    run_gpupdate,
    run_join_domain,
    run_rename_computer,
    run_repair_trust,
    run_unjoin_domain,
)

__all__ = [
    "fetch_domain_identity",
    "run_domain_diagnosis",
    "run_gpresult",
    "run_gpupdate",
    "run_join_domain",
    "run_rename_computer",
    "run_repair_trust",
    "run_unjoin_domain",
]
