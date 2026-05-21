"""DHCP 诊断：本机客户端状态 + 多 DHCP 服务器（污染）探测。"""

from network_diagnosis.dhcp.engine import run_dhcp_diagnosis
from network_diagnosis.dhcp.models import DhcpDiagnosisResult

__all__ = ["DhcpDiagnosisResult", "run_dhcp_diagnosis"]
