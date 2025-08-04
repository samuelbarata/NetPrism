from netprism.custom_napalm.srlinux import CustomSRLDriver, SRLAPIPatched
from netprism.custom_napalm.sros import CustomSROSDriver
from netprism.napalm_traceroute import napalm_traceroute

try:
    import napalm_srl
    import napalm_sros
    import netprism
    import sys

    napalm_srl.NokiaSRLDriver = netprism.CustomSRLDriver
    napalm_sros.NokiaSROSDriver = netprism.CustomSROSDriver

    sys.modules["napalm_srlinux"] = napalm_srl

except ImportError as e:
    print(f"WARNING: napalm-srl not available: {e}")

__all__ = [
    "CustomSRLDriver",
    "CustomSROSDriver",
    "napalm_traceroute",
]
