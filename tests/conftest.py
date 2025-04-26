import sys
import pytest

@pytest.fixture(scope="session", autouse=True)
def patch_napalm_driver():
    """Patch Python imports so 'napalm_srlinux' points to 'napalm_srl'."""
    try:
        import napalm_srl
        import napalm_sros
        import netprism

        napalm_srl.NokiaSRLDriver = netprism.CustomSRLDriver
        napalm_sros.NokiaSROSDriver = netprism.CustomSROSDriver

        sys.modules["napalm_srlinux"] = napalm_srl

    except ImportError as e:
        print(f"WARNING: napalm-srl not available: {e}")
