import pytest
from unittest.mock import patch, MagicMock
from click.testing import CliRunner
from netprism.main import cli

DEBUG = False
DEFAULT_ARGS = ["-t", "/home/samuelbarata/labs/dci-netprism-lab/netprism.clab.yaml", "--cert-file", "/home/samuelbarata/labs/dci-netprism-lab/clab-netprism-demo/.tls/ca/ca.pem"]
if DEBUG:
    DEFAULT_ARGS += ["--debug"]

@pytest.fixture
def mock_napalm_get():
    """Fixture to mock the napalm_get method."""
    with patch("nornir_napalm.plugins.tasks.napalm_get") as mock:
        mock.return_value = MagicMock(
            result={
                "facts": {
                    "vendor": "Nokia",
                    "model": "SR Linux",
                    "serial_number": "12345",
                    "os_version": "21.11",
                    "uptime": 3600,
                    "hostname": "test-device",
                    "fqdn": "test-device.local",
                    "interface_list": ["eth0", "eth1"],
                }
            }
        )
        yield mock

def test_sys_info(mock_napalm_get):
    """Test the sys_info command."""
    runner = CliRunner(mix_stderr=False)
    result = runner.invoke(cli, DEFAULT_ARGS + ["sys-info"])

    # Verify the CLI output
    assert result.exit_code == 0
    assert result.output is not None

    print(result.output)


