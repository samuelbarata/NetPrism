import pytest
from unittest.mock import patch, MagicMock
from click.testing import CliRunner
from netprism.main import cli
import re

DEBUG = False
DEFAULT_ARGS = ["-t", "tests/netprism.clab.yaml"]
if DEBUG:
    DEFAULT_ARGS += ["--debug"]

DEVICE_INFO = {
    "dc1dcgw1": {"vendor": "Nokia", "model": "7750 SR-1", "serial_number": "vSIM", "os_version": "B-24.7.R2", "uptime": "15:02:26.930000"},
    "dc1dcgw2": {"vendor": "Nokia", "model": "7750 SR-1", "serial_number": "vSIM", "os_version": "B-24.7.R2", "uptime": "15:02:40.260000"},
    "dc2dcgw1": {"vendor": "Nokia", "model": "7750 SR-1", "serial_number": "vSIM", "os_version": "B-24.7.R2", "uptime": "15:02:27.810000"},
    "leaf1dc1": {"vendor": "Nokia", "model": "7220 IXR-D2L", "serial_number": "Sim Serial No.", "os_version": "v24.10.1-492-gf8858c5836", "uptime": "15:03:16.053000"},
    "leaf1dc2": {"vendor": "Nokia", "model": "7220 IXR-D2L", "serial_number": "Sim Serial No.", "os_version": "v24.10.1-492-gf8858c5836", "uptime": "15:03:19.510000"},
    "leaf2dc1": {"vendor": "Nokia", "model": "7220 IXR-D2L", "serial_number": "Sim Serial No.", "os_version": "v24.10.1-492-gf8858c5836", "uptime": "15:03:13.659000"},
    "leaf2dc2": {"vendor": "Nokia", "model": "7220 IXR-D2L", "serial_number": "Sim Serial No.", "os_version": "v24.10.1-492-gf8858c5836", "uptime": "15:03:14.222000"},
    "leaf3dc1": {"vendor": "Nokia", "model": "7220 IXR-D2L", "serial_number": "Sim Serial No.", "os_version": "v24.10.1-492-gf8858c5836", "uptime": "15:03:14.826000"},
    "leaf4dc1": {"vendor": "Nokia", "model": "7220 IXR-D2L", "serial_number": "Sim Serial No.", "os_version": "v24.10.1-492-gf8858c5836", "uptime": "15:03:11.579000"},
    "pe30":     {"vendor": "Nokia", "model": "7750 SR-1", "serial_number": "vSIM", "os_version": "B-24.7.R2", "uptime": "15:02:43.710000"},
    "provider1": {"vendor": "Nokia", "model": "7750 SR-1", "serial_number": "vSIM", "os_version": "B-24.7.R2", "uptime": "15:02:34.450000"},
    "provider2": {"vendor": "Nokia", "model": "7750 SR-1", "serial_number": "vSIM", "os_version": "B-24.7.R2", "uptime": "15:02:28.240000"},
    "provider3": {"vendor": "Nokia", "model": "7750 SR-1", "serial_number": "vSIM", "os_version": "B-24.7.R2", "uptime": "15:02:32.060000"},
    "provider4": {"vendor": "Nokia", "model": "7750 SR-1", "serial_number": "vSIM", "os_version": "B-24.7.R2", "uptime": "15:02:37.270000"},
    "provider5": {"vendor": "Nokia", "model": "7750 SR-1", "serial_number": "vSIM", "os_version": "B-24.7.R2", "uptime": "15:02:36.140000"},
    "spine1dc1": {"vendor": "Nokia", "model": "7220 IXR-D3L", "serial_number": "Sim Serial No.", "os_version": "v24.10.1-492-gf8858c5836", "uptime": "15:03:21.913000"},
    "spine1dc2": {"vendor": "Nokia", "model": "7220 IXR-D3L", "serial_number": "Sim Serial No.", "os_version": "v24.10.1-492-gf8858c5836", "uptime": "15:03:21.359000"},
    "spine2dc1": {"vendor": "Nokia", "model": "7220 IXR-D3L", "serial_number": "Sim Serial No.", "os_version": "v24.10.1-492-gf8858c5836", "uptime": "15:03:18.654000"},
}

@pytest.fixture
def mock_napalm_get():
    """Fixture to mock the napalm_get method with device-specific data."""

    def fake_napalm_get(task, getters):
        hostname = task.host.name
        facts = DEVICE_INFO.get(hostname)
        if facts is None:
            raise ValueError(f"No mock data defined for host '{hostname}'")
        return {"facts": facts}

    with patch("netprism.main.napalm_get") as mock:
        mock.side_effect = fake_napalm_get
        yield mock

def parse_sys_info_output(output: str) -> list[dict]:
    """Extract device info rows from sys-info CLI output."""
    rows = []
    for line in output.splitlines():
        if re.match(r"\s+\w", line) and "│" in line:
            parts = [part.strip() for part in line.split("│")]
            if len(parts) == 6:
                if parts[0] == "Node":
                    continue
                rows.append({
                    "Node": parts[0],
                    "Vendor": parts[1],
                    "Model": parts[2],
                    "Serial Number": parts[3],
                    "Software Version": parts[4],
                    "Uptime": parts[5],
                })
    return rows

def test_site_wan1_filter(mock_napalm_get):
    INV_FILTER = ['--inv-filter', 'site=wan1']
    EXPECTED_DEVICES = [
        "dc1dcgw1",
        "dc1dcgw2",
        "dc2dcgw1",
    ]
    runner = CliRunner(mix_stderr=False)
    result = runner.invoke(cli, DEFAULT_ARGS + INV_FILTER + ["sys-info"])

    assert result.exit_code == 0
    assert result.output is not None

    parsed_output = parse_sys_info_output(result.output)
    assert len(parsed_output) == len(EXPECTED_DEVICES), "Output row count does not match expected count"
    for line in result.output.splitlines():
        if "Remaining hosts:" in line:
            for device in EXPECTED_DEVICES:
                assert device in line, f"Expected device '{device}' not found in output"
        if "Filtered inventory with" in line:
            assert "{'site': ['wan1']}" in line, "Filter not found in output"

def test_site_dc1_filter(mock_napalm_get):
    INV_FILTER = ['--inv-filter', 'site=dc1']
    EXPECTED_DEVICES = [
        "leaf1dc1",
        # "leaf1dc2",
        "leaf2dc1",
        # "leaf2dc2",
        "leaf3dc1",
        "leaf4dc1",
        "spine1dc1",
        # "spine1dc2",
        "spine2dc1",
    ]
    runner = CliRunner(mix_stderr=False)
    result = runner.invoke(cli, DEFAULT_ARGS + INV_FILTER + ["sys-info"])

    assert result.exit_code == 0
    assert result.output is not None

    parsed_output = parse_sys_info_output(result.output)
    assert len(parsed_output) == len(EXPECTED_DEVICES), "Output row count does not match expected count"
    for line in result.output.splitlines():
        if "Remaining hosts:" in line:
            for device in EXPECTED_DEVICES:
                assert device in line, f"Expected device '{device}' not found in output"
        if "Filtered inventory with" in line:
            assert "{'site': ['dc1']}" in line, "Filter not found in output"

def test_site_leaf_filter(mock_napalm_get):
    INV_FILTER = ['--inv-filter', 'role=leaf']
    EXPECTED_DEVICES = [
        "leaf1dc1",
        "leaf1dc2",
        "leaf2dc1",
        "leaf2dc2",
        "leaf3dc1",
        "leaf4dc1",
        # "spine1dc1",
        # "spine1dc2",
        # "spine2dc1",
    ]
    runner = CliRunner(mix_stderr=False)
    result = runner.invoke(cli, DEFAULT_ARGS + INV_FILTER + ["sys-info"])

    assert result.exit_code == 0
    assert result.output is not None

    parsed_output = parse_sys_info_output(result.output)
    assert len(parsed_output) == len(EXPECTED_DEVICES), "Output row count does not match expected count"
    for line in result.output.splitlines():
        if "Remaining hosts:" in line:
            for device in EXPECTED_DEVICES:
                assert device in line, f"Expected device '{device}' not found in output"
        if "Filtered inventory with" in line:
            assert "{'role': ['leaf']}" in line, "Filter not found in output"

def test_site_spine_filter(mock_napalm_get):
    INV_FILTER = ['--inv-filter', 'role=spine']
    EXPECTED_DEVICES = [
        # "leaf1dc1",
        # "leaf1dc2",
        # "leaf2dc1",
        # "leaf2dc2",
        # "leaf3dc1",
        # "leaf4dc1",
        "spine1dc1",
        "spine1dc2",
        "spine2dc1",
    ]
    runner = CliRunner(mix_stderr=False)
    result = runner.invoke(cli, DEFAULT_ARGS + INV_FILTER + ["sys-info"])

    assert result.exit_code == 0
    assert result.output is not None

    parsed_output = parse_sys_info_output(result.output)
    assert len(parsed_output) == len(EXPECTED_DEVICES), "Output row count does not match expected count"
    for line in result.output.splitlines():
        if "Remaining hosts:" in line:
            for device in EXPECTED_DEVICES:
                assert device in line, f"Expected device '{device}' not found in output"
        if "Filtered inventory with" in line:
            assert "{'role': ['spine']}" in line, "Filter not found in output"

def test_site_wan1_dc1_hostnames_filter(mock_napalm_get):
    INV_FILTER = ['--inv-filter', 'site=wan1', '--inv-filter', 'site=provider', '--inv-filter', 'hostname=provider1', '--inv-filter', 'hostname=dc1dcgw1', '--inv-filter', 'hostname=provider4', '--inv-filter', 'hostname=leaf1dc1', '--inv-filter', 'hostname=spine1dc2']
    EXPECTED_DEVICES = [
        "dc1dcgw1",
        # "dc1dcgw2",
        # "dc2dcgw1",
        "provider1",
        # "provider2",
        # "provider3",
        "provider4",
        # "provider5",
        # "leaf1dc1",
        # "leaf1dc2",
        # "leaf2dc1",
        # "leaf2dc2",
        # "leaf3dc1",
        # "leaf4dc1",
        # "spine1dc1",
        # "spine1dc2",
        # "spine2dc1",
    ]
    runner = CliRunner(mix_stderr=False)
    result = runner.invoke(cli, DEFAULT_ARGS + INV_FILTER + ["sys-info"])

    assert result.exit_code == 0
    assert result.output is not None

    parsed_output = parse_sys_info_output(result.output)
    assert len(parsed_output) == len(EXPECTED_DEVICES), "Output row count does not match expected count"
    for line in result.output.splitlines():
        if "Remaining hosts:" in line:
            for device in EXPECTED_DEVICES:
                assert device in line, f"Expected device '{device}' not found in output"
        if "Filtered inventory with" in line:
            assert "'hostname': ['provider1', 'dc1dcgw1', 'provider4', 'leaf1dc1', 'spine1dc2']" in line, "Filter not found in output"
            assert "'site': ['wan1', 'provider']" in line, "Filter not found in output"
