import pytest
from unittest.mock import patch, MagicMock
from click.testing import CliRunner
from netprism.main import cli
import re

DEBUG = False
DEFAULT_ARGS = ["-t", "tests/netprism.clab.yaml"]
if DEBUG:
    DEFAULT_ARGS += ["--debug", "--no-wrap"]

# Internal-to-display header mapping
HEADERS = {
    'vendor': 'Vendor',
    'model': 'Model',
    'serial_number': 'Serial Number',
    'os_version': 'Software Version',
    'uptime': 'Uptime',
}

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

def test_sys_info(mock_napalm_get):
    runner = CliRunner(mix_stderr=False)
    result = runner.invoke(cli, DEFAULT_ARGS + ["sys-info"])

    assert result.exit_code == 0
    assert result.output is not None

    parsed_output = parse_sys_info_output(result.output)

    expected_rows = []
    for name, info in DEVICE_INFO.items():
        row = {"Node": name}
        for internal_key, display_key in HEADERS.items():
            row[display_key] = info[internal_key]
        expected_rows.append(row)

    parsed_output_sorted = sorted(parsed_output, key=lambda x: x['Node'])
    expected_rows_sorted = sorted(expected_rows, key=lambda x: x['Node'])

    assert len(parsed_output) == len(expected_rows), "Output row count does not match expected count"
    assert parsed_output_sorted == expected_rows_sorted, "The parsed output does not match the expected output."
