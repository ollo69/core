"""Fixtures for Asuswrt component."""

from unittest.mock import AsyncMock, Mock, patch

from pyasuswrt.asuswrt import AsusWrtError
import pytest

from homeassistant.components.asuswrt.const import PROTOCOL_HTTP, PROTOCOL_SSH

from .common import ASUSWRT_BASE, MOCK_MACS, ROUTER_MAC_ADDR, new_device

ASUSWRT_HTTP_LIB = f"{ASUSWRT_BASE}.bridge.AsusWrtHttp"
ASUSWRT_LEGACY_LIB = f"{ASUSWRT_BASE}.bridge.AsusWrtLegacy"

MOCK_BYTES_TOTAL = [60000000000, 50000000000]
MOCK_BYTES_TOTAL_HTTP = dict(enumerate(MOCK_BYTES_TOTAL))
MOCK_CPU_USAGE = {"cpu1_usage": 0.1, "cpu2_usage": 0.2, "cpu_total_usage": 0.1}
MOCK_CURRENT_TRANSFER_RATES = [20000000, 10000000]
MOCK_CURRENT_TRANSFER_RATES_HTTP = dict(enumerate(MOCK_CURRENT_TRANSFER_RATES))
MOCK_LOAD_AVG_HTTP = {"load_avg_1": 1.1, "load_avg_5": 1.2, "load_avg_15": 1.3}
MOCK_LOAD_AVG = list(MOCK_LOAD_AVG_HTTP.values())
MOCK_MEMORY_USAGE = {
    "mem_usage_perc": 52.4,
    "mem_total": 1048576,
    "mem_free": 393216,
    "mem_used": 655360,
}
MOCK_TEMPERATURES_HTTP = {"2.4GHz": 40.2, "CPU": 71.2}
MOCK_TEMPERATURES = {**MOCK_TEMPERATURES_HTTP, "5.0GHz": 0}


@pytest.fixture(name="patch_setup_entry")
def mock_controller_patch_setup_entry():
    """Mock setting up a config entry."""
    with patch(
        f"{ASUSWRT_BASE}.async_setup_entry", return_value=True
    ) as setup_entry_mock:
        yield setup_entry_mock


@pytest.fixture(name="mock_devices_legacy")
def mock_devices_legacy_fixture():
    """Mock a list of devices."""
    return {
        MOCK_MACS[0]: new_device(PROTOCOL_SSH, MOCK_MACS[0], "192.168.1.2", "Test"),
        MOCK_MACS[1]: new_device(PROTOCOL_SSH, MOCK_MACS[1], "192.168.1.3", "TestTwo"),
    }


@pytest.fixture(name="mock_devices_http")
def mock_devices_http_fixture():
    """Mock a list of devices."""
    return {
        MOCK_MACS[0]: new_device(PROTOCOL_HTTP, MOCK_MACS[0], "192.168.1.2", "Test"),
        MOCK_MACS[1]: new_device(PROTOCOL_HTTP, MOCK_MACS[1], "192.168.1.3", "TestTwo"),
    }


@pytest.fixture(name="mock_available_temps")
def mock_available_temps_fixture():
    """Mock a list of available temperature sensors."""
    return [True, False, True]


@pytest.fixture(name="connect_legacy")
def mock_controller_connect_legacy(mock_devices_legacy, mock_available_temps):
    """Mock a successful connection with legacy library."""
    with patch(ASUSWRT_LEGACY_LIB) as service_mock:
        service_mock.return_value.connection.async_connect = AsyncMock()
        service_mock.return_value.is_connected = True
        service_mock.return_value.connection.disconnect = Mock()
        service_mock.return_value.async_get_nvram = AsyncMock(
            return_value={
                "label_mac": ROUTER_MAC_ADDR,
                "model": "abcd",
                "firmver": "efg",
                "buildno": "123",
            }
        )
        service_mock.return_value.async_get_connected_devices = AsyncMock(
            return_value=mock_devices_legacy
        )
        service_mock.return_value.async_get_mesh_nodes = AsyncMock(return_value=None)
        service_mock.return_value.async_get_bytes_total = AsyncMock(
            return_value=MOCK_BYTES_TOTAL
        )
        service_mock.return_value.async_get_current_transfer_rates = AsyncMock(
            return_value=MOCK_CURRENT_TRANSFER_RATES
        )
        service_mock.return_value.async_get_loadavg = AsyncMock(
            return_value=MOCK_LOAD_AVG
        )
        service_mock.return_value.async_get_temperature = AsyncMock(
            return_value=MOCK_TEMPERATURES
        )
        service_mock.return_value.async_find_temperature_commands = AsyncMock(
            return_value=mock_available_temps
        )
        yield service_mock


@pytest.fixture(name="connect_http")
def mock_controller_connect_http(mock_devices_http):
    """Mock a successful connection with http library."""
    with patch(ASUSWRT_HTTP_LIB) as service_mock:
        service_mock.return_value.async_connect = AsyncMock()
        service_mock.return_value.is_connected = True
        service_mock.return_value.mac = ROUTER_MAC_ADDR
        service_mock.return_value.model = "FAKE_MODEL"
        service_mock.return_value.firmware = "FAKE_FIRMWARE"
        service_mock.return_value.async_disconnect = AsyncMock()
        service_mock.return_value.async_get_connected_devices = AsyncMock(
            return_value=mock_devices_http
        )
        service_mock.return_value.async_get_cpu_usage = AsyncMock(
            return_value=MOCK_CPU_USAGE
        )
        service_mock.return_value.async_get_memory_usage = AsyncMock(
            return_value=MOCK_MEMORY_USAGE
        )
        service_mock.return_value.async_get_traffic_bytes = AsyncMock(
            return_value=MOCK_BYTES_TOTAL_HTTP
        )
        service_mock.return_value.async_get_traffic_rates = AsyncMock(
            return_value=MOCK_CURRENT_TRANSFER_RATES_HTTP
        )
        service_mock.return_value.async_get_loadavg = AsyncMock(
            return_value=MOCK_LOAD_AVG_HTTP
        )
        service_mock.return_value.async_get_temperatures = AsyncMock(
            return_value=MOCK_TEMPERATURES_HTTP
        )
        yield service_mock


@pytest.fixture(name="connect_legacy_sens_fail")
def mock_controller_connect_legacy_sens_fail():
    """Mock a successful connection using legacy library with sensors fail."""
    with patch(ASUSWRT_LEGACY_LIB) as service_mock:
        service_mock.return_value.connection.async_connect = AsyncMock()
        service_mock.return_value.is_connected = True
        service_mock.return_value.connection.disconnect = Mock()
        service_mock.return_value.async_get_nvram = AsyncMock(side_effect=OSError)
        service_mock.return_value.async_get_connected_devices = AsyncMock(
            side_effect=OSError
        )
        service_mock.return_value.async_get_mesh_nodes = AsyncMock(return_value=None)
        service_mock.return_value.async_get_bytes_total = AsyncMock(side_effect=OSError)
        service_mock.return_value.async_get_current_transfer_rates = AsyncMock(
            side_effect=OSError
        )
        service_mock.return_value.async_get_loadavg = AsyncMock(side_effect=OSError)
        service_mock.return_value.async_get_temperature = AsyncMock(side_effect=OSError)
        service_mock.return_value.async_find_temperature_commands = AsyncMock(
            return_value=[True, True, True]
        )
        yield service_mock


@pytest.fixture(name="connect_http_sens_fail")
def mock_controller_connect_http_sens_fail():
    """Mock a successful connection using http library with sensors fail."""
    with patch(ASUSWRT_HTTP_LIB) as service_mock:
        service_mock.return_value.async_connect = AsyncMock()
        service_mock.return_value.is_connected = True
        service_mock.return_value.mac = None
        service_mock.return_value.model = "FAKE_MODEL"
        service_mock.return_value.firmware = "FAKE_FIRMWARE"
        service_mock.return_value.async_disconnect = AsyncMock()
        service_mock.return_value.async_get_connected_devices = AsyncMock(
            side_effect=AsusWrtError
        )
        service_mock.return_value.async_get_cpu_usage = AsyncMock(
            side_effect=AsusWrtError
        )
        service_mock.return_value.async_get_memory_usage = AsyncMock(
            side_effect=AsusWrtError
        )
        service_mock.return_value.async_get_traffic_bytes = AsyncMock(
            side_effect=AsusWrtError
        )
        service_mock.return_value.async_get_traffic_rates = AsyncMock(
            side_effect=AsusWrtError
        )
        service_mock.return_value.async_get_loadavg = AsyncMock(
            side_effect=AsusWrtError
        )
        service_mock.return_value.async_get_temperatures = AsyncMock(
            side_effect=AsusWrtError
        )
        yield service_mock


@pytest.fixture(name="connect_http_sens_detect")
def mock_controller_connect_http_sens_detect():
    """Mock a successful sensor detection using http library."""
    with patch(
        f"{ASUSWRT_BASE}.bridge.AsusWrtHttpBridge._get_available_temperature_sensors",
        return_value=[*MOCK_TEMPERATURES],
    ) as mock_sens_detect:
        yield mock_sens_detect
