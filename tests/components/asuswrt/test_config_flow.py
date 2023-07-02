"""Tests for the AsusWrt config flow."""
from socket import gaierror
from unittest.mock import AsyncMock, Mock, patch

from pyasuswrt import AsusWrtError
import pytest

from homeassistant import data_entry_flow
from homeassistant.components.asuswrt.const import (
    CONF_DNSMASQ,
    CONF_INTERFACE,
    CONF_REQUIRE_IP,
    CONF_SSH_KEY,
    CONF_TRACK_UNKNOWN,
    DOMAIN,
    FLOW_VERSION,
    MODE_AP,
    MODE_ROUTER,
    PROTOCOL_HTTP,
    PROTOCOL_HTTPS,
    PROTOCOL_SSH,
    PROTOCOL_TELNET,
)
from homeassistant.components.device_tracker import CONF_CONSIDER_HOME
from homeassistant.config_entries import SOURCE_REAUTH, SOURCE_USER
from homeassistant.const import (
    CONF_BASE,
    CONF_HOST,
    CONF_METHOD,
    CONF_MODE,
    CONF_PASSWORD,
    CONF_PORT,
    CONF_PROTOCOL,
    CONF_USERNAME,
)
from homeassistant.core import HomeAssistant

from .common import ASUSWRT_BASE, HOST, ROUTER_MAC_ADDR

from tests.common import MockConfigEntry

KEY_HTTP = "http"
KEY_LEGACY = "legacy"

IP_ADDRESS = "192.168.1.1"
PWD = "pwd"
SSH_KEY = "1234"

CONFIG_DATA_AUTO = {
    CONF_HOST: HOST,
    CONF_USERNAME: "user",
    CONF_PASSWORD: PWD,
}

CONFIG_DATA = {
    **CONFIG_DATA_AUTO,
    CONF_PORT: 4567,
}

CONFIG_DATA_HTTP = {
    **CONFIG_DATA,
    CONF_PROTOCOL: PROTOCOL_HTTP,
}

CONFIG_DATA_HTTPS = {
    **CONFIG_DATA,
    CONF_PROTOCOL: PROTOCOL_HTTPS,
    CONF_SSH_KEY: SSH_KEY,
}

CONFIG_DATA_SSH = {
    **CONFIG_DATA,
    CONF_PROTOCOL: PROTOCOL_SSH,
}

CONFIG_DATA_TELNET = {
    **CONFIG_DATA,
    CONF_PROTOCOL: PROTOCOL_TELNET,
}


@pytest.fixture(name="patch_get_host")
def mock_controller_patch_get_host():
    """Mock call to socket gethostbyname function."""
    with patch(
        f"{ASUSWRT_BASE}.config_flow.socket.gethostbyname", return_value=IP_ADDRESS
    ) as get_host_mock:
        yield get_host_mock


class ConnectionFake:
    """A fake of the `AsusWrtLegacy.connection` class."""

    def __init__(self, side_effect=None) -> None:
        """Initialize a fake `Connection` instance."""
        self.async_connect = AsyncMock(side_effect=side_effect)
        self.disconnect = Mock()


class AsusWrtLegacyFake:
    """A fake of the `AsusWrtLegacy` class."""

    def __init__(self, mac_addr=None, is_connected=True, side_effect=None) -> None:
        """Initialize a fake `AsusWrtLegacy` instance."""
        self._mac_addr = mac_addr
        self.is_connected = is_connected
        self.connection = ConnectionFake(side_effect)

    async def async_get_nvram(self, info_type):
        """Return nvram information."""
        return {"label_mac": self._mac_addr} if self._mac_addr else None


class AsusWrtHttpFake:
    """A fake of the `AsusWrtHttp` class."""

    def __init__(self, mac_addr=None, is_connected=True, side_effect=None) -> None:
        """Initialize a fake `AsusWrtLegacy` instance."""
        self.mac = mac_addr
        self.model = "FAKE_MODEL"
        self.firmware = "FAKE_FIRWARE"
        self.is_connected = is_connected
        self.async_connect = AsyncMock(side_effect=side_effect)
        self.async_disconnect = AsyncMock()


def patch_asuswrt(mac_addr=None, *, is_connected=True, side_effect=None):
    """Mock the `AsusWrtLegacy` and `AsusWrtHttp` classes."""
    return {
        KEY_LEGACY: patch(
            f"{ASUSWRT_BASE}.bridge.AsusWrtLegacy",
            return_value=AsusWrtLegacyFake(mac_addr, is_connected, side_effect),
        ),
        KEY_HTTP: patch(
            f"{ASUSWRT_BASE}.bridge.AsusWrtHttp",
            return_value=AsusWrtHttpFake(mac_addr, is_connected, side_effect),
        ),
    }


@pytest.mark.parametrize("unique_id", [None, ROUTER_MAC_ADDR])
async def test_user_legacy(
    hass: HomeAssistant, patch_get_host, patch_setup_entry, unique_id
) -> None:
    """Test user config."""
    flow_result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_USER, "show_advanced_options": True}
    )
    assert flow_result["type"] == data_entry_flow.FlowResultType.FORM
    assert flow_result["step_id"] == "user"

    # test with all provided
    with patch_asuswrt(unique_id)[KEY_LEGACY]:
        # go to legacy form
        legacy_result = await hass.config_entries.flow.async_configure(
            flow_result["flow_id"], user_input=CONFIG_DATA_TELNET
        )
        await hass.async_block_till_done()

        assert legacy_result["type"] == data_entry_flow.FlowResultType.FORM
        assert legacy_result["step_id"] == "legacy"

        # complete configuration
        result = await hass.config_entries.flow.async_configure(
            legacy_result["flow_id"], user_input={CONF_MODE: MODE_AP}
        )
        await hass.async_block_till_done()

        assert result["type"] == data_entry_flow.FlowResultType.CREATE_ENTRY
        assert result["title"] == HOST
        assert result["data"] == {**CONFIG_DATA_TELNET, CONF_MODE: MODE_AP}

        assert len(patch_setup_entry.mock_calls) == 1


@pytest.mark.parametrize("unique_id", [None, ROUTER_MAC_ADDR])
async def test_user_http(
    hass: HomeAssistant, patch_get_host, patch_setup_entry, unique_id
) -> None:
    """Test user config http."""
    flow_result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_USER, "show_advanced_options": True}
    )
    assert flow_result["type"] == data_entry_flow.FlowResultType.FORM
    assert flow_result["step_id"] == "user"

    # test with all provided
    with patch_asuswrt(unique_id)[KEY_HTTP]:
        result = await hass.config_entries.flow.async_configure(
            flow_result["flow_id"], user_input=CONFIG_DATA_HTTP
        )
        await hass.async_block_till_done()

        assert result["type"] == data_entry_flow.FlowResultType.CREATE_ENTRY
        assert result["title"] == HOST
        assert result["data"] == CONFIG_DATA_HTTP

        assert len(patch_setup_entry.mock_calls) == 1


@pytest.mark.parametrize("unique_id", [None, ROUTER_MAC_ADDR])
async def test_user_auto_detect(
    hass: HomeAssistant, patch_get_host, patch_setup_entry, unique_id
) -> None:
    """Test user config auto detect."""
    flow_result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_USER}
    )
    assert flow_result["type"] == data_entry_flow.FlowResultType.FORM
    assert flow_result["step_id"] == "user"

    # test with only user and pwd
    with patch_asuswrt(unique_id)[KEY_HTTP]:
        result = await hass.config_entries.flow.async_configure(
            flow_result["flow_id"], user_input=CONFIG_DATA_AUTO
        )
        await hass.async_block_till_done()

        assert result["type"] == data_entry_flow.FlowResultType.CREATE_ENTRY
        assert result["title"] == HOST
        assert result["data"] == {**CONFIG_DATA_AUTO, CONF_PROTOCOL: PROTOCOL_HTTPS}

        assert len(patch_setup_entry.mock_calls) == 1


@pytest.mark.parametrize(
    "config", [CONFIG_DATA_TELNET, CONFIG_DATA_HTTP, CONFIG_DATA_HTTPS]
)
async def test_error_pwd_required(hass: HomeAssistant, config) -> None:
    """Test we abort for missing password."""
    config_data = {**config}
    config_data.pop(CONF_PASSWORD)
    result = await hass.config_entries.flow.async_init(
        DOMAIN,
        context={"source": SOURCE_USER, "show_advanced_options": True},
        data=config_data,
    )

    assert result["type"] == data_entry_flow.FlowResultType.FORM
    assert result["errors"] == {CONF_BASE: "pwd_required"}


@pytest.mark.parametrize(
    ("config", "error"),
    [
        ({CONF_PASSWORD: None}, "pwd_or_ssh"),
        ({CONF_SSH_KEY: SSH_KEY}, "pwd_and_ssh"),
    ],
)
async def test_error_wrong_password_ssh(hass: HomeAssistant, config, error) -> None:
    """Test we abort for wrong password and ssh file combination."""
    config_data = {**CONFIG_DATA_SSH, **config}
    result = await hass.config_entries.flow.async_init(
        DOMAIN,
        context={"source": SOURCE_USER, "show_advanced_options": True},
        data=config_data,
    )

    assert result["type"] == data_entry_flow.FlowResultType.FORM
    assert result["errors"] == {"base": error}


async def test_error_invalid_ssh(hass: HomeAssistant, patch_get_host) -> None:
    """Test we abort if invalid ssh file is provided."""
    config_data = {**CONFIG_DATA_SSH, CONF_SSH_KEY: SSH_KEY}
    config_data.pop(CONF_PASSWORD)

    with patch(
        f"{ASUSWRT_BASE}.config_flow.os.path.isfile",
        return_value=False,
    ):
        result = await hass.config_entries.flow.async_init(
            DOMAIN,
            context={"source": SOURCE_USER, "show_advanced_options": True},
            data=config_data,
        )
        await hass.async_block_till_done()

        assert result["type"] == data_entry_flow.FlowResultType.FORM
        assert result["errors"] == {CONF_BASE: "ssh_not_file"}


async def test_error_invalid_host(hass: HomeAssistant, patch_get_host) -> None:
    """Test we abort if host name is invalid."""
    patch_get_host.side_effect = gaierror

    result = await hass.config_entries.flow.async_init(
        DOMAIN,
        context={"source": SOURCE_USER},
        data=CONFIG_DATA_HTTP,
    )
    await hass.async_block_till_done()

    assert result["type"] == data_entry_flow.FlowResultType.FORM
    assert result["errors"] == {CONF_BASE: "invalid_host"}


async def test_abort_if_not_unique_id_setup(hass: HomeAssistant) -> None:
    """Test we abort if component without uniqueid is already setup."""
    MockConfigEntry(
        domain=DOMAIN,
        data=CONFIG_DATA_HTTP,
        version=FLOW_VERSION,
    ).add_to_hass(hass)

    result = await hass.config_entries.flow.async_init(
        DOMAIN,
        context={"source": SOURCE_USER},
        data=CONFIG_DATA_HTTP,
    )

    assert result["type"] == data_entry_flow.FlowResultType.ABORT
    assert result["reason"] == "no_unique_id"


async def test_update_uniqueid_exist(
    hass: HomeAssistant, patch_get_host, patch_setup_entry
) -> None:
    """Test we update entry if uniqueid is already configured."""
    existing_entry = MockConfigEntry(
        domain=DOMAIN,
        data={**CONFIG_DATA_HTTP, CONF_HOST: "10.10.10.10"},
        unique_id=ROUTER_MAC_ADDR,
        version=FLOW_VERSION,
    )
    existing_entry.add_to_hass(hass)

    with patch_asuswrt(ROUTER_MAC_ADDR)[KEY_HTTP]:
        result = await hass.config_entries.flow.async_init(
            DOMAIN,
            context={"source": SOURCE_USER, "show_advanced_options": True},
            data=CONFIG_DATA_HTTP,
        )
        await hass.async_block_till_done()

        assert result["type"] == data_entry_flow.FlowResultType.CREATE_ENTRY
        assert result["title"] == HOST
        assert result["data"] == CONFIG_DATA_HTTP
        prev_entry = hass.config_entries.async_get_entry(existing_entry.entry_id)
        assert not prev_entry


async def test_abort_invalid_unique_id(hass: HomeAssistant, patch_get_host) -> None:
    """Test we abort if uniqueid not available."""
    MockConfigEntry(
        domain=DOMAIN,
        data=CONFIG_DATA_HTTP,
        unique_id=ROUTER_MAC_ADDR,
        version=FLOW_VERSION,
    ).add_to_hass(hass)

    with patch_asuswrt()[KEY_HTTP]:
        result = await hass.config_entries.flow.async_init(
            DOMAIN,
            context={"source": SOURCE_USER},
            data=CONFIG_DATA_HTTP,
        )
        await hass.async_block_till_done()

        assert result["type"] == data_entry_flow.FlowResultType.ABORT
        assert result["reason"] == "invalid_unique_id"


@pytest.mark.parametrize(
    ("side_effect", "error"),
    [
        (OSError, "cannot_connect"),
        (TypeError, "unknown"),
        (None, "cannot_connect"),
    ],
)
async def test_on_connect_legacy_failed(
    hass: HomeAssistant, patch_get_host, side_effect, error
) -> None:
    """Test when we have errors connecting the router with legacy library."""
    flow_result = await hass.config_entries.flow.async_init(
        DOMAIN,
        context={"source": SOURCE_USER, "show_advanced_options": True},
    )

    with patch_asuswrt(is_connected=False, side_effect=side_effect)[KEY_LEGACY]:
        # go to legacy form
        result = await hass.config_entries.flow.async_configure(
            flow_result["flow_id"], user_input=CONFIG_DATA_TELNET
        )
        await hass.async_block_till_done()

        assert result["type"] == data_entry_flow.FlowResultType.FORM
        assert result["errors"] == {CONF_BASE: error}


@pytest.mark.parametrize(
    ("side_effect", "error"),
    [
        (AsusWrtError, "cannot_connect"),
        (TypeError, "unknown"),
        (None, "cannot_connect"),
    ],
)
async def test_on_connect_http_failed(
    hass: HomeAssistant, patch_get_host, side_effect, error
) -> None:
    """Test when we have errors connecting the router with http library."""
    flow_result = await hass.config_entries.flow.async_init(
        DOMAIN,
        context={"source": SOURCE_USER, "show_advanced_options": True},
    )

    with patch_asuswrt(is_connected=False, side_effect=side_effect)[KEY_HTTP]:
        result = await hass.config_entries.flow.async_configure(
            flow_result["flow_id"], user_input=CONFIG_DATA_HTTP
        )
        await hass.async_block_till_done()

        assert result["type"] == data_entry_flow.FlowResultType.FORM
        assert result["errors"] == {CONF_BASE: error}


async def test_reauth_flow_success(
    hass: HomeAssistant, patch_get_host, patch_setup_entry
) -> None:
    """Test we launch reauth flow after failed authentication during migration."""
    config_data = {**CONFIG_DATA_SSH, CONF_SSH_KEY: SSH_KEY}
    config_data.pop(CONF_PASSWORD)
    existing_entry = MockConfigEntry(
        domain=DOMAIN,
        data=config_data,
        unique_id=ROUTER_MAC_ADDR,
        version=1,
    )
    existing_entry.add_to_hass(hass)

    existing_entry.async_start_reauth(hass)
    await hass.async_block_till_done()

    flows = hass.config_entries.flow.async_progress()
    assert len(flows) == 1
    result = flows[0]
    assert result["step_id"] == "reauth_confirm"
    assert result["context"]["source"] == SOURCE_REAUTH
    assert result["context"]["unique_id"] == ROUTER_MAC_ADDR

    with patch_asuswrt(ROUTER_MAC_ADDR)[KEY_HTTP]:
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"], user_input={CONF_PASSWORD: PWD}
        )
        await hass.async_block_till_done()

        assert result["type"] == data_entry_flow.FlowResultType.ABORT
        assert result["reason"] == "reauth_successful"
        assert existing_entry.data == {
            **CONFIG_DATA_AUTO,
            CONF_PROTOCOL: PROTOCOL_HTTPS,
            CONF_METHOD: "reauth",
        }
        assert existing_entry.version == FLOW_VERSION


async def test_reauth_flow_fail(hass: HomeAssistant, patch_get_host) -> None:
    """Test we launch reauth flow after failed authentication during migration."""
    config_data = {**CONFIG_DATA_SSH, CONF_SSH_KEY: SSH_KEY}
    config_data.pop(CONF_PASSWORD)
    existing_entry = MockConfigEntry(
        domain=DOMAIN,
        data=config_data,
        unique_id=ROUTER_MAC_ADDR,
        version=1,
    )
    existing_entry.add_to_hass(hass)

    existing_entry.async_start_reauth(hass)
    await hass.async_block_till_done()

    flows = hass.config_entries.flow.async_progress()
    assert len(flows) == 1
    result = flows[0]
    assert result["step_id"] == "reauth_confirm"
    assert result["context"]["source"] == SOURCE_REAUTH
    assert result["context"]["unique_id"] == ROUTER_MAC_ADDR

    with patch_asuswrt(is_connected=False, side_effect=AsusWrtError)[KEY_HTTP]:
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"], user_input={CONF_PASSWORD: PWD}
        )
        await hass.async_block_till_done()

        assert result["type"] == data_entry_flow.FlowResultType.ABORT
        assert result["reason"] == "reauth_fallback"
        assert existing_entry.data == {**config_data, CONF_METHOD: "reauth"}
        assert existing_entry.version == FLOW_VERSION


async def test_options_flow_ap(hass: HomeAssistant, patch_setup_entry) -> None:
    """Test config flow options for ap mode."""
    config_entry = MockConfigEntry(
        domain=DOMAIN,
        data={**CONFIG_DATA_TELNET, CONF_MODE: MODE_AP},
        options={CONF_REQUIRE_IP: True},
        version=FLOW_VERSION,
    )
    config_entry.add_to_hass(hass)

    await hass.config_entries.async_setup(config_entry.entry_id)
    await hass.async_block_till_done()
    result = await hass.config_entries.options.async_init(config_entry.entry_id)

    assert result["type"] == data_entry_flow.FlowResultType.FORM
    assert result["step_id"] == "init"
    assert CONF_REQUIRE_IP in result["data_schema"].schema

    result = await hass.config_entries.options.async_configure(
        result["flow_id"],
        user_input={
            CONF_CONSIDER_HOME: 20,
            CONF_TRACK_UNKNOWN: True,
            CONF_INTERFACE: "aaa",
            CONF_DNSMASQ: "bbb",
            CONF_REQUIRE_IP: False,
        },
    )

    assert result["type"] == data_entry_flow.FlowResultType.CREATE_ENTRY
    assert config_entry.options[CONF_CONSIDER_HOME] == 20
    assert config_entry.options[CONF_TRACK_UNKNOWN] is True
    assert config_entry.options[CONF_INTERFACE] == "aaa"
    assert config_entry.options[CONF_DNSMASQ] == "bbb"
    assert config_entry.options[CONF_REQUIRE_IP] is False


async def test_options_flow_router(hass: HomeAssistant, patch_setup_entry) -> None:
    """Test config flow options for router mode."""
    config_entry = MockConfigEntry(
        domain=DOMAIN,
        data={**CONFIG_DATA_TELNET, CONF_MODE: MODE_ROUTER},
        version=FLOW_VERSION,
    )
    config_entry.add_to_hass(hass)

    await hass.config_entries.async_setup(config_entry.entry_id)
    await hass.async_block_till_done()
    result = await hass.config_entries.options.async_init(config_entry.entry_id)

    assert result["type"] == data_entry_flow.FlowResultType.FORM
    assert result["step_id"] == "init"
    assert CONF_REQUIRE_IP not in result["data_schema"].schema

    result = await hass.config_entries.options.async_configure(
        result["flow_id"],
        user_input={
            CONF_CONSIDER_HOME: 20,
            CONF_TRACK_UNKNOWN: True,
            CONF_INTERFACE: "aaa",
            CONF_DNSMASQ: "bbb",
        },
    )

    assert result["type"] == data_entry_flow.FlowResultType.CREATE_ENTRY
    assert config_entry.options[CONF_CONSIDER_HOME] == 20
    assert config_entry.options[CONF_TRACK_UNKNOWN] is True
    assert config_entry.options[CONF_INTERFACE] == "aaa"
    assert config_entry.options[CONF_DNSMASQ] == "bbb"


async def test_options_flow_http(hass: HomeAssistant, patch_setup_entry) -> None:
    """Test config flow options for http mode."""
    config_entry = MockConfigEntry(
        domain=DOMAIN,
        data={**CONFIG_DATA_HTTP, CONF_MODE: MODE_ROUTER},
        version=FLOW_VERSION,
    )
    config_entry.add_to_hass(hass)

    await hass.config_entries.async_setup(config_entry.entry_id)
    await hass.async_block_till_done()
    result = await hass.config_entries.options.async_init(config_entry.entry_id)

    assert result["type"] == data_entry_flow.FlowResultType.FORM
    assert result["step_id"] == "init"
    assert CONF_INTERFACE not in result["data_schema"].schema
    assert CONF_DNSMASQ not in result["data_schema"].schema
    assert CONF_REQUIRE_IP not in result["data_schema"].schema

    result = await hass.config_entries.options.async_configure(
        result["flow_id"],
        user_input={
            CONF_CONSIDER_HOME: 20,
            CONF_TRACK_UNKNOWN: True,
        },
    )

    assert result["type"] == data_entry_flow.FlowResultType.CREATE_ENTRY
    assert config_entry.options[CONF_CONSIDER_HOME] == 20
    assert config_entry.options[CONF_TRACK_UNKNOWN] is True
