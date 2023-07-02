"""Tests for the AsusWrt integration."""

from unittest.mock import AsyncMock

from pyasuswrt.asuswrt import AsusWrtError
import pytest

from homeassistant.components.asuswrt.const import DOMAIN, FLOW_VERSION, PROTOCOL_HTTPS
from homeassistant.config_entries import ConfigEntryState
from homeassistant.const import (
    CONF_HOST,
    CONF_PASSWORD,
    CONF_PROTOCOL,
    CONF_USERNAME,
    EVENT_HOMEASSISTANT_STOP,
)
from homeassistant.core import HomeAssistant

from .common import (
    CONFIG_DATA_HTTP,
    CONFIG_DATA_SSH,
    CONFIG_DATA_TELNET,
    ROUTER_MAC_ADDR,
)

from tests.common import MockConfigEntry


async def test_protocol_migration_legacy(
    hass: HomeAssistant, connect_legacy, connect_http
) -> None:
    """Test AsusWRT integration migration configuration with http fail."""
    config_entry = MockConfigEntry(
        domain=DOMAIN,
        data=CONFIG_DATA_TELNET,
        unique_id=ROUTER_MAC_ADDR,
        version=1,
    )
    config_entry.add_to_hass(hass)

    connect_http.return_value.async_connect = AsyncMock(side_effect=AsusWrtError)
    connect_http.return_value.is_connected = False

    assert await hass.config_entries.async_setup(config_entry.entry_id)
    await hass.async_block_till_done()

    assert config_entry.state is ConfigEntryState.LOADED
    assert config_entry.version == FLOW_VERSION
    assert config_entry.data == CONFIG_DATA_TELNET


@pytest.mark.parametrize(
    "config",
    [CONFIG_DATA_TELNET, CONFIG_DATA_HTTP],
)
async def test_protocol_migration_http(
    hass: HomeAssistant, connect_http, config
) -> None:
    """Test AsusWRT integration migration configuration with http success."""
    config_entry = MockConfigEntry(
        domain=DOMAIN,
        data=config,
        unique_id=ROUTER_MAC_ADDR,
        version=1,
    )
    config_entry.add_to_hass(hass)

    assert await hass.config_entries.async_setup(config_entry.entry_id)
    await hass.async_block_till_done()

    assert config_entry.state is ConfigEntryState.LOADED
    assert config_entry.version == FLOW_VERSION
    assert config_entry.data[CONF_HOST] == config[CONF_HOST]
    assert config_entry.data[CONF_USERNAME] == config[CONF_USERNAME]
    assert config_entry.data[CONF_PASSWORD] == config[CONF_PASSWORD]
    assert config_entry.data[CONF_PROTOCOL] == PROTOCOL_HTTPS


async def test_protocol_migration_ssh_key(hass: HomeAssistant) -> None:
    """Test AsusWRT integration migration configuration with ssh key."""
    config_entry = MockConfigEntry(
        domain=DOMAIN,
        data=CONFIG_DATA_SSH,
        unique_id=ROUTER_MAC_ADDR,
        version=1,
    )
    config_entry.add_to_hass(hass)

    assert not await hass.config_entries.async_setup(config_entry.entry_id)
    await hass.async_block_till_done()

    assert config_entry.state is ConfigEntryState.SETUP_ERROR
    assert any(config_entry.async_get_active_flows(hass, {"reauth"}))
    assert config_entry.version == 1


async def test_disconnect_on_stop(hass: HomeAssistant, connect_http) -> None:
    """Test we close the connection with the router when Home Assistants stops."""
    config_entry = MockConfigEntry(
        domain=DOMAIN,
        data=CONFIG_DATA_HTTP,
        unique_id=ROUTER_MAC_ADDR,
        version=FLOW_VERSION,
    )
    config_entry.add_to_hass(hass)
    await hass.config_entries.async_setup(config_entry.entry_id)
    await hass.async_block_till_done()

    assert config_entry.state is ConfigEntryState.LOADED

    hass.bus.async_fire(EVENT_HOMEASSISTANT_STOP)
    await hass.async_block_till_done()

    assert connect_http.return_value.async_disconnect.call_count == 1
