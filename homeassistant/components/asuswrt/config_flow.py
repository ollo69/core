"""Config flow to configure the AsusWrt integration."""

from __future__ import annotations

from collections.abc import Mapping
import logging
import os
import socket
from typing import Any, cast

from pyasuswrt import AsusWrtError
import voluptuous as vol

from homeassistant.components.device_tracker import (
    CONF_CONSIDER_HOME,
    DEFAULT_CONSIDER_HOME,
)
from homeassistant.config_entries import ConfigEntry, ConfigFlow
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
from homeassistant.core import callback
from homeassistant.data_entry_flow import FlowResult
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.schema_config_entry_flow import (
    SchemaCommonFlowHandler,
    SchemaFlowFormStep,
    SchemaOptionsFlowHandler,
)
from homeassistant.helpers.selector import SelectSelector, SelectSelectorConfig

from .bridge import AsusWrtBridge
from .const import (
    CONF_DNSMASQ,
    CONF_INTERFACE,
    CONF_REQUIRE_IP,
    CONF_SSH_KEY,
    CONF_TRACK_UNKNOWN,
    DEFAULT_DNSMASQ,
    DEFAULT_INTERFACE,
    DEFAULT_TRACK_UNKNOWN,
    DOMAIN,
    FLOW_VERSION,
    MODE_AP,
    MODE_ROUTER,
    PROTOCOL_HTTP,
    PROTOCOL_HTTPS,
    PROTOCOL_SSH,
    PROTOCOL_TELNET,
)

ALLOWED_PROTOCOL = [
    PROTOCOL_HTTPS,
    PROTOCOL_HTTP,
    PROTOCOL_SSH,
    PROTOCOL_TELNET,
]

RESULT_CONN_ERROR = "cannot_connect"
RESULT_SUCCESS = "success"
RESULT_UNKNOWN = "unknown"

_LOGGER = logging.getLogger(__name__)

LEGACY_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_MODE, default=MODE_ROUTER): vol.In(
            {MODE_ROUTER: "Router", MODE_AP: "Access Point"}
        ),
    }
)

OPTIONS_SCHEMA = vol.Schema(
    {
        vol.Optional(
            CONF_CONSIDER_HOME, default=DEFAULT_CONSIDER_HOME.total_seconds()
        ): vol.All(vol.Coerce(int), vol.Clamp(min=0, max=900)),
        vol.Optional(CONF_TRACK_UNKNOWN, default=DEFAULT_TRACK_UNKNOWN): bool,
    }
)


async def get_options_schema(handler: SchemaCommonFlowHandler) -> vol.Schema:
    """Get options schema."""
    options_flow: SchemaOptionsFlowHandler
    options_flow = cast(SchemaOptionsFlowHandler, handler.parent_handler)
    used_protocol = options_flow.config_entry.data[CONF_PROTOCOL]
    if used_protocol in [PROTOCOL_SSH, PROTOCOL_TELNET]:
        data_schema = OPTIONS_SCHEMA.extend(
            {
                vol.Required(CONF_INTERFACE, default=DEFAULT_INTERFACE): str,
                vol.Required(CONF_DNSMASQ, default=DEFAULT_DNSMASQ): str,
            }
        )
        if options_flow.config_entry.data[CONF_MODE] == MODE_AP:
            return data_schema.extend(
                {
                    vol.Optional(CONF_REQUIRE_IP, default=True): bool,
                }
            )
        return data_schema

    return OPTIONS_SCHEMA


OPTIONS_FLOW = {
    "init": SchemaFlowFormStep(get_options_schema),
}


def _is_file(value: str) -> bool:
    """Validate that the value is an existing file."""
    file_in = os.path.expanduser(value)
    return os.path.isfile(file_in) and os.access(file_in, os.R_OK)


def _get_ip(host: str) -> str | None:
    """Get the ip address from the host name."""
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None


class AsusWrtFlowHandler(ConfigFlow, domain=DOMAIN):
    """Handle a config flow for AsusWRT."""

    VERSION = FLOW_VERSION

    def __init__(self) -> None:
        """Initialize the AsusWrt config flow."""
        self._config_data: dict[str, Any] = {}
        self._unique_id: str | None = None
        self._reauth_entry: ConfigEntry | None = None

    @callback
    def _show_setup_form(self, error: str | None = None) -> FlowResult:
        """Show the setup form to the user."""

        user_input = self._config_data

        if self.show_advanced_options:
            add_schema = {
                vol.Optional(CONF_PASSWORD): str,
                vol.Required(
                    CONF_PROTOCOL,
                    default=user_input.get(CONF_PROTOCOL, PROTOCOL_HTTPS),
                ): SelectSelector(
                    SelectSelectorConfig(
                        options=ALLOWED_PROTOCOL, translation_key="protocols"
                    )
                ),
                vol.Optional(CONF_PORT): cv.port,
                vol.Optional(CONF_SSH_KEY): str,
            }
        else:
            add_schema = {vol.Required(CONF_PASSWORD): str}

        schema = {
            vol.Required(CONF_HOST, default=user_input.get(CONF_HOST, "")): str,
            vol.Required(CONF_USERNAME, default=user_input.get(CONF_USERNAME, "")): str,
            **add_schema,
        }

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(schema),
            errors={CONF_BASE: error} if error else None,
        )

    async def _async_check_connection(
        self, user_input: dict[str, Any], allowed_protocol: list[str] | None = None
    ) -> tuple[str, str | None, str | None]:
        """Attempt to connect the AsusWrt router."""

        api: AsusWrtBridge
        host: str = user_input[CONF_HOST]
        error: str | None = None
        valid_protocol: str | None = None

        if CONF_PROTOCOL in user_input:
            protocols: list[str] = [user_input[CONF_PROTOCOL]]
        else:
            protocols = allowed_protocol or ALLOWED_PROTOCOL

        for protocol in protocols:
            conf = {**user_input, CONF_PROTOCOL: protocol, CONF_MODE: MODE_ROUTER}
            api = AsusWrtBridge.get_bridge(self.hass, conf)
            try:
                await api.async_connect()

            except (AsusWrtError, OSError):
                _LOGGER.error(
                    "Error connecting to the AsusWrt router at %s using protocol %s",
                    host,
                    protocol,
                )
                error = RESULT_CONN_ERROR

            except Exception:  # pylint: disable=broad-except
                _LOGGER.exception(
                    "Unknown error connecting with AsusWrt router at %s using protocol %s",
                    host,
                    protocol,
                )
                if error is None:
                    error = RESULT_UNKNOWN

            else:
                valid_protocol = protocol
                error = None

            if error is None:
                if not api.is_connected:
                    _LOGGER.error(
                        "Error connecting to the AsusWrt router at %s using protocol %s",
                        host,
                        protocol,
                    )
                    error = RESULT_CONN_ERROR
                else:
                    break

        if error is not None:
            return error, None, None

        _LOGGER.info(
            "Successfully connected to the AsusWrt router at %s using protocol %s",
            host,
            protocol,
        )
        unique_id = api.label_mac
        await api.async_disconnect()

        return RESULT_SUCCESS, unique_id, valid_protocol

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle a flow initiated by the user."""

        # if there's one entry without unique ID, we abort config flow
        if self._reauth_entry is None:
            for unique_id in self._async_current_ids():
                if unique_id is None:
                    return self.async_abort(reason="no_unique_id")

        if user_input is None:
            return self._show_setup_form()

        protocol: str | None = user_input.get(CONF_PROTOCOL)
        if protocol != PROTOCOL_SSH and CONF_SSH_KEY in user_input:
            user_input.pop(CONF_SSH_KEY)

        self._config_data = user_input
        pwd: str | None = user_input.get(CONF_PASSWORD)
        ssh: str | None = user_input.get(CONF_SSH_KEY)

        if not pwd and protocol != PROTOCOL_SSH:
            return self._show_setup_form(error="pwd_required")
        if not (pwd or ssh):
            return self._show_setup_form(error="pwd_or_ssh")
        if pwd and ssh:
            return self._show_setup_form(error="pwd_and_ssh")
        if ssh:
            if not await self.hass.async_add_executor_job(_is_file, ssh):
                return self._show_setup_form(error="ssh_not_file")

        host: str = user_input[CONF_HOST]
        if not await self.hass.async_add_executor_job(_get_ip, host):
            return self._show_setup_form(error="invalid_host")

        result, unique_id, protocol = await self._async_check_connection(user_input)
        if result == RESULT_SUCCESS:
            self._unique_id = unique_id
            self._config_data = {**user_input, CONF_PROTOCOL: protocol}
            if protocol in [PROTOCOL_SSH, PROTOCOL_TELNET]:
                return await self.async_step_legacy()
            return await self._async_save_entry()

        return self._show_setup_form(error=result)

    async def async_step_legacy(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle a flow for legacy settings."""
        if user_input is None:
            return self.async_show_form(step_id="legacy", data_schema=LEGACY_SCHEMA)

        self._config_data.update(user_input)
        return await self._async_save_entry()

    async def async_step_reauth(self, entry_data: Mapping[str, Any]) -> FlowResult:
        """Perform reauth upon an API authentication error."""
        self._config_data = {
            CONF_HOST: entry_data[CONF_HOST],
            CONF_USERNAME: entry_data[CONF_USERNAME],
        }
        self._reauth_entry = self.hass.config_entries.async_get_entry(
            self.context["entry_id"]
        )
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Dialog that informs the user that reauth is required."""
        if user_input is None:
            return self.async_show_form(
                step_id="reauth_confirm",
                data_schema=vol.Schema({vol.Required(CONF_PASSWORD): str}),
            )

        self._config_data[CONF_PASSWORD] = user_input[CONF_PASSWORD]
        result, _, protocol = await self._async_check_connection(
            self._config_data, [PROTOCOL_HTTPS, PROTOCOL_HTTP]
        )
        if result == RESULT_SUCCESS:
            self._config_data[CONF_PROTOCOL] = protocol
        else:
            # if http reauth fail, we fall back to original configuration
            self._config_data = {}

        return await self._async_save_entry()

    async def _async_save_entry(self) -> FlowResult:
        """Save entry data if unique id is valid."""
        if self._reauth_entry:
            self._reauth_entry.version = self.VERSION
            if not self._config_data:
                self._config_data = dict(self._reauth_entry.data)
                reauth_result = "reauth_fallback"
            else:
                reauth_result = "reauth_successful"
            self._config_data[CONF_METHOD] = "reauth"

            self.hass.config_entries.async_update_entry(
                self._reauth_entry, data=self._config_data
            )
            await self.hass.config_entries.async_reload(self._reauth_entry.entry_id)
            return self.async_abort(reason=reauth_result)

        if self._unique_id:
            await self.async_set_unique_id(self._unique_id)
        # we allow to configure a single instance without unique id
        elif self._async_current_entries():
            return self.async_abort(reason="invalid_unique_id")
        else:
            _LOGGER.warning(
                "This device does not provide a valid Unique ID."
                " Configuration of multiple instance will not be possible"
            )

        return self.async_create_entry(
            title=self._config_data[CONF_HOST],
            data=self._config_data,
        )

    @staticmethod
    @callback
    def async_get_options_flow(
        config_entry: ConfigEntry,
    ) -> SchemaOptionsFlowHandler:
        """Get options flow for this handler."""
        return SchemaOptionsFlowHandler(config_entry, OPTIONS_FLOW)
