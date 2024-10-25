"""Header Authentication provider.

Allow access to users based on a header set by a reverse-proxy.
"""
import logging
from typing import Any, Dict, List, Optional, cast

from aiohttp.web import Request
from homeassistant.auth.models import Credentials, User, UserMeta
from homeassistant.auth.providers import AUTH_PROVIDERS, AuthProvider, LoginFlow
from homeassistant.auth.providers.trusted_networks import (
    InvalidAuthError,
    InvalidUserError,
    IPAddress,
)
from homeassistant.core import callback

CONF_USERNAME_PREFIX = "username_prefix"
CONF_USERNAME_HEADER = "username_header"
CONF_DISPLAYNAME_HEADER = "displayname_header"
CONF_USERGROUP_HEADER = "usergroup_header"
CONF_ALLOW_BYPASS_LOGIN = "allow_bypass_login"
CONF_CREATE_NONEXISTENT = "create_nonexistent"
CONF_GROUPMAPPING = "groupmapping"
CONF_GROUPMAPPING_SYSTEM_USERS = "system_users"
CONF_GROUPMAPPING_SYSTEM_ADMIN = "system_admin"
CONF_GROUPMAPPING_LOCAL_ONLY = "system_users"

_LOGGER = logging.getLogger(__name__)


@AUTH_PROVIDERS.register("header")
class HeaderAuthProvider(AuthProvider):
    """Header Authentication Provider.

    Allow access to users based on a header set by a reverse-proxy.
    """

    DEFAULT_TITLE = "Header Authentication"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Extend parent's __init__.

        Adds self._user_meta dictionary to hold the user-specific
        attributes provided by external programs.
        """
        super().__init__(*args, **kwargs)
        self._user_meta: dict[str, dict[str, Any]] = {}

    @property
    def type(self) -> str:
        return "auth_header"

    @property
    def support_mfa(self) -> bool:
        """Header Authentication Provider does not support MFA."""
        return False

    async def async_login_flow(self, context: Optional[Dict]) -> LoginFlow:
        """Return a flow to login."""
        assert context is not None
        username_header_name = self.config[CONF_USERNAME_HEADER]
        displayname_header_name = self.config[CONF_DISPLAYNAME_HEADER]
        usergroup_header_name = self.config[CONF_USERGROUP_HEADER]

        request = cast(Request, context.get("request"))

        empty_header_flow = HeaderLoginFlow(
            self,
            None,
            [],
            cast(IPAddress, context.get("conn_ip_address")),
            self.config[CONF_ALLOW_BYPASS_LOGIN],
        )

        if username_header_name not in request.headers:
            _LOGGER.info("No username header set, returning empty flow")
            return empty_header_flow

        if self.config[CONF_CREATE_NONEXISTENT]:
            if usergroup_header_name not in request.headers:
                _LOGGER.info("No usergroup header set, returning empty flow")
                return empty_header_flow

        remote_user = (
            self.config[CONF_USERNAME_PREFIX] + request.headers[username_header_name].casefold()
        )
        remote_group = request.headers[usergroup_header_name].casefold()

        self._user_meta["name"] = request.headers[displayname_header_name]

        # Admin has precedence
        if (
            remote_group in self.config[CONF_GROUPMAPPING][CONF_GROUPMAPPING_SYSTEM_ADMIN]
            or "*" in self.config[CONF_GROUPMAPPING][CONF_GROUPMAPPING_SYSTEM_ADMIN]
        ):
            self._user_meta["group"] = "system_admin"
        elif (
            remote_group in self.config[CONF_GROUPMAPPING][CONF_GROUPMAPPING_SYSTEM_USERS]
            or "*" in self.config[CONF_GROUPMAPPING][CONF_GROUPMAPPING_SYSTEM_USERS]
        ):
            self._user_meta["group"] = "system_users"
        else:
            _LOGGER.info("No group header mapped to neither group, returning empty flow")
            return empty_header_flow

        self._user_meta["local_only"] = (
            remote_group in self.config[CONF_GROUPMAPPING][CONF_GROUPMAPPING_LOCAL_ONLY]
            or "*" in self.config[CONF_GROUPMAPPING][CONF_GROUPMAPPING_LOCAL_ONLY]
        )

        # Translate username to id
        users = await self.store.async_get_users()
        available_users = [user for user in users if not user.system_generated and user.is_active]
        return HeaderLoginFlow(
            self,
            remote_user,
            available_users,
            cast(IPAddress, context.get("conn_ip_address")),
            self.config[CONF_ALLOW_BYPASS_LOGIN],
        )

    async def async_user_meta_for_credentials(self, credentials: Credentials) -> UserMeta:
        """Return extra user metadata for credentials.

        Trusted network auth provider should never create new user.
        """
        raise NotImplementedError

    async def async_get_or_create_credentials(self, flow_result: Dict[str, str]) -> Credentials:
        """Get credentials based on the flow result."""
        user_id = flow_result["user"]

        users = await self.store.async_get_users()
        for user in users:
            if not user.system_generated and user.is_active and user.id == user_id:
                for credential in await self.async_credentials():
                    if credential.data["user_id"] == user_id:
                        return credential
                cred = self.async_create_credentials({"user_id": user_id})
                await self.store.async_link_user(user, cred)
                return cred

        # We only allow login as exist user
        raise InvalidUserError

    @callback
    def async_validate_access(self, ip_addr: IPAddress) -> None:
        """Make sure the access is from trusted_proxies.

        Raise InvalidAuthError if not.
        Raise InvalidAuthError if trusted_proxies is not configured.
        """
        if not self.hass.http.trusted_proxies:
            _LOGGER.warning("trusted_proxies is not configured")
            raise InvalidAuthError("trusted_proxies is not configured")

        if not any(
            ip_addr in trusted_network for trusted_network in self.hass.http.trusted_proxies
        ):
            _LOGGER.warning("Remote IP not in trusted proxies: %s", ip_addr)
            raise InvalidAuthError("Not in trusted_proxies")


class HeaderLoginFlow(LoginFlow):
    """Handler for the login flow."""

    def __init__(
        self,
        auth_provider: HeaderAuthProvider,
        remote_user: str,
        available_users: List[User],
        ip_address: IPAddress,
        allow_bypass_login: bool,
    ) -> None:
        """Initialize the login flow."""
        super().__init__(auth_provider)
        self._available_users = available_users
        self._remote_user = remote_user
        self._ip_address = ip_address
        self._allow_bypass_login = allow_bypass_login

    async def async_step_init(self, user_input=None) -> Dict[str, Any]:
        """Handle the step of the form."""

        if user_input is not None or self._allow_bypass_login:
            try:
                _LOGGER.debug("Validating access for IP: %s", self._ip_address)
                cast(HeaderAuthProvider, self._auth_provider).async_validate_access(
                    self._ip_address
                )
            except InvalidAuthError as exc:
                _LOGGER.debug("Invalid auth: %s", exc)
                return self.async_abort(reason="not_allowed")

            for user in self._available_users:
                _LOGGER.debug("Checking user: %s", user.name)
                for cred in user.credentials:
                    if "username" in cred.data:
                        _LOGGER.debug("Found username in credentials: %s", cred.data["username"])
                        if cred.data["username"] == self._remote_user:
                            _LOGGER.debug("Username match found, finishing login flow")
                            return await self.async_finish({"user": user.id})
                if user.name == self._remote_user:
                    _LOGGER.debug("User name match found, finishing login flow")
                    return await self.async_finish({"user": user.id})

            _LOGGER.debug("No matching user found")
            return self.async_abort(reason="not_allowed")

        _LOGGER.debug("Showing login form with remote_user: %s", self._remote_user)
        return self.async_show_form(
            step_id="init",
            data_schema=None,
        )
