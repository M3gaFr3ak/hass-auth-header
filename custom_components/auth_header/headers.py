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
from homeassistant.auth.const import GROUP_ID_USER, GROUP_ID_ADMIN

CONF_USERNAME_PREFIX = "username_prefix"
CONF_USERNAME_HEADER = "username_header"
CONF_DISPLAYNAME_HEADER = "displayname_header"
CONF_USERGROUP_HEADER = "usergroup_header"
CONF_ALLOW_BYPASS_LOGIN = "allow_bypass_login"
CONF_CREATE_NONEXISTENT = "allow_create_nonexistent"
CONF_GROUPMAPPING = "groupmapping"
CONF_GROUPMAPPING_SYSTEM_USERS = "system_users"
CONF_GROUPMAPPING_SYSTEM_ADMIN = "system_admin"
CONF_GROUPMAPPING_LOCAL_ONLY = "local_only"

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
            self.config[CONF_CREATE_NONEXISTENT],
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

        meta: dict[str, str] = {}

        meta["name"] = request.headers[displayname_header_name]

        # Admin has precedence
        if (
            any(
                group in self.config[CONF_GROUPMAPPING][CONF_GROUPMAPPING_SYSTEM_ADMIN]
                for group in remote_group
            )
            or "*" in self.config[CONF_GROUPMAPPING][CONF_GROUPMAPPING_SYSTEM_ADMIN]
        ):
            meta["group"] = GROUP_ID_ADMIN
        elif (
            any(
                group in self.config[CONF_GROUPMAPPING][CONF_GROUPMAPPING_SYSTEM_USERS]
                for group in remote_group
            )
            or "*" in self.config[CONF_GROUPMAPPING][CONF_GROUPMAPPING_SYSTEM_USERS]
        ):
            meta["group"] = GROUP_ID_USER
        else:
            _LOGGER.info("No group header mapped to neither group, returning empty flow")
            return empty_header_flow

        meta["local_only"] = (
            any(
                group in self.config[CONF_GROUPMAPPING][CONF_GROUPMAPPING_LOCAL_ONLY]
                for group in remote_group
            )
            or "*" in self.config[CONF_GROUPMAPPING][CONF_GROUPMAPPING_LOCAL_ONLY]
        )

        self._user_meta[remote_user] = meta

        # Translate username to id
        users = await self.store.async_get_users()
        available_users = [user for user in users if not user.system_generated and user.is_active]
        return HeaderLoginFlow(
            self,
            remote_user,
            available_users,
            cast(IPAddress, context.get("conn_ip_address")),
            self.config[CONF_ALLOW_BYPASS_LOGIN],
            self.config[CONF_CREATE_NONEXISTENT],
        )

    async def async_user_meta_for_credentials(self, credentials: Credentials) -> UserMeta:
        """Return extra user metadata for credentials.

        Currently, supports name, group and local_only.
        """
        meta = self._user_meta.get(credentials.data["username"], {})
        return UserMeta(
            name=meta.get("name"),
            is_active=True,
            group=meta.get("group"),
            local_only=meta.get("local_only") == "true",
        )

    async def async_get_or_create_credentials(self, flow_result: Dict[str, str]) -> Credentials:
        """Get credentials based on the flow result."""
        create = flow_result["create"]
        username = flow_result["username"]

        _LOGGER.debug("async def async_get_or_create_credentials " + str(create))

        if not create:
            user_id = flow_result["user"]

            users = await self.store.async_get_users()
            for user in users:
                if not user.system_generated and user.is_active and user.id == user_id:
                    for credential in await self.async_credentials():
                        if (
                            "username" in credential.data
                            and credential.data["username"] == username
                        ):
                            return credential
                        if "user_id" in credential.data and credential.data["user_id"] == user_id:
                            return credential
                    cred = self.async_create_credentials({"user_id": user_id, "username": username})
                    await self.store.async_link_user(user, cred)
                    return cred
        else:
            _LOGGER.debug("Creating credentials for " + username)
            if self.config[CONF_CREATE_NONEXISTENT]:
                return self.async_create_credentials({"username": username})
            else:
                raise InvalidUserError(
                    "User doesn't exist and creation of nonexistent users is disabled"
                )

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
        allow_create_nonexistent: bool,
    ) -> None:
        """Initialize the login flow."""
        super().__init__(auth_provider)
        self._available_users = available_users
        self._remote_user = remote_user
        self._ip_address = ip_address
        self._allow_bypass_login = allow_bypass_login
        self._allow_create_nonexistent = allow_create_nonexistent

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
                            return await self.async_finish(
                                {"create": False, "user": user.id, "username": user.name}
                            )
                if user.name == self._remote_user:
                    _LOGGER.debug("User name match found, finishing login flow")
                    return await self.async_finish(
                        {"create": False, "user": user.id, "username": user.name}
                    )

            if self._allow_create_nonexistent:
                _LOGGER.debug("No matching user found, creating user and finishing login flow")
                return await self.async_finish({"create": True, "username": self._remote_user})
            else:
                _LOGGER.debug("No matching user found, user creation not enabled")
                return self.async_abort(reason="not_allowed")

        _LOGGER.debug("Showing login form with remote_user: %s", self._remote_user)
        return self.async_show_form(
            step_id="init",
            data_schema=None,
        )
