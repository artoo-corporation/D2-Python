"""Policy management package."""

from .bundle import PolicyBundle
from . import manager as _manager
from .manager import (
    PolicyManager,
    configure_rbac,
    configure_rbac_sync,
    get_policy_manager,
    shutdown_all_rbac,
    shutdown_rbac,
)
from .loaders import PolicyLoader, FilePolicyLoader, CloudPolicyLoader

jwt = _manager.jwt
configure_rbac_async = configure_rbac

__all__ = [
    "PolicyBundle",
    "PolicyManager",
    "PolicyLoader",
    "FilePolicyLoader",
    "CloudPolicyLoader",
    "configure_rbac",
    "configure_rbac_async",
    "configure_rbac_sync",
    "get_policy_manager",
    "jwt",
    "shutdown_all_rbac",
    "shutdown_rbac",
]


