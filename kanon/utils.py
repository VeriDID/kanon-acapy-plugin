"""Utility functions that don't fit into a specific module."""

from typing import Type

from acapy_agent.config.injector import InjectType
from acapy_agent.core.profile import ProfileSession
from acapy_agent.wallet.base import BaseWallet


def inject_or_fail(
    session: ProfileSession, base_class: Type[InjectType], exception
) -> InjectType:
    """Inject class from context or immediately fail if not possible."""
    instance = session.inject_or(base_class)

    if not instance:
        raise exception(f"Could not inject class {base_class}")

    return instance
