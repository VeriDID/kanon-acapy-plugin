import pytest

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.core.event_bus import EventBus, MockEventBus
from acapy_agent.utils.testing import create_test_profile
from acapy_agent.wallet.base import BaseWallet
from acapy_agent.wallet.key_type import KeyTypes
from acapy_agent.resolver.did_resolver import DIDResolver
from acapy_agent.anoncreds.registry import AnonCredsRegistry
from acapy_agent.wallet.did_method import DIDMethods

from unittest.mock import create_autospec


@pytest.fixture
async def profile():
    profile = await create_test_profile(
        settings={
            "admin.admin_api_key": "admin_api_key",
            "admin.admin_insecure_mode": False,
            "plugin_config": {
                "kanon": {
                    "evm": {
                        "web3_provider_url": "http://localhost:8545",
                        "operator_key": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
                        "kanon_contract_address": "0x1234567890abcdef1234567890abcdef12345678",
                        "kanon_contract_abi": [],  # Empty list for ABI to pass validation
                    }
                }
            },
        }
    )
    profile.context.injector.bind_instance(KeyTypes, KeyTypes())
    profile.context.injector.bind_instance(EventBus, MockEventBus())
    profile.context.injector.bind_instance(DIDResolver, DIDResolver())
    profile.context.injector.bind_instance(AnonCredsRegistry, AnonCredsRegistry())
    profile.context.injector.bind_instance(DIDMethods, DIDMethods())
    yield profile


@pytest.fixture
async def session_inject():
    session_inject = {BaseWallet: create_autospec(BaseWallet)}
    yield session_inject


@pytest.fixture
async def context(profile, session_inject):
    context = AdminRequestContext.test_context(session_inject, profile)
    yield context
