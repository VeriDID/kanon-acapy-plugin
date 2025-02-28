import re
import pytest

from dataclasses import dataclass

from unittest.mock import AsyncMock, MagicMock, patch

from acapy_agent.anoncreds.base import AnonCredsObjectNotFound, AnonCredsResolutionError
from acapy_agent.anoncreds.models.credential_definition import (
    CredDef,
    CredDefValue,
    CredDefValuePrimary,
    CredDefValueRevocation,
)
from acapy_agent.anoncreds.models.revocation import RevList, RevRegDef, RevRegDefValue

from kanon.anoncreds import KanonAnonCredsRegistry
from kanon.anoncreds.registry import _validate_resolution_result
from kanon.anoncreds.types import (
    build_acapy_cred_def_result,
    build_acapy_get_cred_def_result,
    build_acapy_get_rev_list_result,
    build_acapy_get_rev_reg_def_result,
    build_acapy_get_schema_result,
    build_acapy_rev_list_result,
    build_acapy_rev_reg_def_result,
    build_acapy_schema_result,
    build_kanon_anoncreds_schema,
    build_kanon_anoncreds_cred_def,
    build_kanon_anoncreds_rev_reg_def,
    build_kanon_anoncreds_rev_list,
    KanonAnonCredsSchema,
    KanonAnonCredsCredDef,
    KanonCredDefValue,
    KanonCredDefValuePrimary,
    KanonCredDefValueRevocation,
    KanonAnonCredsRevRegDef,
    KanonRevRegDefValue,
    KanonAnonCredsRevList,
    KanonRevListState,
    KanonRegisterRevListResult,
)

# Create mock class for SdkKanonAnonCredsRegistry 
class SdkKanonAnonCredsRegistry:
    """Mock SDK class for tests."""
    
    def __init__(self, *args, **kwargs):
        """Initialize with mocks."""
        pass


@dataclass
class MockAnonCredsResult:
    result: any
    resolution_metadata: dict = None


MOCK_RESULT_PARAMS = {"result": "test", "resolution_metadata": {}}

MOCK_RESULT_ATTRIBUTE_NAME = "result"

MOCK_ISSUER_ID = (
    "did:kanon:testnet:zFwZUYPrhi333pC2anAnSkctXgZzLfeR8DXURo2N4xV1C_0.0.5284925"
)

MOCK_SCHEMA = KanonAnonCredsSchema(
    name="Example schema", issuer_id=MOCK_ISSUER_ID, attr_names=["score"], version="1.0"
)
MOCK_SCHEMA_ID = "did:kanon:testnet:zFwZUYPrhi333pC2anAnSkctXgZzLfeR8DXURo2N4xV1C_0.0.5284925/anoncreds/v0/SCHEMA/0.0.5284932"

MOCK_CRED_DEF = KanonAnonCredsCredDef(
    schema_id=MOCK_SCHEMA_ID,
    issuer_id=MOCK_ISSUER_ID,
    tag="mock-cred-def-tag",
    value=KanonCredDefValue(
        KanonCredDefValuePrimary(n="n", s="s", r={"key": "value"}, rctxt="rctxt", z="z"),
        KanonCredDefValueRevocation(
            g="g",
            g_dash="g_dash",
            h="h",
            h0="h0",
            h1="h1",
            h2="h2",
            htilde="htilde",
            h_cap="h_cap",
            u="u",
            pk="pk",
            y="y",
        ),
    ),
)

MOCK_CRED_DEF_ID = f"{MOCK_ISSUER_ID}/anoncreds/v0/CRED_DEF/{MOCK_SCHEMA_ID}"

MOCK_REV_REG_DEF = KanonAnonCredsRevRegDef(
    issuer_id=MOCK_ISSUER_ID,
    cred_def_id=MOCK_CRED_DEF_ID,
    tag="mock-rev-reg-tag",
    value=KanonRevRegDefValue(
        public_keys={},
        max_cred_num=100,
        tails_location="/tmp/tails",
        tails_hash="hash",
    ),
)

MOCK_REV_REG_DEF_ID = (
    f"{MOCK_ISSUER_ID}/anoncreds/v0/REV_REG_DEF/{MOCK_CRED_DEF_ID}/mock-rev-reg-tag"
)

MOCK_REV_LIST = KanonAnonCredsRevList(
    issuer_id=MOCK_ISSUER_ID,
    rev_reg_def_id=MOCK_REV_REG_DEF_ID,
    revocation_list=[0, 0, 0, 0],
    current_accumulator="accum",
    timestamp=0,
)


async def create_and_setup_registry(context):
    """Create and setup the registry for tests."""
    # Patch the Config class
    with patch("kanon.config.Config") as mock_config:
        # Setup a mock operator key and contract 
        mock_config.from_settings.return_value = MagicMock()
        mock_config.from_settings.return_value.evm.operator_key = "test_operator_key"
        mock_config.from_settings.return_value.evm.web3_provider_url = "http://test.url" 
        mock_config.from_settings.return_value.evm.kanon_contract_address = "0x123"
        mock_config.from_settings.return_value.evm.kanon_contract_abi = []
        
        # Patch Web3 class
        with patch("kanon.anoncreds.registry.Web3") as mock_web3:
            # Setup mock for web3
            mock_web3_instance = MagicMock()
            mock_web3.return_value = mock_web3_instance
            mock_web3.HTTPProvider.return_value = "http_provider"
            
            # Setup mock for eth account
            mock_account = MagicMock()
            mock_web3_instance.eth.account.from_key.return_value = mock_account
            mock_web3_instance.eth.contract.return_value = MagicMock()
            
    registry = KanonAnonCredsRegistry()
    await registry.setup(context)
    return registry


class TestAnonCredsRegistry:
    async def test_validate_resolution_result(self):
        _validate_resolution_result(
            MockAnonCredsResult(**MOCK_RESULT_PARAMS), MOCK_RESULT_ATTRIBUTE_NAME
        )

        with pytest.raises(
            AnonCredsResolutionError,
            match=f"Failed to retrieve {MOCK_RESULT_ATTRIBUTE_NAME}",
        ):
            _validate_resolution_result(
                MockAnonCredsResult(**{**MOCK_RESULT_PARAMS, "result": None}),
                MOCK_RESULT_ATTRIBUTE_NAME,
            )

        # Test for error case
        with pytest.raises(AnonCredsResolutionError, match="Custom error"):
            _validate_resolution_result(
                MockAnonCredsResult(
                    result=None,
                    resolution_metadata={"error": "someError", "message": "Custom error"},
                ),
                MOCK_RESULT_ATTRIBUTE_NAME,
            )

        # Test for notFound case
        with pytest.raises(AnonCredsObjectNotFound, match="Not found error"):
            _validate_resolution_result(
                MockAnonCredsResult(
                    result=None,
                    resolution_metadata={"error": "notFound", "message": "Not found error"},
                ),
                MOCK_RESULT_ATTRIBUTE_NAME,
            )

    # Continue with the patched test functions...
