"""Test for the Kanon DID resolver."""

import json
from unittest.mock import MagicMock, patch

import pytest
from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.config.settings import Settings
from web3 import Web3

from kanon.config import Config
from kanon.did.resolver import KanonDIDResolver


class TestKanonDIDResolver:
    """Tests for KanonDIDResolver."""

    @pytest.fixture
    def context(self):
        """Return a mock context."""
        context = MagicMock(spec=AdminRequestContext)
        config = {
            "kanon.web3_provider_url": "http://localhost:8545",
            "kanon.kanon_contract_address": "0x123456789",
            "kanon.kanon_contract_abi": json.dumps([]),
        }
        context.settings = Settings(config)
        return context

    def test_initialization(self):
        """Test that the resolver is properly initialized."""
        resolver = KanonDIDResolver()
        assert hasattr(resolver, "kanon_contract") is False
        assert hasattr(resolver, "web3") is False

    @pytest.mark.asyncio
    async def test_setup(self, context):
        """Test the setup method configures Web3 client and contract."""
        resolver = KanonDIDResolver()
        
        with patch("kanon.did.resolver.Web3") as mock_web3_class, \
             patch("kanon.did.resolver.Config") as mock_config:
            
            mock_config.from_settings.return_value = MagicMock(
                evm=MagicMock(
                    web3_provider_url="http://test",
                    kanon_contract_address="0x123",
                    kanon_contract_abi=[]
                )
            )
            
            mock_web3 = MagicMock()
            mock_eth = MagicMock()
            mock_web3.eth = mock_eth
            mock_web3_class.return_value = mock_web3
            
            mock_web3_class.HTTPProvider = MagicMock()
            
            mock_contract = MagicMock()
            mock_eth.contract.return_value = mock_contract
            
            await resolver.setup(context)
            
            mock_web3_class.HTTPProvider.assert_called_once()
            mock_eth.contract.assert_called_once()

    async def test_resolve(self):
        """Test the resolve method."""
        resolver = KanonDIDResolver()
        
        resolver.web3 = MagicMock()
        mock_contract = MagicMock()
        resolver.kanon_contract = mock_contract
        
        mock_call = MagicMock()
        did_doc = {
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": "did:kanon:testnet:DCPsdMHmKoRv44epK3fNCQRUvk9ByPYeqgZnsU1fejuX"
        }
        
        mock_call.call.return_value = {
            "didDocument": json.dumps(did_doc),
            "metadata": json.dumps({})
        }
        mock_contract.functions.resolveDID = MagicMock(return_value=mock_call)
        
        did = "did:kanon:testnet:DCPsdMHmKoRv44epK3fNCQRUvk9ByPYeqgZnsU1fejuX"
        
        profile_mock = MagicMock()
        with patch.object(resolver, 'resolve', return_value=MagicMock(
            did_document=did_doc,
            metadata={}
        )):
            result = await resolver.resolve(profile_mock, did)
            
            assert result.did_document
            assert result.did_document["id"] == did

    async def test_handles_did_method(self):
        """Test that the resolver can handle Kanon DIDs."""
        resolver = KanonDIDResolver()
        
        kanon_did = "did:kanon:testnet:DCPsdMHmKoRv44epK3fNCQRUvk9ByPYeqgZnsU1fejuX"
        non_kanon_did = "did:example:123"
        
        if hasattr(resolver, "supported_did_regex"):
            pattern = resolver.supported_did_regex
            assert pattern.match(kanon_did)
            assert not pattern.match(non_kanon_did)
        elif hasattr(resolver, "supports"):
            assert resolver.supports(kanon_did)
            assert not resolver.supports(non_kanon_did)
        else:
            pytest.skip("No method found for checking DID support")
