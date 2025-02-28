from logging import WARN
from unittest.mock import AsyncMock, MagicMock, patch

from acapy_agent.resolver.did_resolver import DIDResolver
from acapy_agent.anoncreds.registry import AnonCredsRegistry
from kanon import setup


class TestInit:
    class TestSetup:
        @patch("kanon.did.resolver.KanonDIDResolver.setup")
        @patch("kanon.anoncreds.registry.KanonAnonCredsRegistry.setup")
        async def test_sucess(self, mock_anoncreds_setup, mock_did_setup, context):
            # Bypass the actual setup implementations
            mock_did_setup.return_value = None
            mock_anoncreds_setup.return_value = None
            
            await setup(context)

        async def test_no_did_resolver(self, caplog):
            context = MagicMock(inject_or=MagicMock(return_value=None))

            await setup(context)

            assert caplog.record_tuples == [
                ("kanon", WARN, "No DID Resolver instance found in context")
            ]

        @patch("kanon.did.resolver.KanonDIDResolver.setup")
        async def test_no_anoncreds_registry(self, mock_did_setup, caplog):
            resolver = DIDResolver()
            context = MagicMock(
                inject_or=MagicMock(
                    side_effect=lambda x: resolver if x == DIDResolver else None
                ),
            )

            # Bypass the actual setup implementation
            mock_did_setup.return_value = None

            await setup(context)

            assert caplog.record_tuples == [
                ("kanon", WARN, "No AnonCredsRegistry instance found in context")
            ]
