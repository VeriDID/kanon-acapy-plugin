import pytest
import asyncio
from unittest import IsolatedAsyncioTestCase
from unittest.mock import AsyncMock, MagicMock, Mock, create_autospec, patch

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.utils.testing import create_test_profile

from acapy_agent.wallet.base import BaseWallet, KeyInfo
from acapy_agent.wallet.key_type import ED25519, KeyTypes

from kanon.did import KanonDIDRegistrar


class TestKanonDIDRegistrar(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.wallet = create_autospec(BaseWallet)
        self.session_inject = {BaseWallet: self.wallet}
        
        # Wrap the EVM configuration under the "kanon" key so that
        # settings.for_plugin("kanon") returns the appropriate config.
        self.profile = await create_test_profile(
            settings={
                "admin.admin_api_key": "admin_api_key",
                "admin.admin_insecure_mode": False,
                "plugin_config": {
                    "kanon": {
                        "evm": {
                            "web3_provider_url": "http://localhost:8545",
                            "contract_address": "0x1234567890abcdef1234567890abcdef12345678",
                            "contract_abi": [],  
                            "operator_key": "0x1000000000000000000000000000000000000000000000000000000000000000",
                        }
                    }
                },
            }
        )
        # Bind key types
        self.profile.context.injector.bind_instance(KeyTypes, KeyTypes())
        self.context = AdminRequestContext.test_context(self.session_inject, self.profile)

    async def setup_registrar_with_evm(self, verkey: str, fake_tx_hash: bytes, fake_receipt: dict):
        """
        Helper to set up the registrar instance with patched Web3 and contract functions.
        """
        registrar = KanonDIDRegistrar(self.context)

        # Patch the parts of the web3.eth contract and account methods used in register
        registrar.web3.eth.getTransactionCount = MagicMock(return_value=1)

        # Create a fake function object for registerDID that returns a fake transaction dict
        fake_register_function = MagicMock()
        fake_register_function.buildTransaction.return_value = {"gas": 200000}
        registrar.contract.functions = MagicMock()
        registrar.contract.functions.registerDID.return_value = fake_register_function

        # Patch account signing to return a fake signed transaction
        fake_signed_tx = MagicMock(rawTransaction=b"signed_tx")
        registrar.web3.eth.account.sign_transaction = MagicMock(return_value=fake_signed_tx)

        # Patch sending the transaction and waiting for receipt
        registrar.web3.eth.sendRawTransaction = MagicMock(return_value=fake_tx_hash)
        registrar.web3.eth.waitForTransactionReceipt = MagicMock(return_value=fake_receipt)
        return registrar

    async def test_registers_did(self):
        verkey = "DCPsdMHmKoRv44epK3fNCQRUvk9ByPYeqgZnsU1fejuX"
        expected_did = f"did:kanon:{verkey}"
        fake_tx_hash = b"\x12\x34"
        fake_receipt = {"status": 1}

        # Setup wallet mocks: create_key and fetch_key
        key_info = KeyInfo(verkey, {}, ED25519)
        self.wallet.create_key = AsyncMock(return_value=key_info)
        self.wallet._session = MagicMock(
            handle=AsyncMock(
                fetch_key=AsyncMock(
                    return_value=Mock(
                        key=Mock(
                            # Not used in EVM registrar for key conversion but still required for flow.
                            get_secret_bytes=Mock(return_value=b"dummy_bytes")
                        )
                    )
                ),
                insert=AsyncMock(return_value=None),
            )
        )

        registrar = await self.setup_registrar_with_evm(verkey, fake_tx_hash, fake_receipt)

        result = await registrar.register("ed25519")
        expected = {
            "did": expected_did,
            "verkey": verkey,
            "key_type": "ed25519",
            "tx_hash": fake_tx_hash.hex(),
        }
        assert result == expected

    async def test_throws_on_missing_key_types(self):
        self.session_inject[KeyTypes] = None

        with pytest.raises(Exception, match="Failed to inject supported key types enum"):
            await KanonDIDRegistrar(self.context).register("Ed25519")

    async def test_throws_on_missing_wallet(self):
        self.session_inject[BaseWallet] = None

        with pytest.raises(Exception, match="Failed to inject wallet instance"):
            await KanonDIDRegistrar(self.context).register("Ed25519")
