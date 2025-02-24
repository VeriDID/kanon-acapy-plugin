from acapy_agent.wallet.base import BaseWallet, DIDInfo
from acapy_agent.wallet.key_type import ED25519, KeyTypes
from web3 import Web3
from ..config import Config
from .did_method import KANON

class KanonDIDRegistrar:
    """Kanon DID registrar for EVM-based DID registration using a smart contract."""

    def __init__(self, context):
        """Constructor."""
        self.context = context

        config = Config.from_settings(context.settings)
        # Initialize the Web3 client and contract instance
        self.web3 = Web3(Web3.HTTPProvider(config.web3_provider_url))
        self.contract = self.web3.eth.contract(address=config.contract_address, abi=config.contract_abi)
        self.operator_key = config.operator_key
        self.account = self.web3.eth.account.from_key(self.operator_key)

    async def register(self, key_type, seed=None) -> DIDInfo:
        """Register a Kanon DID on an EVM contract.

        This function generates a new key using the wallet, derives a DID from the verification key,
        and then registers that DID on the EVM contract using the registerDID method.
        """
        async with self.context.session() as session:
            key_types = session.inject_or(KeyTypes)
            if not key_types:
                raise Exception("Failed to inject supported key types enum")
            key_type = key_types.from_key_type(key_type) or ED25519

            wallet = session.inject_or(BaseWallet)
            if not wallet:
                raise Exception("Failed to inject wallet instance")

            # Create a new key
            key_info = await wallet.create_key(ED25519, seed=seed)
            key_entry = await wallet._session.handle.fetch_key(name=key_info.verkey)
            if not key_entry:
                raise Exception("Could not fetch key")

            # Derive the DID from the verkey. You might adjust this formatting as needed.
            did = f"did:kanon:{key_info.verkey}"
            # Define context and metadata to store on-chain
            context_value = "Kanon DID Registration"
            metadata = "{}"

            # Build the transaction to register the DID on the smart contract
            nonce = self.web3.eth.getTransactionCount(self.account.address)
            txn = self.contract.functions.registerDID(did, context_value, metadata).buildTransaction({
                'from': self.account.address,
                'nonce': nonce,
                'gas': 200000,  # Adjust gas limit as needed
                'gasPrice': self.web3.to_wei('20', 'gwei'),
            })

            # Sign and send the transaction
            signed_txn = self.web3.eth.account.sign_transaction(txn, self.operator_key)
            #TODO: Add a retry mechanism for the transaction and async execution
            tx_hash = self.web3.eth.sendRawTransaction(signed_txn.rawTransaction)
            receipt = self.web3.eth.waitForTransactionReceipt(tx_hash)

            # Insert the DID record into the wallet's store for persistence
            await wallet._session.handle.insert(
                "did",
                did,
                value_json={
                    "did": did,
                    "method": KANON.method_name,
                    "verkey": key_info.verkey,
                    "verkey_type": key_type.key_type,
                    "metadata": {},
                },
                tags={
                    "method": KANON.method_name,
                    "verkey": key_info.verkey,
                    "verkey_type": key_type.key_type,
                },
            )

            # Return the DID information along with the transaction hash
            info: DIDInfo = {
                "did": did,
                "verkey": key_info.verkey,
                "key_type": key_type.key_type,
                "tx_hash": tx_hash.hex(),
            }
            return info
