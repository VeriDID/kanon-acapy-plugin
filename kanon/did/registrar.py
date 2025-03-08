from acapy_agent.wallet.base import BaseWallet, DIDInfo
from acapy_agent.wallet.key_type import ED25519, KeyTypes
from web3 import Web3
from ..config import Config
from .did_method import KANON
import logging
LOGGER = logging.getLogger(__name__)

CONTRACT_ABI = [
    {
        "inputs": [
            {"internalType": "string", "name": "did", "type": "string"},
            {"internalType": "string", "name": "context", "type": "string"},
            {"internalType": "string", "name": "metadata", "type": "string"}
        ],
        "name": "registerDID",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [
            {"internalType": "string", "name": "did", "type": "string"},
            {"internalType": "string", "name": "context", "type": "string"},
            {"internalType": "string", "name": "metadata", "type": "string"}
        ],
        "name": "updateDID",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [
            {"internalType": "string", "name": "did", "type": "string"}
        ],
        "name": "resolveDID",
        "outputs": [
            {
                "components": [
                    {"internalType": "string", "name": "context", "type": "string"},
                    {"internalType": "string", "name": "metadata", "type": "string"},
                    {"internalType": "bool", "name": "active", "type": "bool"}
                ],
                "internalType": "struct DIDRegistry.DIDDocument",
                "name": "",
                "type": "tuple"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [
            {"internalType": "string", "name": "did", "type": "string"}
        ],
        "name": "deactivateDID",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    }
]

class KanonDIDRegistrar:
    """Kanon DID registrar for EVM-based DID registration using a smart contract."""

    def __init__(self, context):
        """Constructor."""
        self.context = context

        config = Config.from_settings(context.settings)
        # Initialize the Web3 client and contract instance
        self.web3 = Web3(Web3.HTTPProvider(config.web3_provider_url))
        self.contract = self.web3.eth.contract(
            address=config.contract_address, 
            abi=CONTRACT_ABI
        )
        self.operator_key = config.operator_key
        self.account = self.web3.eth.account.from_key(self.operator_key)

    async def register(self, key_type, seed=None, metadata=None) -> DIDInfo:
        """Register a Kanon DID on an EVM contract.

        This function generates a new key using the wallet, derives a DID from the verification key,
        and then registers that DID on the EVM contract using the registerDID method.

        Args:
            key_type: The type of key to create
            seed: Optional seed to use for key generation
            metadata: Optional metadata for the DID (company name, logo URL, etc.)
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

            # Derive the DID from the verkey
            did = f"did:kanon:{key_info.verkey}"
            context_value = "Kanon DID Registration"
            
            # Use provided metadata or empty JSON object
            metadata_json = metadata if metadata else "{}"

            # Build the transaction to register the DID on the smart contract
            nonce = self.web3.eth.get_transaction_count(self.account.address)
            txn = self.contract.functions.registerDID(did, context_value, metadata_json).build_transaction({
                'from': self.account.address,
                'nonce': nonce,
                'gas': 200000,  # Adjust gas limit as needed
                'gasPrice': self.web3.to_wei('20', 'gwei'),
            })

            # Sign and send the transaction
            signed_txn = self.web3.eth.account.sign_transaction(txn, self.operator_key)
            tx_hash = self.web3.eth.send_raw_transaction(signed_txn.rawTransaction)
            receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash)
            
            # Check if the transaction was successful
            if not receipt['status']:
                raise Exception(f"Blockchain transaction failed. Transaction hash: {tx_hash.hex()}")
            
            # Parse metadata for storage
            did_metadata = {}
            if metadata and metadata != "{}":
                try:
                    import json
                    did_metadata = json.loads(metadata)
                except json.JSONDecodeError:
                    LOGGER.warning("Invalid metadata JSON format, storing as string")
                    did_metadata = {"raw": metadata}
            
            # Only insert the DID record if the transaction was successful
            await wallet._session.handle.insert(
                "did",
                did,
                value_json={
                    "did": did,
                    "method": KANON.method_name,
                    "verkey": key_info.verkey,
                    "verkey_type": key_type.key_type,
                    "metadata": did_metadata,
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
                "metadata": did_metadata,
            }
            return info

    async def update(self, did: str, metadata: str) -> dict:
        """Update metadata for an existing Kanon DID.
        
        Args:
            did: The DID to update
            metadata: New metadata for the DID (company name, logo URL, etc.)
            
        Returns:
            Dictionary with transaction details
        """
        if not did.startswith("did:kanon:"):
            raise Exception("Invalid Kanon DID format")
            
        context_value = "Kanon DID Update"
        
        # Build the transaction to update the DID on the smart contract
        nonce = self.web3.eth.get_transaction_count(self.account.address)
        txn = self.contract.functions.updateDID(did, context_value, metadata).build_transaction({
            'from': self.account.address,
            'nonce': nonce,
            'gas': 200000,  # Adjust gas limit as needed
            'gasPrice': self.web3.to_wei('20', 'gwei'),
        })

        # Sign and send the transaction
        signed_txn = self.web3.eth.account.sign_transaction(txn, self.operator_key)
        tx_hash = self.web3.eth.send_raw_transaction(signed_txn.rawTransaction)
        receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash)
        
        # Check if the transaction was successful
        if not receipt['status']:
            raise Exception(f"Blockchain transaction failed. Transaction hash: {tx_hash.hex()}")
            
        # Update the local DID record with new metadata
        async with self.context.session() as session:
            wallet = session.inject_or(BaseWallet)
            if not wallet:
                raise Exception("Failed to inject wallet instance")
                
            # Parse metadata for storage
            did_metadata = {}
            if metadata and metadata != "{}":
                try:
                    import json
                    did_metadata = json.loads(metadata)
                except json.JSONDecodeError:
                    LOGGER.warning("Invalid metadata JSON format, storing as string")
                    did_metadata = {"raw": metadata}
            
            # Fetch the existing DID record
            did_record = await wallet._session.handle.fetch("did", did)
            if not did_record:
                LOGGER.warning(f"DID {did} not found in local storage, but blockchain update succeeded")
            else:
                # Update the metadata in the DID record
                did_info = did_record.value_json
                did_info["metadata"] = did_metadata
                
                # Update the record
                await wallet._session.handle.replace(
                    "did",
                    did,
                    value_json=did_info,
                    tags=did_record.tags
                )
        
        return {
            "did": did,
            "tx_hash": tx_hash.hex(),
            "metadata": did_metadata
        }
