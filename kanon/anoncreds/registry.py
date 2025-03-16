import re
import time
import json
from typing import Pattern
import logging

from acapy_agent.anoncreds.base import (
    AnonCredsObjectNotFound,
    AnonCredsResolutionError,
    AnonCredsRegistrationError,
    BaseAnonCredsRegistrar,
    BaseAnonCredsResolver,
    CredDefResult,
    GetCredDefResult,
    GetRevListResult,
    GetRevRegDefResult,
    GetSchemaResult,
    RevListResult,
    RevRegDefResult,
    SchemaResult,
)
from acapy_agent.anoncreds.events import RevListFinishedEvent
from acapy_agent.anoncreds.models.schema_info import AnoncredsSchemaInfo
from acapy_agent.core.event_bus import EventBus
from acapy_agent.wallet.base import BaseWallet
from web3 import Web3

from ..config import Config
from .types import (
    build_acapy_cred_def_result,
    build_acapy_get_cred_def_result,
    build_acapy_get_rev_list_result,
    build_acapy_get_rev_reg_def_result,
    build_acapy_get_schema_result,
    build_acapy_rev_list_result,
    build_acapy_schema_result,
    build_kanon_anoncreds_schema,
    build_kanon_anoncreds_cred_def,
)
from ..utils import inject_or_fail

# Define the Kanon contract ABI directly in this file
KANON_CONTRACT_ABI = [
    {
        "inputs": [{"internalType": "string", "name": "_schemaId", "type": "string"}],
        "name": "getSchema",
        "outputs": [
            {"internalType": "string", "name": "schemaDetails", "type": "string"},
            {"internalType": "address[]", "name": "approvedIssuers", "type": "address[]"}
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [{"internalType": "string", "name": "_credDefId", "type": "string"}],
        "name": "getCredentialDefinition",
        "outputs": [
            {"internalType": "string", "name": "schemaId", "type": "string"},
            {"internalType": "string", "name": "issuerId", "type": "string"}
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [
            {"internalType": "string", "name": "_schemaId", "type": "string"},
            {"internalType": "string", "name": "_details", "type": "string"},
            {"internalType": "string", "name": "_issuerId", "type": "string"}
        ],
        "name": "registerSchema",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [
            {"internalType": "string", "name": "_credDefId", "type": "string"},
            {"internalType": "string", "name": "_schemaId", "type": "string"},
            {"internalType": "string", "name": "_issuerId", "type": "string"}
        ],
        "name": "registerCredentialDefinition",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [{"internalType": "string", "name": "_credId", "type": "string"}],
        "name": "revokeCredential",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [{"internalType": "string", "name": "_credId", "type": "string"}],
        "name": "isCredentialRevoked",
        "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
        "stateMutability": "view",
        "type": "function"
    }
]

def _validate_resolution_result(result, attribute_name):
    """Validate resolution result helper."""
    if getattr(result, attribute_name) is None:
        if hasattr(result, "resolution_metadata") and result.resolution_metadata:
            if result.resolution_metadata.get("error") == "notFound":
                msg = (
                    result.resolution_metadata.get("message")
                    if result.resolution_metadata.get("message")
                    else "Unknown error"
                )
                raise AnonCredsObjectNotFound(msg)
            elif result.resolution_metadata.get("error"):
                msg = (
                    result.resolution_metadata.get("message")
                    if result.resolution_metadata.get("message")
                    else "Unknown error"
                )
                raise AnonCredsResolutionError(msg)
        raise AnonCredsResolutionError(f"Failed to retrieve {attribute_name}")
    return result


class KanonAnonCredsRegistry(BaseAnonCredsResolver, BaseAnonCredsRegistrar):
    """
    AnonCreds registry for the Kanon contract.
    Adapts the AnonCreds registry logic to use a Kanon
    smart contract deployed on an EVM chain for schema, credential definition,
    and basic revocation management.
    """

    def __init__(self):
        """Initializer."""
        # Accept DIDs of form did:kanon:...
        self._supported_identifiers_regex = re.compile(r"^did:kanon:.*$")

    @property
    def supported_identifiers_regex(self) -> Pattern:
        """Return the compiled regex of supported identifiers."""
        return self._supported_identifiers_regex

    async def setup(self, context):
        """
        Setup the registry using context settings:
        - web3_provider_url
        - contract_address
        - operator_key
        """
        settings = Config.from_settings(context.settings)
        
        logging.info(f"Setting up Kanon AnonCreds Registry with network: {settings.network}")
        
        # Initialize Web3 connection
        self.web3 = Web3(Web3.HTTPProvider(settings.web3_provider_url))
        if not self.web3.is_connected():
            logging.error(f"Failed to connect to Web3 provider at {settings.web3_provider_url}")
            raise AnonCredsResolutionError(f"Failed to connect to Web3 provider at {settings.web3_provider_url}")
        
        # Setup operator account
        self.operator_key = settings.operator_key
        self.eth_account = self.web3.eth.account.from_key(self.operator_key)
        logging.info(f"Using operator account: {self.eth_account.address}")
        
        # Initialize contract
        try:
            self.kanon_contract = self.web3.eth.contract(
                address=settings.contract_address,
                abi=settings.contract_abi or KANON_CONTRACT_ABI,
            )
            logging.info(f"Successfully initialized Kanon contract at {settings.contract_address}")
        except Exception as e:
            logging.error(f"Failed to initialize Kanon contract: {e}")
            raise AnonCredsResolutionError(f"Failed to initialize Kanon contract: {e}")
        
        logging.info("Kanon AnonCreds Registry setup complete")

    async def get_schema(self, profile, schema_id) -> GetSchemaResult:
        """
        Get schema from:
        1) The local wallet (if previously stored),
        2) The Kanon contract (blockchain) if not found locally.
        """
        from acapy_agent.anoncreds.models.schema import Schema

        # 1) Attempt local wallet fetch
        try:
            async with profile.session() as session:
                # Try with the provided ID first
                schema_record = await session.handle.fetch(
                    "anoncreds:schema", schema_id
                )
                
                # If not found, try with a sanitized version of the ID
                if not schema_record:
                    # Create a sanitized version of the ID
                    parts = schema_id.split(":")
                    if len(parts) >= 4:
                        # Extract the schema name and version
                        schema_name = parts[-2]
                        schema_version = parts[-1]
                        # Create a sanitized schema name
                        sanitized_schema_name = schema_name.replace(" ", "_")
                        # Reconstruct the ID
                        sanitized_schema_id = f"{parts[0]}:{parts[1]}:{parts[2]}:{sanitized_schema_name}:{schema_version}"
                        
                        logging.debug(f"Original schema_id not found, trying sanitized version: {sanitized_schema_id}")
                        schema_record = await session.handle.fetch(
                            "anoncreds:schema", sanitized_schema_id
                        )
                
                if schema_record:
                    # Found in local wallet
                    try:
                        # Deserialize the JSON string to a dictionary
                        schema_data = json.loads(schema_record.value)
                        logging.debug(f"Successfully deserialized schema from wallet: {schema_data}")
                    except json.JSONDecodeError:
                        # If not a JSON string, try using it directly (for backward compatibility)
                        schema_data = schema_record.value
                        logging.debug("Using schema record value directly (not JSON)")
                    
                    issuer_id = schema_data.get("issuer_id", "")
                    schema_name = schema_data.get("name", "")
                    schema_version = schema_data.get("version", "")
                    attr_names = schema_data.get("attrNames", [])
                    
                    schema = Schema(
                        issuer_id=issuer_id,
                        name=schema_name,
                        version=schema_version,
                        attr_names=attr_names,
                    )
                    
                    # Use the original schema_id for the result
                    # to maintain compatibility with the caller's expectations
                    return GetSchemaResult(
                        schema_id=schema_id,
                        schema=schema,
                        resolution_metadata={},
                        schema_metadata={
                            "issuer": issuer_id,
                            "from": "wallet",
                            "blockchain_id": schema_data.get("blockchain_id", schema_id),
                        },
                    )
        except Exception as wallet_err:
            logging.debug(f"Local wallet lookup failed for schema={schema_id}, "
                          f"falling back to blockchain. Error: {wallet_err}")

        # 2) Not in wallet, try the blockchain
        try:
            # For blockchain lookup, we need to ensure we're using the original format
            blockchain_id = schema_id
            
            # Call the contract with the updated ABI
            schema_details, approved_issuers = self.kanon_contract.functions.getSchema(blockchain_id).call()
            
            if not schema_details:
                raise AnonCredsResolutionError(f"Schema not found on chain or invalid data for ID: {schema_id}")
            
            # Parse the schema details from JSON
            try:
                schema_data = json.loads(schema_details)
                schema_name = schema_data.get("name", "")
                attr_names = schema_data.get("attrNames", [])
                issuer_id = schema_data.get("issuerId", "")
            except json.JSONDecodeError:
                # Fallback if not valid JSON
                logging.warning(f"Schema details not valid JSON: {schema_details}")
                # Extract from schema_id
                parts = schema_id.split(":")
                issuer_id = ":".join(parts[0:3]) if len(parts) >= 3 else ""
                schema_name = parts[-2] if len(parts) >= 4 else ""
                attr_names = []
            
            # Extract version from schema_id
            # Format e.g.: did:kanon:xxxx:Example schema:1.0
            parts = schema_id.split(":")
            schema_version = parts[-1] if len(parts) >= 2 else "1.0"
            
            schema = Schema(
                issuer_id=issuer_id,
                name=schema_name,
                version=schema_version,
                attr_names=attr_names,
            )
            
            # Store in the local wallet for future
            try:
                async with profile.session() as session:
                    # Create a sanitized version of the ID for storage
                    parts = schema_id.split(":")
                    if len(parts) >= 4:
                        schema_name_part = parts[-2]
                        sanitized_schema_name = schema_name_part.replace(" ", "_")
                        sanitized_schema_id = f"{parts[0]}:{parts[1]}:{parts[2]}:{sanitized_schema_name}:{parts[-1]}"
                    else:
                        sanitized_schema_id = schema_id
                    
                    # Create the complete record value dictionary
                    record_value_dict = {
                        "issuer_id": issuer_id,
                        "name": schema_name,
                        "version": schema_version,
                        "attrNames": attr_names,
                        "blockchain_id": schema_id,
                        "schema_details": schema_details,
                        "approved_issuers": [str(addr) for addr in approved_issuers] if approved_issuers else [],
                    }
                    
                    # Serialize the entire record to JSON
                    record_value = json.dumps(record_value_dict)
                    
                    await session.handle.insert(
                        "anoncreds:schema",
                        sanitized_schema_id,
                        record_value,  # Store as JSON string
                        tags={"name": schema_name},
                    )
                    logging.debug(f"Cached schema from blockchain to wallet with ID={sanitized_schema_id}")
            except Exception as store_err:
                logging.warning(f"Failed to cache schema in wallet for {schema_id}: {store_err}")
            
            return GetSchemaResult(
                schema_id=schema_id,
                schema=schema,
                resolution_metadata={},
                schema_metadata={
                    "issuer": issuer_id, 
                    "from": "blockchain", 
                    "schema_details": schema_details,
                    "approved_issuers": [str(addr) for addr in approved_issuers] if approved_issuers else [],
                },
            )
        except Exception as err:
            raise AnonCredsResolutionError(f"Error retrieving schema from blockchain: {err}")

    async def get_credential_definition(
        self, profile, credential_definition_id
    ) -> GetCredDefResult:
        """
        Get credential definition from:
        1) The local wallet (if previously stored),
        2) The Kanon contract (blockchain) if not found locally.
        """
        from acapy_agent.anoncreds.models.cred_def import CredDef

        # 1) Attempt local wallet fetch
        try:
            async with profile.session() as session:
                # Try with the provided ID first
                cred_def_record = await session.handle.fetch(
                    "anoncreds:credential_definition", credential_definition_id
                )
                
                # If not found, try with a sanitized version of the ID
                if not cred_def_record:
                    # Create a sanitized version of the ID
                    parts = credential_definition_id.split(":")
                    if len(parts) >= 5:
                        # Extract the schema name and tag
                        schema_name = parts[-2]
                        tag = parts[-1]
                        # Create a sanitized schema name
                        sanitized_schema_name = schema_name.replace(" ", "_")
                        # Reconstruct the ID
                        sanitized_cred_def_id = f"{parts[0]}:{parts[1]}:{parts[2]}:{parts[3]}:{sanitized_schema_name}:{tag}"
                        
                        logging.debug(f"Original cred_def_id not found, trying sanitized version: {sanitized_cred_def_id}")
                        cred_def_record = await session.handle.fetch(
                            "anoncreds:credential_definition", sanitized_cred_def_id
                        )
                
                if cred_def_record:
                    # Found in local wallet
                    try:
                        # Deserialize the JSON string to a dictionary
                        cred_def_data = json.loads(cred_def_record.value)
                        logging.debug(f"Successfully deserialized cred def from wallet: {cred_def_data}")
                    except json.JSONDecodeError:
                        # If not a JSON string, try using it directly (for backward compatibility)
                        cred_def_data = cred_def_record.value
                        logging.debug("Using cred def record value directly (not JSON)")
                    
                    issuer_id = cred_def_data.get("issuer_id", "")
                    schema_id = cred_def_data.get("schema_id", "")
                    cred_def_type = cred_def_data.get("type", "CL")
                    tag = cred_def_data.get("tag", "")
                    value = cred_def_data.get("value", {})
                    
                    cred_def = CredDef(
                        issuer_id=issuer_id,
                        schema_id=schema_id,
                        type=cred_def_type,
                        tag=tag,
                        value=value,
                    )
                    
                    # Use the original credential_definition_id for the result
                    # to maintain compatibility with the caller's expectations
                    return GetCredDefResult(
                        credential_definition_id=credential_definition_id,
                        credential_definition=cred_def,
                        resolution_metadata={},
                        credential_definition_metadata={
                            "issuer": issuer_id,
                            "from": "wallet",
                            "blockchain_id": cred_def_data.get("blockchain_id", credential_definition_id),
                        },
                    )
        except Exception as wallet_err:
            logging.debug(f"Local wallet lookup failed for cred_def={credential_definition_id}, "
                          f"falling back to blockchain. Error: {wallet_err}")

        # 2) Not in wallet, try the blockchain
        try:
            # For blockchain lookup, we need to ensure we're using the original format
            blockchain_id = credential_definition_id
            
            # Call the contract with the updated ABI
            cred_def_value, issuer_id = self.kanon_contract.functions.getCredentialDefinition(blockchain_id).call()
            
            if not cred_def_value:
                raise AnonCredsResolutionError(f"Credential definition not found on chain or invalid data for ID: {credential_definition_id}")
            
            # Parse the credential definition from the blockchain
            try:
                # Try to parse as JSON
                cred_def_dict = json.loads(cred_def_value)
            except json.JSONDecodeError:
                # If not valid JSON, use as is
                cred_def_dict = {"value": cred_def_value}
            
            # Extract schema_id from credential_definition_id
            # Format: did:kanon:xxxx:schema_id:tag
            parts = credential_definition_id.split(":")
            schema_id = ":".join(parts[3:-1]) if len(parts) >= 5 else ""
            tag = parts[-1] if len(parts) >= 2 else ""
            
            cred_def = CredDef(
                issuer_id=issuer_id,
                schema_id=schema_id,
                type="CL",  # Default to CL type
                tag=tag,
                value=cred_def_dict.get("value", cred_def_value),
            )
            
            # Store in the local wallet for future
            try:
                async with profile.session() as session:
                    # Create a sanitized version of the ID for storage
                    parts = credential_definition_id.split(":")
                    if len(parts) >= 5:
                        schema_name_part = parts[-2]
                        sanitized_schema_name = schema_name_part.replace(" ", "_")
                        sanitized_cred_def_id = f"{parts[0]}:{parts[1]}:{parts[2]}:{parts[3]}:{sanitized_schema_name}:{parts[-1]}"
                    else:
                        sanitized_cred_def_id = credential_definition_id
                    
                    # Create the complete record value dictionary
                    record_value_dict = {
                        "issuer_id": issuer_id,
                        "schema_id": schema_id,
                        "type": "CL",
                        "tag": tag,
                        "value": cred_def_dict.get("value", cred_def_value),
                        "blockchain_id": credential_definition_id,
                        "cred_def_value": cred_def_value,
                    }
                    
                    # Serialize the entire record to JSON
                    record_value = json.dumps(record_value_dict)
                    
                    await session.handle.insert(
                        "anoncreds:credential_definition",
                        sanitized_cred_def_id,
                        record_value,  # Store as JSON string
                        tags={"tag": tag},
                    )
                    logging.debug(f"Cached cred def from blockchain to wallet with ID={sanitized_cred_def_id}")
            except Exception as store_err:
                logging.warning(f"Failed to cache cred def in wallet for {credential_definition_id}: {store_err}")
            
            return GetCredDefResult(
                credential_definition_id=credential_definition_id,
                credential_definition=cred_def,
                resolution_metadata={},
                credential_definition_metadata={
                    "issuer": issuer_id, 
                    "from": "blockchain", 
                    "cred_def_value": cred_def_value,
                },
            )
        except Exception as err:
            raise AnonCredsResolutionError(f"Error retrieving credential definition from blockchain: {err}")

    async def get_revocation_registry_definition(self, profile, revocation_registry_id) -> GetRevRegDefResult:
        """Not supported in the Kanon contract (no on-chain rev reg definitions)."""
        raise NotImplementedError("Revocation registry definition not supported in Kanon contract")

    async def get_revocation_list(
        self,
        profile,
        revocation_registry_id: str,
        timestamp_from_: int,
        timestamp_to: int,
    ) -> GetRevListResult:
        """Not implemented: Kanon uses per-credential revocation checks instead of rev lists."""
        raise NotImplementedError("Revocation list retrieval not implemented for Kanon contract")

    async def get_schema_info_by_id(self, profile, schema_id) -> AnoncredsSchemaInfo:
        """Simplified helper to get schema info. This may not always be called by ACA-Py."""
        result = await self.get_schema(profile, schema_id)
        fetched_schema = result.schema if result else None
        if not fetched_schema:
            raise AnonCredsResolutionError(f"Schema not found for schema_id={schema_id}")

        # Derive name/version from the fetched schema (fallback as needed)
        name = fetched_schema.name or "Unknown"
        version = fetched_schema.version or "1.0"
        issuer_id = fetched_schema.issuer_id or ""
        return AnoncredsSchemaInfo(
            issuer_id=issuer_id,
            name=name,
            version=version,
        )

    async def register_schema(
        self, profile, schema, options: dict = None
    ) -> SchemaResult:
        """
        Register a schema on the Kanon contract and store it in the local wallet.
        """
        from acapy_agent.anoncreds.models.schema import SchemaState

        # Validate schema
        if not schema.attr_names or len(schema.attr_names) < 1:
            raise AnonCredsRegistrationError("Schema must have at least one attribute")

        # Construct schema ID
        schema_id = f"{schema.issuer_id}:{schema.name}:{schema.version}"
        
        # Create a sanitized version for storage (replace spaces with underscores)
        sanitized_schema_name = schema.name.replace(" ", "_")
        sanitized_schema_id = f"{schema.issuer_id}:{sanitized_schema_name}:{schema.version}"
        
        # Prepare schema data for the contract with updated ABI
        schema_details = json.dumps({
            "name": schema.name,
            "attrNames": schema.attr_names,
            "issuerId": schema.issuer_id
        })
        
        # Register on the Kanon contract
        try:
            async with profile.session() as session:
                # Get the issuer's Ethereum address from the wallet
                issuer_did = schema.issuer_id
                
                # Prepare the transaction
                tx = self.kanon_contract.functions.registerSchema(
                    schema_id,  # _schemaId
                    schema_details,  # _details
                    issuer_did  # _issuerId
                ).build_transaction({
                    'from': self.eth_account.address,
                    'nonce': self.web3.eth.get_transaction_count(self.eth_account.address),
                    'gas': 2000000,
                    'gasPrice': self.web3.eth.gas_price
                })
                
                # Sign the transaction
                signed_tx = self.web3.eth.account.sign_transaction(tx, self.operator_key)
                
                # Send the transaction
                tx_hash = self.web3.eth.send_raw_transaction(signed_tx.rawTransaction)
                logging.debug(f"Transaction sent: {tx_hash.hex()}")
                
                # Wait for transaction receipt
                tx_receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash)
                if tx_receipt.status != 1:
                    raise AnonCredsRegistrationError(f"Transaction failed: {tx_receipt}")
                
                logging.debug(f"Schema registered on blockchain with ID={schema_id}, tx={tx_hash.hex()}")
                
                # Store in the local wallet
                # Create the complete record value dictionary
                record_value_dict = {
                    "issuer_id": schema.issuer_id,
                    "name": schema.name,
                    "version": schema.version,
                    "attrNames": schema.attr_names,
                    "blockchain_id": schema_id,
                    "schema_details": schema_details,
                }
                
                # Serialize the entire record to JSON
                record_value = json.dumps(record_value_dict)
                
                # Store in the wallet
                await session.handle.insert(
                    "anoncreds:schema",
                    sanitized_schema_id,
                    record_value,  # Store as JSON string
                    tags={"name": schema.name},
                )
                
                logging.debug(f"Schema stored in wallet with ID={sanitized_schema_id}")
                
                # Create schema state
                schema_state = SchemaState(
                    state=SchemaState.STATE_FINISHED,
                    schema_id=schema_id,
                    schema=schema,
                )
                
                # Return the result
                return SchemaResult(
                    job_id="",
                    schema_state=schema_state,
                    registration_metadata={
                        "tx_hash": tx_hash.hex(),
                        "issuer_id": schema.issuer_id,
                        "schema_details": schema_details,
                    },
                )
        except Exception as err:
            raise AnonCredsRegistrationError(f"Error registering schema: {err}")

    async def register_credential_definition(
        self, profile, credential_definition, options: dict = None
    ) -> CredDefResult:
        """
        Register a credential definition on the Kanon contract and store it in the local wallet.
        """
        from acapy_agent.anoncreds.models.cred_def import CredDefState

        # Extract schema_id from the credential definition
        schema_id = credential_definition.schema_id
        
        # Get the schema to ensure it exists
        try:
            schema_result = await self.get_schema(profile, schema_id)
            if not schema_result or not schema_result.schema:
                raise AnonCredsRegistrationError(f"Schema not found for ID: {schema_id}")
        except Exception as err:
            raise AnonCredsRegistrationError(f"Error retrieving schema: {err}")
        
        # Construct credential definition ID
        issuer_did = credential_definition.issuer_id
        cred_def_id = f"{issuer_did}:3:CL:{schema_id}:{credential_definition.tag}"
        
        # Create a sanitized version for storage (replace spaces with underscores)
        parts = schema_id.split(":")
        if len(parts) >= 3:
            schema_name = parts[-2]
            sanitized_schema_name = schema_name.replace(" ", "_")
            sanitized_schema_id = f"{parts[0]}:{parts[1]}:{parts[2]}:{sanitized_schema_name}:{parts[-1]}"
            sanitized_cred_def_id = f"{issuer_did}:3:CL:{sanitized_schema_id}:{credential_definition.tag}"
        else:
            sanitized_cred_def_id = cred_def_id
        
        # Helper function to convert objects to dictionaries for serialization
        def obj_to_dict(obj):
            if hasattr(obj, "__dict__"):
                return {k: obj_to_dict(v) for k, v in obj.__dict__.items() if not k.startswith("_")}
            elif isinstance(obj, dict):
                return {k: obj_to_dict(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [obj_to_dict(item) for item in obj]
            else:
                return obj
        
        # Serialize the credential definition value
        cred_def_value = obj_to_dict(credential_definition.value)
        cred_def_value_json = json.dumps(cred_def_value)
        
        # Register on the Kanon contract
        try:
            async with profile.session() as session:
                # Prepare the transaction
                # This transaction registers the credential definition on the Kanon contract
                # using the updated ABI
                tx = self.kanon_contract.functions.registerCredentialDefinition(
                    cred_def_id,  # _credDefId
                    schema_id,     # _schemaId
                    issuer_did     # _issuerId
                ).build_transaction({
                    'from': self.eth_account.address,
                    'nonce': self.web3.eth.get_transaction_count(self.eth_account.address),
                    'gas': 2000000,
                    'gasPrice': self.web3.eth.gas_price
                })
                
                # Sign the transaction
                signed_tx = self.web3.eth.account.sign_transaction(tx, self.operator_key)
                
                # Send the transaction
                tx_hash = self.web3.eth.send_raw_transaction(signed_tx.rawTransaction)
                logging.debug(f"Transaction sent: {tx_hash.hex()}")
                
                # Wait for transaction receipt
                tx_receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash)
                if tx_receipt.status != 1:
                    raise AnonCredsRegistrationError(f"Transaction failed: {tx_receipt}")
                
                logging.debug(f"Credential definition registered on blockchain with ID={cred_def_id}, tx={tx_hash.hex()}")
                
                # Store in the local wallet
                # Create the complete record value dictionary
                record_value_dict = {
                    "issuer_id": issuer_did,
                    "schema_id": schema_id,
                    "type": credential_definition.type,
                    "tag": credential_definition.tag,
                    "value": cred_def_value,
                    "blockchain_id": cred_def_id,
                }
                
                # Serialize the entire record to JSON
                record_value = json.dumps(record_value_dict)
                
                # Store in the wallet
                await session.handle.insert(
                    "anoncreds:credential_definition",
                    sanitized_cred_def_id,
                    record_value,  # Store as JSON string
                    tags={"tag": credential_definition.tag},
                )
                
                logging.debug(f"Credential definition stored in wallet with ID={sanitized_cred_def_id}")
                
                # Create credential definition state
                cred_def_state = CredDefState(
                    state=CredDefState.STATE_FINISHED,
                    credential_definition_id=cred_def_id,
                    credential_definition=credential_definition,
                )
                
                # Return the result
                return CredDefResult(
                    job_id="",
                    credential_definition_state=cred_def_state,
                    registration_metadata={
                        "tx_hash": tx_hash.hex(),
                        "issuer_id": issuer_did,
                    },
                )
        except Exception as err:
            raise AnonCredsRegistrationError(f"Error registering credential definition: {err}")

    async def register_revocation_registry_definition(
        self, profile, revocation_registry_definition, options=None
    ) -> RevRegDefResult:
        """Not supported by the Kanon contract."""
        raise NotImplementedError("Revocation registry definition not supported in Kanon contract")

    async def register_revocation_list(self, profile, rev_reg_def, rev_list, options=None) -> RevListResult:
        """
        Simulate revocation by calling revokeCredential for each credential ID.
        Not truly an AnonCreds revocation list, but an example approach.
        """
        from acapy_agent.anoncreds.models.revocation import RevListState
        
        async with profile.session() as session:
            wallet = inject_or_fail(session, BaseWallet, AnonCredsResolutionError)
            receipts = []
            for cred_id in rev_list.credential_ids:
                nonce = self.web3.eth.get_transaction_count(self.eth_account.address)
                txn = self.kanon_contract.functions.revokeCredential(cred_id).build_transaction({
                    "from": self.eth_account.address,
                    "nonce": nonce,
                    "gas": 200000,
                    "gasPrice": self.web3.to_wei("20", "gwei"),
                })
                signed_txn = self.web3.eth.account.sign_transaction(txn, self.operator_key)
                tx_hash = self.web3.eth.send_raw_transaction(signed_txn.rawTransaction)
                receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash)
                receipts.append(receipt)

            # Create a revocation list state
            rev_list_state = RevListState(
                state=RevListState.STATE_FINISHED,
                revocation_list=rev_list
            )
            
            # Return the result directly
            return RevListResult(
                job_id=None,
                revocation_list_state=rev_list_state,
                registration_metadata={},
                revocation_list_metadata={}
            )

    async def update_revocation_list(
        self,
        profile,
        rev_reg_def,
        prev_list,
        curr_list,
        revoked,
        options=None
    ) -> RevListResult:
        """
        Update revocation by revoking the newly 'revoked' credentials and notify event bus.
        (Still not a standard AnonCreds rev list, more a direct approach.)
        """
        from acapy_agent.anoncreds.models.revocation import RevListState
        
        async with profile.session() as session:
            wallet = inject_or_fail(session, BaseWallet, AnonCredsResolutionError)
            event_bus = inject_or_fail(session, EventBus, AnonCredsResolutionError)
            receipts = []
            for cred_id in revoked:
                nonce = self.web3.eth.get_transaction_count(self.eth_account.address)
                txn = self.kanon_contract.functions.revokeCredential(cred_id).build_transaction({
                    "from": self.eth_account.address,
                    "nonce": nonce,
                    "gas": 200000,
                    "gasPrice": self.web3.to_wei("20", "gwei"),
                })
                signed_txn = self.web3.eth.account.sign_transaction(txn, self.operator_key)
                tx_hash = self.web3.eth.send_raw_transaction(signed_txn.rawTransaction)
                receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash)
                receipts.append(receipt)

            await event_bus.notify(
                profile,
                RevListFinishedEvent.with_payload(curr_list.rev_reg_def_id, list(revoked))
            )
            
            # Create a revocation list state
            rev_list_state = RevListState(
                state=RevListState.STATE_FINISHED,
                revocation_list=curr_list
            )
            
            # Return the result directly
            return RevListResult(
                job_id=None,
                revocation_list_state=rev_list_state,
                registration_metadata={},
                revocation_list_metadata={}
            )
