import re
import time
import json
from typing import Pattern, Optional
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

from acapy_agent.anoncreds.models.credential_definition import CredDefState, CredDef
from acapy_agent.anoncreds.events import RevListFinishedEvent
from acapy_agent.anoncreds.models.schema_info import AnoncredsSchemaInfo
from acapy_agent.core.event_bus import EventBus
from acapy_agent.core.profile import Profile
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
from acapy_agent.anoncreds.models.schema import Schema as AnoncredsSchema

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
        """Get schema from the Kanon contract.

        Calls the smart contract's getSchema function which returns the schema details
        and a list of approved issuers.
        """
        try:
            # getSchema returns (schemaDetails, approvedIssuers)
            schema_details, approved_issuers = self.kanon_contract.functions.getSchema(schema_id).call()
        except Exception as e:
            raise AnonCredsResolutionError(str(e))
        if not schema_details:
            raise AnonCredsResolutionError("Failed to retrieve schema")
        try:
            # Parse the schema details from JSON string
            schema_dict = json.loads(schema_details)
            # Create the response objects directly
            from acapy_agent.anoncreds.base import GetSchemaResult
            from acapy_agent.anoncreds.models.schema import AnonCredsSchema


            # Create AnonCredsSchema object
            schema = AnonCredsSchema(
                issuer_id=schema_dict.get("issuerId", ""),
                name=schema_dict.get("name", ""),
                version=schema_dict.get("version", ""),
                attr_names=schema_dict.get("attrNames", [])
            )

            # Create metadata
            metadata = {
                "details": schema_details,
                "approved_issuers": approved_issuers
            }
            # Return GetSchemaResult directly
            return GetSchemaResult(
                schema=schema,
                schema_id=schema_id,
                resolution_metadata=None,
                schema_metadata=metadata
            )
            
        except json.JSONDecodeError:
            # If schema_details is not valid JSON, use a simpler approach
            # Build a response object that matches what build_acapy_get_schema_result expects
            class SchemaResponse:
                def __init__(self, schema):
                    self.schema = schema
            
            kanon_res = SchemaResponse({
                "schema_id": schema_id,
                "details": schema_details,
                "approved_issuers": approved_issuers,
            })
            
            return build_acapy_get_schema_result(kanon_res)


    async def get_credential_definition(
        self,
        profile: Profile,
        credential_definition_id: str,
        _options: Optional[dict] = None,
    ) -> CredDefResult:
        """Get a credential definition from the registry."""
        
        # Sanitize the credential definition ID for wallet lookup
        parts = credential_definition_id.split(":")
        if len(parts) >= 5:
            schema_parts = parts[3].split(":")
            if len(schema_parts) >= 2:
                schema_name = schema_parts[-2]
                sanitized_schema_name = schema_name.replace(" ", "_")
                sanitized_cred_def_id = f"{parts[0]}:{parts[1]}:{parts[2]}:{sanitized_schema_name}:{parts[4]}"
            else:
                sanitized_cred_def_id = credential_definition_id
        else:
            sanitized_cred_def_id = credential_definition_id

        try:
            async with profile.session() as session:
                # Try to get from wallet first
                try:
                    wallet_record = await session.handle.fetch(
                        "anoncreds:credential_definition",
                        sanitized_cred_def_id
                    )
                    if wallet_record:
                        record_value = json.loads(wallet_record.value)
                        cred_def = CredDef(
                            issuer_id=record_value["issuerId"],
                            schema_id=record_value["schemaId"],
                            type=record_value["type"],
                            tag=record_value["tag"],
                            value=record_value["value"]
                        )
                        cred_def_state = CredDefState(
                            state=CredDefState.STATE_FINISHED,
                            credential_definition_id=credential_definition_id,
                            credential_definition=cred_def
                        )
                        return CredDefResult(
                            job_id="",
                            credential_definition_state=cred_def_state,
                            registration_metadata={
                                "from": "wallet",
                                "tx_hash": record_value.get("tx_hash"),
                                "registration_time": record_value.get("registration_time")
                            },
                            credential_definition_metadata={
                                "wallet_id": sanitized_cred_def_id,
                                "blockchain_id": credential_definition_id,
                                "registration_time": record_value.get("registration_time")
                            }
                        )
                except Exception as wallet_err:
                    logging.debug(f"Error fetching from wallet: {wallet_err}")

                # If not in wallet, try to get from blockchain
                try:
                    # Call the contract function directly without await
                    cred_def_data = self.kanon_contract.functions.getCredentialDefinition(
                        credential_definition_id
                    ).call()
                    
                    if not cred_def_data or not cred_def_data[0]:  # Assuming first element indicates existence
                        raise AnonCredsRegistrationError(f"Credential definition not found: {credential_definition_id}")
                    
                    # Create credential definition object from blockchain data
                    cred_def = CredDef(
                        issuer_id=cred_def_data[1],  # issuerId
                        schema_id=cred_def_data[0],   # schemaId
                        type="CL",
                        tag=parts[4] if len(parts) >= 5 else "",
                        value={}  # You might need to adjust this based on your needs
                    )
                    
                    cred_def_state = CredDefState(
                        state=CredDefState.STATE_FINISHED,
                        credential_definition_id=credential_definition_id,
                        credential_definition=cred_def
                    )
                    
                    return CredDefResult(
                        job_id="",
                        credential_definition_state=cred_def_state,
                        registration_metadata={
                            "from": "blockchain",
                            "issuerId": cred_def_data[1]
                        },
                        credential_definition_metadata={
                            "blockchain_id": credential_definition_id,
                            "schema_id": cred_def_data[0],
                            "issuer_id": cred_def_data[1]
                        }
                    )
                    
                except Exception as blockchain_err:
                    raise AnonCredsRegistrationError(f"Error retrieving from blockchain: {blockchain_err}")
                
        except Exception as err:
            raise AnonCredsRegistrationError(f"Error retrieving credential definition: {err}")

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
            "issuerId": schema.issuer_id,
            "version": schema.version
        })
        
        # Register on the Kanon contract
        try:
            async with profile.session() as session:
                # Get the issuer's Ethereum address from the wallet
                issuer_did = schema.issuer_id
                
                # Check if schema already exists in wallet
                try:
                    existing_schema = await session.handle.fetch(
                        "anoncreds:schema",
                        sanitized_schema_id
                    )
                    if existing_schema:
                        logging.info(f"Schema already exists in wallet with ID={sanitized_schema_id}")
                        schema_state = SchemaState(
                            state=SchemaState.STATE_FINISHED,
                            schema_id=schema_id,
                            schema=schema,
                        )
                        return SchemaResult(
                            job_id="",
                            schema_state=schema_state,
                            registration_metadata={
                                "from": "wallet",
                                "issuerId": schema.issuerId,
                            },
                        )
                except Exception as wallet_err:
                    logging.debug(f"Error checking wallet for schema: {wallet_err}")
                
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
                    "issuerId": schema.issuer_id,
                    "name": schema.name,
                    "version": schema.version,
                    "attrNames": schema.attr_names,
                    "blockchain_id": schema_id,
                    "schema_details": schema_details,
                    "tx_hash": tx_hash.hex(),
                    "registration_time": int(time.time())
                }
                
                # Serialize the entire record to JSON
                record_value = json.dumps(record_value_dict)
                
                # Store in the wallet with additional tags for better querying
                await session.handle.insert(
                    "anoncreds:schema",
                    sanitized_schema_id,
                    record_value,  # Store as JSON string
                    tags={
                        "name": schema.name,
                        "version": schema.version,
                        "issuerId": schema.issuer_id,
                        "blockchain_id": schema_id
                    }
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
                        "issuerId": schema.issuer_id,
                        "schema_details": schema_details,
                        "wallet_id": sanitized_schema_id
                    },
                )
        except Exception as err:
            raise AnonCredsRegistrationError(f"Error registering schema: {err}")

    async def register_credential_definition(
        self,
        profile: Profile,
        schema: GetSchemaResult,
        credential_definition: CredDef,
        _options: Optional[dict] = None,
    ) -> CredDefResult:
        """Register a credential definition on the registry."""
        from acapy_agent.anoncreds.models.credential_definition import CredDefState

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
                # Check if credential definition already exists in wallet
                try:
                    existing_cred_def = await session.handle.fetch(
                        "anoncreds:credential_definition",
                        sanitized_cred_def_id
                    )
                    if existing_cred_def:
                        logging.info(f"Credential definition already exists in wallet with ID={sanitized_cred_def_id}")
                        cred_def_state = CredDefState(
                            state=CredDefState.STATE_FINISHED,
                            credential_definition_id=cred_def_id,
                            credential_definition=credential_definition,
                        )
                        return CredDefResult(
                            job_id="",
                            credential_definition_state=cred_def_state,
                            registration_metadata={
                                "from": "wallet",
                                "issuerId": issuer_did,
                            },
                            credential_definition_metadata={
                                "wallet_id": sanitized_cred_def_id,
                                "blockchain_id": cred_def_id,
                                "registration_time": int(time.time())
                            }
                        )
                except Exception as wallet_err:
                    logging.debug(f"Error checking wallet for credential definition: {wallet_err}")
                
                # Prepare the transaction
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
                    "issuerId": issuer_did,
                    "schemaId": schema_id,
                    "type": credential_definition.type,
                    "tag": credential_definition.tag,
                    "value": cred_def_value,
                    "blockchain_id": cred_def_id,
                    "tx_hash": tx_hash.hex(),
                    "registration_time": int(time.time())
                }
                
                # Serialize the entire record to JSON
                record_value = json.dumps(record_value_dict)
                
                # Store in the wallet with additional tags for better querying
                await session.handle.insert(
                    "anoncreds:credential_definition",
                    sanitized_cred_def_id,
                    record_value,  # Store as JSON string
                    tags={
                        "tag": credential_definition.tag,
                        "schemaId": schema_id,
                        "issuerId": issuer_did,
                        "blockchain_id": cred_def_id
                    }
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
                        "issuerId": issuer_did,
                        "wallet_id": sanitized_cred_def_id
                    },
                    credential_definition_metadata={
                        "wallet_id": sanitized_cred_def_id,
                        "blockchain_id": cred_def_id,
                        "registration_time": int(time.time())
                    }
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

    async def get_all_schemas(self, profile) -> list:
        """Get all schemas from the wallet."""
        try:
            async with profile.session() as session:
                # Search for all schema records
                schema_records = await session.handle.search_records(
                    "anoncreds:schema",
                    {},  # Empty dict to get all records
                    None,  # No limit
                    {"name": "asc"}  # Sort by name
                )
                
                schemas = []
                async for record in schema_records:
                    try:
                        # Parse the schema data
                        schema_data = json.loads(record.value)
                        logging.debug(f"Parsing schema record {record.id}")
                        logging.debug(f"Schema data from record: {schema_data}")
                        
                        # Create schema object
                        try:
                            schema = AnoncredsSchema(
                                {
                                    "version": schema_data.get("version", ""),
                                    "attrNames": schema_data.get("attrNames", [])
                                }
                            )
                            logging.debug(f"Successfully created schema for record {record.id}: {vars(schema)}")
                        except Exception as schema_err:
                            logging.error(f"Error creating schema for record {record.id}: {schema_err}")
                            logging.error(f"Schema data used: {schema_data}")
                            raise
                        
                        # Add to results
                        schemas.append({
                            "schema_id": record.id,
                            "schema": schema,
                            "metadata": {
                                "issuer": schema_data.get("issuerId", ""),
                                "from": "wallet",
                                "blockchain_id": schema_data.get("blockchain_id", record.id),
                                "registration_time": schema_data.get("registration_time"),
                                "tx_hash": schema_data.get("tx_hash"),
                                "from_cache": schema_data.get("from_cache", False)
                            }
                        })
                    except Exception as parse_err:
                        logging.warning(f"Error parsing schema record {record.id}: {parse_err}")
                        continue
                
                return schemas
        except Exception as err:
            logging.error(f"Error retrieving schemas from wallet: {err}")
            return []
