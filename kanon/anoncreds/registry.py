import re
import time
import json
from typing import Pattern, cast
import logging

from acapy_agent.anoncreds.base import (
    AnonCredsObjectNotFound,
    AnonCredsResolutionError,
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

# Define the Kanon contract ABI directly in the file
KANON_CONTRACT_ABI = [
    {
        "inputs": [{"internalType": "string", "name": "schemaId", "type": "string"}],
        "name": "getSchema",
        "outputs": [
            {"internalType": "string", "name": "details", "type": "string"},
            {"internalType": "address[]", "name": "approvedIssuers", "type": "address[]"}
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [{"internalType": "string", "name": "credDefId", "type": "string"}],
        "name": "getCredentialDefinition",
        "outputs": [
            {"internalType": "string", "name": "schemaId", "type": "string"},
            {"internalType": "address", "name": "issuer", "type": "address"}
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
            {"internalType": "string", "name": "credDefId", "type": "string"},
            {"internalType": "string", "name": "schemaId", "type": "string"},
            {"internalType": "address", "name": "issuer", "type": "address"}
        ],
        "name": "registerCredentialDefinition",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [{"internalType": "string", "name": "credentialId", "type": "string"}],
        "name": "revokeCredential",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [{"internalType": "string", "name": "credentialId", "type": "string"}],
        "name": "isCredentialRevoked",
        "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
        "stateMutability": "view",
        "type": "function"
    }
]

def _validate_resolution_result(result, attribute_name):
    """Validate resolution result."""
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
    """AnonCreds registry for the Kanon contract.

    This class adapts the AnonCreds registry logic to use a Kanon
    smart contract deployed on an EVM chain. It leverages contract functions
    for schema, credential definition, and revocation management.
    """

    def __init__(self):
        """Initializer."""
        self._supported_identifiers_regex = re.compile("^did:kanon:.*$")

    @property
    def supported_identifiers_regex(self) -> Pattern:
        """Supported identifiers regular expression."""
        return self._supported_identifiers_regex

    async def setup(self, context):
        """Setup the registry using context settings.

        Reads the EVM provider URL and Kanon contract address from settings.
        Uses the ABI defined in this file.
        """
        settings = Config.from_settings(context.settings)
        self.web3 = Web3(Web3.HTTPProvider(settings.web3_provider_url))
        self.operator_key = settings.operator_key
        self.account = self.web3.eth.account.from_key(self.operator_key)
        self.kanon_contract = self.web3.eth.contract(
            address=settings.contract_address,
            abi=KANON_CONTRACT_ABI,
        )

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

    async def get_credential_definition(self, profile, credential_definition_id) -> GetCredDefResult:
        """Get credential definition from the Kanon contract.

        Calls the smart contract's getCredentialDefinition function which returns the
        schema ID and issuer for the given credential definition ID.
        """
        try:
            schema_id, issuer = self.kanon_contract.functions.getCredentialDefinition(credential_definition_id).call()
        except Exception as e:
            raise AnonCredsResolutionError(str(e))
        if not schema_id:
            raise AnonCredsResolutionError("Failed to retrieve credential definition")
        
        # Extract tag from credential definition ID
        tag = credential_definition_id.split(":")[-1]
        
        # Create a more complex nested structure to match what build_acapy_get_cred_def_result expects
        class CredDefValue:
            def __init__(self):
                self.primary = {"n": "", "s": "", "r": {}, "rctxt": "", "z": ""}
                self.revocation = None
        
        class CredentialDefinition:
            def __init__(self, cred_def_id, schema_id, issuer, tag):
                self.cred_def_id = cred_def_id
                self.schema_id = schema_id
                self.issuer_id = issuer
                self.type = "CL"
                self.tag = tag
                self.value = CredDefValue()
        
        # Create the response object that matches the expected structure in types.py
        from acapy_agent.anoncreds.models.credential_definition import GetCredDefResult
        
        return GetCredDefResult(
            credential_definition_id=credential_definition_id,
            credential_definition=CredentialDefinition(
                cred_def_id=credential_definition_id,
                schema_id=schema_id,
                issuer=issuer,
                tag=tag
            ),
            resolution_metadata={},
            credential_definition_metadata={"issuer": issuer}
        )

    async def get_revocation_registry_definition(self, profile, revocation_registry_id) -> GetRevRegDefResult:
        """Get revocation registry definition.

        This function is not supported in the Kanon contract; raise an error.
        """
        raise NotImplementedError("Revocation registry definition not supported in Kanon contract")

    async def get_revocation_list(
        self, profile, revocation_registry_id: str, timestamp_from_: int, timestamp_to: int
    ) -> GetRevListResult:
        """Get revocation list.

        In this Kanon implementation, a dedicated revocation list is not maintained on-chain.
        Instead, individual credential revocation status is available via isCredentialRevoked.
        """
        raise NotImplementedError("Revocation list retrieval not implemented for Kanon contract")

    async def get_schema_info_by_id(self, profile, schema_id) -> AnoncredsSchemaInfo:
        """Get schema info by schema id."""
        result = await self.get_schema(profile, schema_id)
        schema = result.get("schema")
        if not schema:
            raise AnonCredsResolutionError("Schema not found")
        # For this example, we assume the schema details include the name.
        return AnoncredsSchemaInfo(
            issuer_id="",  # Issuer ID is not returned by getSchema; adjust if available.
            name=schema.get("details"),
            version="1.0",  # Default version or parse from details if available.
        )

    async def register_schema(self, profile, schema, options=None) -> SchemaResult:
        """Register a schema on the Kanon contract.

        Signs the transaction using the issuer's private key and calls registerSchema.
        
        """
        async with profile.session() as session:
            print(schema)
            issuer_did = schema.issuer_id
            schema_id = schema.issuer_id + ":" + schema.name + ":" + schema.version
            wallet = inject_or_fail(session, BaseWallet, AnonCredsResolutionError)
            
            schema_dict = {
                "name": schema.name,
                "version": schema.version,
                "attrNames": schema.attr_names,
                "issuerId": schema.issuer_id
            }
            
            # Convert the dictionary to a JSON string
            schema_payload = json.dumps(schema_dict)
            
            nonce = self.web3.eth.get_transaction_count(self.account.address)
            txn = self.kanon_contract.functions.registerSchema(
                schema_id, 
                schema_payload,
                issuer_did 
            ).build_transaction({
                'from': self.account.address,
                'nonce': nonce,
                'gas': 300000,
                'gasPrice': self.web3.to_wei('20', 'gwei'),
            })
            signed_txn = self.web3.eth.account.sign_transaction(txn, self.operator_key)
            tx_hash = self.web3.eth.send_raw_transaction(signed_txn.rawTransaction)
            receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash)
            
            from acapy_agent.anoncreds.base import SchemaResult
            from acapy_agent.anoncreds.models.schema import AnonCredsSchema, SchemaState
            
            # Create the schema state object
            schema_state = SchemaState(
                state="published",
                schema_id=schema_id,
                schema=AnonCredsSchema(
                    issuer_id=schema.issuer_id,
                    name=schema.name,
                    version=schema.version,
                    attr_names=schema.attr_names
                )
            )
            
            # Create metadata dictionary
            metadata = {
                "details": schema_payload,
                "tx_receipt": str(receipt)  # Convert receipt to string for serialization
            }
            
            # Generate a job_id (using transaction hash as a unique identifier)
            job_id = str(tx_hash.hex())
            
            # Return the SchemaResult directly with job_id
            return SchemaResult(
                schema_state=schema_state,
                schema_metadata=metadata,
                job_id=job_id
            )

    async def register_credential_definition(
        self, profile, schema, credential_definition, options=None
    ) -> CredDefResult:
        """Register a credential definition on the Kanon contract.

        Signs the transaction using the issuer's private key and calls registerCredentialDefinition.
        """
        async with profile.session() as session:
            print("Schema:", schema)
            print("Credential Definition:", credential_definition)
            
            # Extract issuer DID from schema
            issuer_did = schema.schema.issuer_id
            wallet = inject_or_fail(session, BaseWallet, AnonCredsResolutionError)
            
            # Construct credential definition ID if not available
            # Format: issuer_did:3:CL:schema_id:tag
            cred_def_id = f"{issuer_did}:3:CL:{schema.schema_id}:{credential_definition.tag}"
            
            # Convert CredDefValue to a serializable dictionary
            def convert_to_dict(obj):
                if hasattr(obj, '__dict__'):
                    result = {}
                    for key, val in obj.__dict__.items():
                        if key.startswith('_'):
                            continue
                        if hasattr(val, '__dict__') or isinstance(val, list) or isinstance(val, dict):
                            result[key] = convert_to_dict(val)
                        else:
                            result[key] = val
                    return result
                elif isinstance(obj, list):
                    return [convert_to_dict(item) for item in obj]
                elif isinstance(obj, dict):
                    return {key: convert_to_dict(val) for key, val in obj.items()}
                else:
                    return obj
            
            # Create a serializable dictionary for the credential definition
            cred_def_dict = {
                "type": credential_definition.type,
                "tag": credential_definition.tag,
                "value": convert_to_dict(credential_definition.value)
            }
            
            # Convert to JSON string
            cred_def_payload = json.dumps(cred_def_dict)
            
            nonce = self.web3.eth.get_transaction_count(self.account.address)
            txn = self.kanon_contract.functions.registerCredentialDefinition(
                cred_def_id,
                schema.schema_id,
                self.account.address  # Issuer address
            ).build_transaction({
                'from': self.account.address,
                'nonce': nonce,
                'gas': 300000,
                'gasPrice': self.web3.to_wei('20', 'gwei'),
            })
            signed_txn = self.web3.eth.account.sign_transaction(txn, self.operator_key)
            tx_hash = self.web3.eth.send_raw_transaction(signed_txn.rawTransaction)
            receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash)
            
            # Create CredDefResult directly
            from acapy_agent.anoncreds.base import CredDefResult
            from acapy_agent.anoncreds.models.credential_definition import CredentialDefinition, CredDefState
            
            # Create the credential definition state object with correct parameters
            cred_def_state = CredDefState(
                state="published",
                credential_definition_id=cred_def_id,  # Use credential_definition_id instead of cred_def_id
                credential_definition=credential_definition  # Use credential_definition instead of cred_def
            )
            
            # Create metadata dictionaries
            registration_metadata = {
                "tx_hash": str(tx_hash.hex())
            }
            
            credential_definition_metadata = {
                "payload": cred_def_payload,
                "tx_receipt": str(receipt)  # Convert receipt to string for serialization
            }
            
            # Generate a job_id (using transaction hash as a unique identifier)
            job_id = str(tx_hash.hex())
            
            # Return the CredDefResult directly with all required parameters
            return CredDefResult(
                credential_definition_state=cred_def_state,  # Use credential_definition_state instead of cred_def_state
                registration_metadata=registration_metadata,  # Add registration_metadata
                credential_definition_metadata=credential_definition_metadata,  # Use credential_definition_metadata instead of cred_def_metadata
                job_id=job_id
            )

    async def register_revocation_registry_definition(
        self, profile, revocation_registry_definition, options=None
    ) -> RevRegDefResult:
        """Register revocation registry definition.

        Not supported by the Kanon contract.
        """
        raise NotImplementedError("Revocation registry definition not supported in Kanon contract")

    async def register_revocation_list(self, profile, rev_reg_def, rev_list, options=None) -> RevListResult:
        """Register a revocation list on the Kanon contract.

        In this implementation, we simulate revocation by calling the revokeCredential function
        for each credential ID listed in the revocation list.
        """
        async with profile.session() as session:
            issuer_did = rev_reg_def.issuer_id
            wallet = inject_or_fail(session, BaseWallet, AnonCredsResolutionError)
            receipts = []
            # Assume rev_list.credential_ids is a list of credential IDs to revoke.
            for cred_id in rev_list.credential_ids:
                nonce = self.web3.eth.get_transaction_count(self.account.address)
                txn = self.kanon_contract.functions.revokeCredential(cred_id).build_transaction({
                    'from': self.account.address,
                    'nonce': nonce,
                    'gas': 200000,
                    'gasPrice': self.web3.to_wei('20', 'gwei'),
                })
                signed_txn = self.web3.eth.account.sign_transaction(txn, self.operator_key)
                tx_hash = self.web3.eth.send_raw_transaction(signed_txn.rawTransaction)
                receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash)
                receipts.append(receipt)
            kanon_res = {
                "revocation_list": {
                    "rev_reg_def_id": rev_list.rev_reg_def_id,
                    "receipts": receipts,
                }
            }
            return build_acapy_rev_list_result(kanon_res)

    async def update_revocation_list(
        self, profile, rev_reg_def, prev_list, curr_list, revoked, options=None
    ) -> RevListResult:
        """Update the revocation list on the Kanon contract.

        This implementation revokes additional credentials provided in the 'revoked' list and notifies the event bus.
        """
        async with profile.session() as session:
            issuer_did = rev_reg_def.issuer_id
            wallet = inject_or_fail(session, BaseWallet, AnonCredsResolutionError)
            event_bus = inject_or_fail(session, EventBus, AnonCredsResolutionError)
            receipts = []
            for cred_id in revoked:
                nonce = self.web3.eth.get_transaction_count(self.account.address)
                txn = self.kanon_contract.functions.revokeCredential(cred_id).build_transaction({
                    'from': self.account.address,
                    'nonce': nonce,
                    'gas': 200000,
                    'gasPrice': self.web3.to_wei('20', 'gwei'),
                })
                signed_txn = self.web3.eth.account.sign_transaction(txn, self.operator_key)
                tx_hash = self.web3.eth.send_raw_transaction(signed_txn.rawTransaction)
                receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash)
                receipts.append(receipt)
            await event_bus.notify(
                profile,
                RevListFinishedEvent.with_payload(curr_list.rev_reg_def_id, list(revoked))
            )
            kanon_res = {
                "revocation_list": {
                    "rev_reg_def_id": curr_list.rev_reg_def_id,
                    "receipts": receipts,
                }
            }
            return build_acapy_rev_list_result(kanon_res)
