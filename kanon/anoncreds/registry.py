import re
import time
from typing import Pattern, cast

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
from ..utils import  inject_or_fail


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

        Reads the EVM provider URL, Kanon contract address, and ABI from settings.
        """
        settings = Config.from_settings(context.settings)
        self.web3 = Web3(Web3.HTTPProvider(settings.evm.web3_provider_url))
        self.operator_key = settings.evm.operator_key
        self.account = self.web3.eth.account.from_key(self.operator_key)
        self.kanon_contract = self.web3.eth.contract(
            address=settings.evm.kanon_contract_address,
            abi=settings.evm.kanon_contract_abi,
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
        # Build a response object
        kanon_res = {
            "schema": {
                "schema_id": schema_id,
                "details": schema_details,
                "approved_issuers": approved_issuers,
            }
        }
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
        kanon_res = {
            "credential_definition": {
                "cred_def_id": credential_definition_id,
                "schema_id": schema_id,
                "issuer": issuer,
            }
        }
        return build_acapy_get_cred_def_result(kanon_res)

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
            issuer_did = schema.issuer_id
            wallet = inject_or_fail(session, BaseWallet, AnonCredsResolutionError)
            # Transform the schema object into the payload expected by the contract.
            schema_payload = build_kanon_anoncreds_schema(schema)
            nonce = self.web3.eth.getTransactionCount(self.account.address)
            txn = self.kanon_contract.functions.registerSchema(schema.schema_id, schema_payload).buildTransaction({
                'from': self.account.address,
                'nonce': nonce,
                'gas': 300000,
                'gasPrice': self.web3.to_wei('20', 'gwei'),
            })
            signed_txn = self.web3.eth.account.sign_transaction(txn, self.operator_key)
            tx_hash = self.web3.eth.sendRawTransaction(signed_txn.rawTransaction)
            receipt = self.web3.eth.waitForTransactionReceipt(tx_hash)
            kanon_res = {
                "schema": {
                    "schema_id": schema.schema_id,
                    "details": schema_payload,
                    "tx_receipt": receipt,
                }
            }
            return build_acapy_schema_result(kanon_res)

    async def register_credential_definition(
        self, profile, schema, credential_definition, options=None
    ) -> CredDefResult:
        """Register a credential definition on the Kanon contract.

        Signs the transaction using the issuer's private key and calls registerCredentialDefinition.
        """
        async with profile.session() as session:
            issuer_did = schema.schema.issuer_id
            wallet = inject_or_fail(session, BaseWallet, AnonCredsResolutionError)
            cred_def_payload = build_kanon_anoncreds_cred_def(credential_definition)
            nonce = self.web3.eth.getTransactionCount(self.account.address)
            txn = self.kanon_contract.functions.registerCredentialDefinition(
                credential_definition.cred_def_id,
                schema.schema_id,
                self.account.address  # Issuer address
            ).buildTransaction({
                'from': self.account.address,
                'nonce': nonce,
                'gas': 300000,
                'gasPrice': self.web3.to_wei('20', 'gwei'),
            })
            signed_txn = self.web3.eth.account.sign_transaction(txn, self.operator_key)
            tx_hash = self.web3.eth.sendRawTransaction(signed_txn.rawTransaction)
            receipt = self.web3.eth.waitForTransactionReceipt(tx_hash)
            kanon_res = {
                "credential_definition": {
                    "cred_def_id": credential_definition.cred_def_id,
                    "schema_id": schema.schema_id,
                    "issuer": self.account.address,
                    "tx_receipt": receipt,
                }
            }
            return build_acapy_cred_def_result(kanon_res)

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
                nonce = self.web3.eth.getTransactionCount(self.account.address)
                txn = self.kanon_contract.functions.revokeCredential(cred_id).buildTransaction({
                    'from': self.account.address,
                    'nonce': nonce,
                    'gas': 200000,
                    'gasPrice': self.web3.to_wei('20', 'gwei'),
                })
                signed_txn = self.web3.eth.account.sign_transaction(txn, self.operator_key)
                tx_hash = self.web3.eth.sendRawTransaction(signed_txn.rawTransaction)
                receipt = self.web3.eth.waitForTransactionReceipt(tx_hash)
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
                nonce = self.web3.eth.getTransactionCount(self.account.address)
                txn = self.kanon_contract.functions.revokeCredential(cred_id).buildTransaction({
                    'from': self.account.address,
                    'nonce': nonce,
                    'gas': 200000,
                    'gasPrice': self.web3.to_wei('20', 'gwei'),
                })
                signed_txn = self.web3.eth.account.sign_transaction(txn, self.operator_key)
                tx_hash = self.web3.eth.sendRawTransaction(signed_txn.rawTransaction)
                receipt = self.web3.eth.waitForTransactionReceipt(tx_hash)
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
