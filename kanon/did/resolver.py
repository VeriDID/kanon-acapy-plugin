import re
from typing import Pattern

from acapy_agent.core.profile import Profile
from acapy_agent.resolver.base import BaseDIDResolver, ResolverError, ResolverType
from web3 import Web3

from ..config import Config

class KanonDIDResolver(BaseDIDResolver):
    """Kanon DID resolver for EVM-registered DIDs."""

    def __init__(self):
        """Constructor."""
        super().__init__(ResolverType.NATIVE)
        self._supported_did_regex = re.compile("^did:kanon:.*$")

    @property
    def supported_did_regex(self) -> Pattern:
        """Return the regex pattern for supported DIDs."""
        return self._supported_did_regex

    async def setup(self, context):
        """Setup the resolver using configuration from the context."""
        settings = Config.from_settings(context.settings)
        # Initialize the Web3 instance and contract
        self.web3 = Web3(Web3.HTTPProvider(settings.web3_provider_url))
        self.contract = self.web3.eth.contract(
            address=settings.contract_address,
            abi=settings.contract_abi
        )

    async def _resolve(self, profile: Profile, did: str, service_accept=None) -> dict:
        """
        Resolve a Kanon DID by calling the EVM smart contract's getDID function.
        
        Returns:
            A dict with the DID, its context, and metadata.
        Raises:
            ResolverError: if the DID does not exist or an error occurs.
        """
        try:
            # Call the getDID function on the contract.
            # TODO: Add support for execution of the contract asynchronously
            result = self.contract.functions.getDID(did).call()
            # Assuming the contract returns a tuple (context, metadata)
            context_value, metadata = result

            return {
                "did": did,
                "context": context_value,
                "metadata": metadata,
            }
        except Exception as e:
            raise ResolverError(str(e))
