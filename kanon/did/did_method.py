"""Kanon DID method."""

from acapy_agent.wallet.did_method import DIDMethod, HolderDefinedDid
from acapy_agent.wallet.key_type import ED25519

KANON = DIDMethod(
    name="kanon",
    key_types=[ED25519],
    rotation=False,
    holder_defined_did=HolderDefinedDid.NO,
)
