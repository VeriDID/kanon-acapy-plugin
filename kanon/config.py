"""Kanon configuration."""

from dataclasses import dataclass
from os import getenv
from typing import Optional
from web3 import Web3

from acapy_agent.config.base import BaseSettings
from acapy_agent.config.settings import Settings


class ConfigError(ValueError):
    """Base class for configuration errors."""

    def __init__(self, var: str, env: str):
        """Initializer."""
        super().__init__(
            f"Invalid {var} specified for Kanon DID plugin; use either "
            f"kanon.{var} plugin config value or environment variable {env}"
        )


@dataclass
class Config:
    """Configuration for Kanon DID plugin."""

    network: str
    operator_key: str
    web3_provider_url: str
    contract_address: str
    contract_abi: list

    @classmethod
    def from_settings(cls, settings: BaseSettings) -> "Config":
        """Retrieve configuration from application context settings class."""

        assert isinstance(settings, Settings)
        plugin_settings = settings.for_plugin("kanon")

        # Default to "sepolia" if no network is provided and force to lowercase
        network: str = (plugin_settings.get("network") or getenv("KANON_NETWORK") or "sepolia").lower()
        operator_key: Optional[str] = plugin_settings.get("operator_key")
        if not operator_key:
            evm_config = plugin_settings.get("evm", {})
            operator_key = evm_config.get("operator_key")
        if not operator_key:
            operator_key = getenv("KANON_OPERATOR_KEY")
        if not operator_key:
            raise ConfigError("operator_key", "KANON_OPERATOR_KEY (or evm.operator_key)")

        if network not in ("mainnet", "sepolia"):
            raise ConfigError("network", f"Unsupported network '{network}'. Use 'mainnet' or 'sepolia'.")

        # Retrieve the web3 provider URL and contract address from the evm configuration
        evm_config = plugin_settings.get("evm", {})
        web3_provider_url: Optional[str] = evm_config.get("web3_provider_url") or getenv("KANON_WEB3_PROVIDER_URL")
        if not web3_provider_url:
            raise ConfigError("web3_provider_url", "KANON_WEB3_PROVIDER_URL")

        contract_address: Optional[str] = evm_config.get("contract_address") or getenv("KANON_CONTRACT_ADDRESS")
        if not contract_address:
            raise ConfigError("contract_address", "KANON_CONTRACT_ADDRESS")
        try:
            contract_address = Web3.to_checksum_address(contract_address)
        except Exception as e:
            raise ConfigError("contract_address", f"Invalid checksum address: {contract_address}") from e

        contract_abi: list = evm_config.get("contract_abi", [])

        return cls(network, operator_key, web3_provider_url, contract_address, contract_abi)
