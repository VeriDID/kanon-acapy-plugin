"""Kanon API Routes."""

import logging
from typing import Mapping

from acapy_agent.admin.decorators.auth import tenant_authentication
from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.messaging.models.openapi import OpenAPISchema
from aiohttp import web
from aiohttp_apispec import docs, json_schema, response_schema
from marshmallow import fields
from marshmallow.validate import OneOf

from .did import KanonDIDRegistrar

LOGGER = logging.getLogger(__name__)


class KanonRequestJSONSchema(OpenAPISchema):
    """Request schema for Kanon DID operations."""

    key_type = fields.String(
        required=True,
        validate=OneOf(["Ed25519"]),
        metadata={
            "description": "Key type to use for DID registration",
            "example": "Ed25519",
        },
    )

    seed = fields.String(
        required=False,
        metadata={
            "description": "Optional seed to use for DID",
            "example": "000000000000000000000000Trustee1",
        },
    )
    
    metadata = fields.Dict(
        required=False,
        metadata={
            "description": "Optional metadata for the DID (company name, logo URL, etc.)",
            "example": {
                "company_name": "Example Corp",
                "logo_url": "https://example.com/logo.png",
                "website": "https://example.com"
            },
        },
    )


class KanonUpdateRequestJSONSchema(OpenAPISchema):
    """Request schema for updating Kanon DID metadata."""

    did = fields.String(
        required=True,
        metadata={
            "description": "DID to update",
            "example": "did:kanon:0x71C7656EC7ab88b098defB751B7401B5f6d8976F",
        },
    )
    
    metadata = fields.Dict(
        required=True,
        metadata={
            "description": "New metadata for the DID (company name, logo URL, etc.)",
            "example": {
                "company_name": "Updated Corp",
                "logo_url": "https://example.com/new-logo.png",
                "website": "https://example.com",
                "description": "A company description"
            },
        },
    )


class KanonResponseSchema(OpenAPISchema):
    """Response schema for Kanon DID operations."""

    did = fields.Str(
        required=True,
        metadata={
            "description": "DID that was created",
            "example": "did:kanon:testnet:0x71C7656EC7ab88b098defB751B7401B5f6d8976F",  # noqa: E501
        },
    )

    verkey = fields.Str(
        required=True,
        metadata={
            "description": "Verification key",
            "example": "7mbbTXhnPx8ux4LBVRPoHxpSACPRF9axYU4uwiKNhzUH",
        },
    )

    key_type = fields.Str(
        required=True, metadata={"description": "Used key type", "example": "ed25519"}
    )
    
    metadata = fields.Dict(
        required=False,
        metadata={
            "description": "Metadata associated with the DID",
            "example": {
                "company_name": "Example Corp",
                "logo_url": "https://example.com/logo.png"
            },
        },
    )


class KanonUpdateResponseSchema(OpenAPISchema):
    """Response schema for updating Kanon DID metadata."""

    did = fields.Str(
        required=True,
        metadata={
            "description": "DID that was updated",
            "example": "did:kanon:testnet:0x71C7656EC7ab88b098defB751B7401B5f6d8976F",  # noqa: E501
        },
    )
    
    tx_hash = fields.Str(
        required=True,
        metadata={
            "description": "Transaction hash of the update operation",
            "example": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        },
    )
    
    metadata = fields.Dict(
        required=True,
        metadata={
            "description": "Updated metadata for the DID",
            "example": {
                "company_name": "Updated Corp",
                "logo_url": "https://example.com/new-logo.png"
            },
        },
    )


@docs(
    tags=["kanon"],
    summary="Register a new Kanon DID",
)
@json_schema(KanonRequestJSONSchema())
@response_schema(KanonResponseSchema(), 200)
@tenant_authentication
async def kanon_register_did(request: web.BaseRequest):
    """Request handler for registering a new Kanon DID."""
    LOGGER.debug("Received register new Kanon DID request")

    context: AdminRequestContext = request["context"]

    body = await request.json()

    key_type = body["key_type"]
    seed = body.get("seed") or None
    metadata = body.get("metadata")
    
    # Convert metadata to JSON string if provided
    metadata_json = None
    if metadata:
        import json
        metadata_json = json.dumps(metadata)

    if key_type != "Ed25519":
        raise web.HTTPForbidden(reason=f"Unsupported key type {key_type}")

    try:
        did_info = await KanonDIDRegistrar(context).register(key_type, seed, metadata_json)
        return web.json_response(did_info)
    except Exception as error:
        raise web.HTTPInternalServerError(reason=str(error)) from error


@docs(
    tags=["kanon"],
    summary="Update metadata for an existing Kanon DID",
)
@json_schema(KanonUpdateRequestJSONSchema())
@response_schema(KanonUpdateResponseSchema(), 200)
@tenant_authentication
async def kanon_update_did(request: web.BaseRequest):
    """Request handler for updating Kanon DID metadata."""
    LOGGER.debug("Received update Kanon DID metadata request")

    context: AdminRequestContext = request["context"]

    body = await request.json()

    did = body["did"]
    metadata = body["metadata"]
    
    # Convert metadata to JSON string
    import json
    metadata_json = json.dumps(metadata)

    try:
        update_info = await KanonDIDRegistrar(context).update(did, metadata_json)
        return web.json_response(update_info)
    except Exception as error:
        raise web.HTTPInternalServerError(reason=str(error)) from error


async def register(app: web.Application):
    """Register endpoints."""
    app.add_routes([
        web.post("/kanon/did/register", kanon_register_did),
        web.post("/kanon/did/update", kanon_update_did),
    ])


def post_process_routes(app: web.Application):
    """Amend swagger API."""
    app_state: Mapping = app._state

    if "tags" not in app_state["swagger_dict"]:
        app_state["swagger_dict"]["tags"] = []

    app_state["swagger_dict"]["tags"].append(
        {
            "name": "kanon",
            "description": "Kanon DID and AnonCreds plugin API",
            "externalDocs": {
                "description": "Specification",
                "url": "",
            },
        }
    )
