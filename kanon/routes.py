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


class KanonResponseSchema(OpenAPISchema):
    """Response schema for Kanon DID operations."""

    did = fields.Str(
        required=True,
        metadata={
            "description": "DID that was created",
            "example": "did:kanon:testnet:zMqXmB7cTsTXqyxDPBbrgu5EPqw61kouK1qjMvnoPa96_0.0.5254964",  # noqa: E501
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

    if key_type != "Ed25519":
        raise web.HTTPForbidden(reason=f"Unsupported key type {key_type}")

    try:
        did_info = await KanonDIDRegistrar(context).register(key_type, seed)
        return web.json_response(did_info)
    except Exception as error:
        raise web.HTTPInternalServerError(reason=str(error)) from error


async def register(app: web.Application):
    """Register endpoints."""
    app.add_routes([web.post("/kanon/did/register", kanon_register_did)])


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
