"""Helpers for mapping AnonCreds-related data classes."""

from acapy_agent.anoncreds.base import (
    AnonCredsSchema as AcapyAnonCredsSchema,
    CredDef as AcapyAnonCredsCredDef,
    CredDefResult as AcapyCredDefResult,
    GetRevListResult as AcapyGetRevListResult,
    GetRevRegDefResult as AcapyGetRevRegDefResult,
    GetSchemaResult as AcapyGetSchemaResult,
    RevList as AcapyRevList,
    RevListResult as AcapyRevListResult,
    RevRegDef as AcapyRevRegDef,
    RevRegDefResult as AcapyRevRegDefResult,
    SchemaResult as AcapySchemaResult,
)
from acapy_agent.anoncreds.models.credential_definition import (
    CredDefState as AcapyCredDefState,
    CredDefValue as AcapyCredDefValue,
    CredDefValuePrimary as AcapyCredDefValuePrimary,
    CredDefValueRevocation as AcapyCredDefValueRevocation,
    GetCredDefResult as AcapyGetCredDefResult,
)
from acapy_agent.anoncreds.models.revocation import (
    RevListState as AcapyRevListState,
    RevRegDefState as AcapyRevRegDefState,
    RevRegDefValue as AcapyRevRegDefValue,
)
from acapy_agent.anoncreds.models.schema import SchemaState as AcapySchemaState
from dataclasses import dataclass
from typing import Dict, List, Optional, Any


# Define our own simple types for Kanon anoncreds models
@dataclass
class KanonCredDefValuePrimary:
    n: str
    s: str
    r: Dict[str, str]
    rctxt: str
    z: str


@dataclass
class KanonCredDefValueRevocation:
    g: str
    g_dash: str
    h: str
    h0: str
    h1: str
    h2: str
    htilde: str
    h_cap: str
    u: str
    pk: str
    y: str


@dataclass
class KanonCredDefValue:
    primary: KanonCredDefValuePrimary
    revocation: Optional[KanonCredDefValueRevocation] = None


@dataclass
class KanonAnonCredsCredDef:
    issuer_id: str
    schema_id: str
    tag: str
    value: KanonCredDefValue


@dataclass
class KanonAnonCredsSchema:
    name: str
    issuer_id: str
    attr_names: List[str]
    version: str


@dataclass
class KanonRevRegDefValue:
    public_keys: Dict
    max_cred_num: int
    tails_location: str
    tails_hash: str


@dataclass
class KanonAnonCredsRevRegDef:
    issuer_id: str
    cred_def_id: str
    tag: str
    value: KanonRevRegDefValue


@dataclass
class KanonAnonCredsRevList:
    issuer_id: str
    rev_reg_def_id: str
    revocation_list: List[int]
    current_accumulator: str
    timestamp: int


@dataclass
class KanonSchemaState:
    state: str
    schema_id: str
    schema: KanonAnonCredsSchema


@dataclass
class KanonSchemaResult:
    schema_state: KanonSchemaState
    registration_metadata: Dict
    schema_metadata: Dict


@dataclass
class KanonCredDefState:
    state: str
    credential_definition_id: str
    credential_definition: KanonAnonCredsCredDef


@dataclass
class KanonCredDefResult:
    credential_definition_state: KanonCredDefState
    registration_metadata: Dict
    credential_definition_metadata: Dict


@dataclass
class KanonRevRegDefState:
    state: str
    revocation_registry_definition_id: str
    revocation_registry_definition: KanonAnonCredsRevRegDef


@dataclass
class KanonRegisterRevRegDefResult:
    revocation_registry_definition_state: KanonRevRegDefState
    registration_metadata: Dict
    revocation_registry_definition_metadata: Dict


@dataclass
class KanonRevListState:
    state: str
    revocation_list: KanonAnonCredsRevList
    reason: Optional[str] = None


@dataclass
class KanonRegisterRevListResult:
    revocation_list_state: KanonRevListState
    registration_metadata: Dict
    revocation_list_metadata: Dict


@dataclass
class KanonGetSchemaResult:
    """Get schema result for Kanon."""
    schema_id: str
    schema: KanonAnonCredsSchema
    schema_metadata: Dict[str, Any]
    resolution_metadata: Dict[str, Any]


@dataclass
class KanonGetCredDefResult:
    """Get credential definition result for Kanon."""
    credential_definition_id: str
    credential_definition: KanonAnonCredsCredDef
    credential_definition_metadata: Dict[str, Any]
    resolution_metadata: Dict[str, Any]


@dataclass
class KanonGetRevRegDefResult:
    """Get revocation registry definition result for Kanon."""
    revocation_registry_definition_id: str
    revocation_registry_definition: KanonAnonCredsRevRegDef
    revocation_registry_definition_metadata: Dict[str, Any]
    resolution_metadata: Dict[str, Any]


@dataclass
class KanonGetRevListResult:
    resolution_metadata: Dict[str, Any]
    revocation_list_metadata: Dict[str, Any]
    revocation_list: Optional[KanonAnonCredsRevList]
    revocation_registry_id: str


def build_kanon_anoncreds_schema(schema: AcapyAnonCredsSchema) -> KanonAnonCredsSchema:
    """Map object."""
    return KanonAnonCredsSchema(
        name=schema.name,
        issuer_id=schema.issuer_id,
        attr_names=schema.attr_names,
        version=schema.version,
    )


def build_kanon_anoncreds_cred_def(
    cred_def: AcapyAnonCredsCredDef,
) -> KanonAnonCredsCredDef:
    """Map object."""
    revocation = None
    if cred_def.value.revocation:
        revocation = KanonCredDefValueRevocation(
            g=cred_def.value.revocation.g,
            g_dash=cred_def.value.revocation.g_dash,
            h=cred_def.value.revocation.h,
            h0=cred_def.value.revocation.h0,
            h1=cred_def.value.revocation.h1,
            h2=cred_def.value.revocation.h2,
            htilde=cred_def.value.revocation.htilde,
            h_cap=cred_def.value.revocation.h_cap,
            u=cred_def.value.revocation.u,
            pk=cred_def.value.revocation.pk,
            y=cred_def.value.revocation.y,
        )

    return KanonAnonCredsCredDef(
        issuer_id=cred_def.issuer_id,
        schema_id=cred_def.schema_id,
        tag=cred_def.tag,
        value=KanonCredDefValue(
            primary=KanonCredDefValuePrimary(
                n=cred_def.value.primary.n,
                s=cred_def.value.primary.s,
                r=cred_def.value.primary.r,
                rctxt=cred_def.value.primary.rctxt,
                z=cred_def.value.primary.z,
            ),
            revocation=revocation,
        ),
    )


def build_kanon_anoncreds_rev_reg_def(
    rev_reg_def: AcapyRevRegDef,
) -> KanonAnonCredsRevRegDef:
    """Map object."""
    return KanonAnonCredsRevRegDef(
        issuer_id=rev_reg_def.issuer_id,
        cred_def_id=rev_reg_def.cred_def_id,
        tag=rev_reg_def.tag,
        value=KanonRevRegDefValue(
            public_keys=rev_reg_def.value.public_keys,
            max_cred_num=rev_reg_def.value.max_cred_num,
            tails_location=rev_reg_def.value.tails_location,
            tails_hash=rev_reg_def.value.tails_hash,
        ),
    )


def build_kanon_anoncreds_rev_list(
    rev_list: AcapyRevList,
) -> KanonAnonCredsRevList:
    """Map object."""
    return KanonAnonCredsRevList(
        issuer_id=rev_list.issuer_id,
        rev_reg_def_id=rev_list.rev_reg_def_id,
        revocation_list=rev_list.revocation_list,
        current_accumulator=rev_list.current_accumulator,
        timestamp=rev_list.timestamp,
    )


def build_acapy_get_schema_result(
    kanon_res: KanonGetSchemaResult,
) -> AcapyGetSchemaResult:
    """Map object."""
    assert kanon_res.schema

    return AcapyGetSchemaResult(
        schema=AcapyAnonCredsSchema(
            issuer_id=kanon_res.schema.issuer_id,
            attr_names=kanon_res.schema.attr_names,
            name=kanon_res.schema.name,
            version=kanon_res.schema.version,
        ),
        schema_id=kanon_res.schema_id,
        resolution_metadata=kanon_res.resolution_metadata,
        schema_metadata=kanon_res.schema_metadata,
    )


def build_acapy_get_cred_def_result(
    kanon_res: KanonGetCredDefResult,
) -> AcapyGetCredDefResult:
    """Map object."""
    assert kanon_res.credential_definition

    revocation = (
        AcapyCredDefValueRevocation(
            g=kanon_res.credential_definition.value.revocation.g,
            g_dash=kanon_res.credential_definition.value.revocation.g_dash,
            h=kanon_res.credential_definition.value.revocation.h,
            h0=kanon_res.credential_definition.value.revocation.h0,
            h1=kanon_res.credential_definition.value.revocation.h1,
            h2=kanon_res.credential_definition.value.revocation.h2,
            htilde=kanon_res.credential_definition.value.revocation.htilde,
            h_cap=kanon_res.credential_definition.value.revocation.h_cap,
            u=kanon_res.credential_definition.value.revocation.u,
            pk=kanon_res.credential_definition.value.revocation.pk,
            y=kanon_res.credential_definition.value.revocation.y,
        )
        if kanon_res.credential_definition.value.revocation
        else None
    )

    return AcapyGetCredDefResult(
        credential_definition_id=kanon_res.credential_definition_id,
        credential_definition=AcapyAnonCredsCredDef(
            issuer_id=kanon_res.credential_definition.issuer_id,
            schema_id=kanon_res.credential_definition.schema_id,
            type="CL",
            tag=kanon_res.credential_definition.tag,
            value=AcapyCredDefValue(
                AcapyCredDefValuePrimary(
                    n=kanon_res.credential_definition.value.primary.n,
                    s=kanon_res.credential_definition.value.primary.s,
                    r=kanon_res.credential_definition.value.primary.r,
                    rctxt=kanon_res.credential_definition.value.primary.rctxt,
                    z=kanon_res.credential_definition.value.primary.z,
                ),
                revocation,
            ),
        ),
        resolution_metadata=kanon_res.resolution_metadata,
        credential_definition_metadata=kanon_res.credential_definition_metadata,
    )


def build_acapy_get_rev_reg_def_result(
    kanon_res: KanonGetRevRegDefResult,
) -> AcapyGetRevRegDefResult:
    """Map object."""
    assert kanon_res.revocation_registry_definition is not None

    return AcapyGetRevRegDefResult(
        revocation_registry=AcapyRevRegDef(
            issuer_id=kanon_res.revocation_registry_definition.issuer_id,
            type="CL_ACCUM",
            cred_def_id=kanon_res.revocation_registry_definition.cred_def_id,
            tag=kanon_res.revocation_registry_definition.tag,
            value=AcapyRevRegDefValue(
                kanon_res.revocation_registry_definition.value.public_keys,
                kanon_res.revocation_registry_definition.value.max_cred_num,
                kanon_res.revocation_registry_definition.value.tails_location,
                kanon_res.revocation_registry_definition.value.tails_hash,
            ),
        ),
        revocation_registry_id=kanon_res.revocation_registry_definition_id,
        resolution_metadata=kanon_res.resolution_metadata,
        revocation_registry_metadata=kanon_res.revocation_registry_definition_metadata,
    )


def build_acapy_get_rev_list_result(
    kanon_res: KanonGetRevListResult,
) -> AcapyGetRevListResult:
    """Map object, handling None case for revocation_list."""
    if kanon_res.revocation_list is None:
        return AcapyGetRevListResult(
            resolution_metadata=kanon_res.resolution_metadata,
            revocation_registry_metadata=kanon_res.revocation_list_metadata,
            revocation_list=None
        )
    
    return AcapyGetRevListResult(
        resolution_metadata=kanon_res.resolution_metadata,
        revocation_registry_metadata=kanon_res.revocation_list_metadata,
        revocation_list=AcapyRevList(
            issuer_id=kanon_res.revocation_list.issuer_id,
            rev_reg_def_id=kanon_res.revocation_list.rev_reg_def_id,
            revocation_list=kanon_res.revocation_list.revocation_list,
            current_accumulator=kanon_res.revocation_list.current_accumulator,
            timestamp=kanon_res.revocation_list.timestamp,
        ),
    )


def build_acapy_schema_result(
    res: KanonSchemaResult, *, job_id=None
) -> AcapySchemaResult:
    """Map object."""
    return AcapySchemaResult(
        job_id=job_id,
        schema_state=AcapySchemaState(
            state=res.schema_state.state,
            schema_id=res.schema_state.schema_id or "",
            schema=AcapyAnonCredsSchema(
                res.schema_state.schema.issuer_id,
                res.schema_state.schema.attr_names,
                res.schema_state.schema.name,
                res.schema_state.schema.version,
            ),
        ),
        registration_metadata=res.registration_metadata,
        schema_metadata=res.schema_metadata,
    )


def build_acapy_cred_def_result(
    kanon_res: KanonCredDefResult, *, job_id=None
) -> AcapyCredDefResult:
    """Map object."""
    state = kanon_res.credential_definition_state
    cred_def = state.credential_definition
    value = cred_def.value
    schema_id = state.credential_definition.schema_id
    primary = value.primary

    revocation = (
        AcapyCredDefValueRevocation(
            g=value.revocation.g,
            g_dash=value.revocation.g_dash,
            h=value.revocation.h,
            h0=value.revocation.h0,
            h1=value.revocation.h1,
            h2=value.revocation.h2,
            htilde=value.revocation.htilde,
            h_cap=value.revocation.h_cap,
            u=value.revocation.u,
            pk=value.revocation.pk,
            y=value.revocation.y,
        )
        if value.revocation
        else None
    )

    return AcapyCredDefResult(
        job_id,
        AcapyCredDefState(
            state.state,
            kanon_res.credential_definition_state.credential_definition_id,
            AcapyAnonCredsCredDef(
                cred_def.issuer_id,
                schema_id,
                "CL",
                cred_def.tag,
                AcapyCredDefValue(
                    AcapyCredDefValuePrimary(
                        n=primary.n,
                        s=primary.s,
                        r=primary.r,
                        rctxt=primary.rctxt,
                        z=primary.z,
                    ),
                    revocation,
                ),
            ),
        ),
        registration_metadata=kanon_res.registration_metadata,
        credential_definition_metadata=kanon_res.credential_definition_metadata,
    )


def build_acapy_rev_reg_def_result(
    kanon_res: KanonRegisterRevRegDefResult, *, job_id=None
) -> AcapyRevRegDefResult:
    """Map object."""
    assert (
        kanon_res.revocation_registry_definition_state.revocation_registry_definition_id
        is not None
    )

    return AcapyRevRegDefResult(
        job_id=job_id,
        revocation_registry_definition_state=AcapyRevRegDefState(
            state=kanon_res.revocation_registry_definition_state.state,
            revocation_registry_definition_id=kanon_res.revocation_registry_definition_state.revocation_registry_definition_id,
            revocation_registry_definition=AcapyRevRegDef(
                issuer_id=kanon_res.revocation_registry_definition_state.revocation_registry_definition.issuer_id,
                type="CL_ACCUM",
                cred_def_id=kanon_res.revocation_registry_definition_state.revocation_registry_definition.cred_def_id,
                tag=kanon_res.revocation_registry_definition_state.revocation_registry_definition.tag,
                value=AcapyRevRegDefValue(
                    kanon_res.revocation_registry_definition_state.revocation_registry_definition.value.public_keys,
                    kanon_res.revocation_registry_definition_state.revocation_registry_definition.value.max_cred_num,
                    kanon_res.revocation_registry_definition_state.revocation_registry_definition.value.tails_location,
                    kanon_res.revocation_registry_definition_state.revocation_registry_definition.value.tails_hash,
                ),
            ),
        ),
        registration_metadata=kanon_res.registration_metadata,
        revocation_registry_definition_metadata=kanon_res.revocation_registry_definition_metadata,
    )


def build_acapy_rev_list_result(
    kanon_res: KanonRegisterRevListResult, *, job_id=None
) -> AcapyRevListResult:
    """Map object."""
    return AcapyRevListResult(
        job_id=job_id,
        revocation_list_state=AcapyRevListState(
            state=kanon_res.revocation_list_state.state,
            revocation_list=AcapyRevList(
                issuer_id=kanon_res.revocation_list_state.revocation_list.issuer_id,
                rev_reg_def_id=kanon_res.revocation_list_state.revocation_list.rev_reg_def_id,
                revocation_list=kanon_res.revocation_list_state.revocation_list.revocation_list,
                current_accumulator=kanon_res.revocation_list_state.revocation_list.current_accumulator,
                timestamp=kanon_res.revocation_list_state.revocation_list.timestamp,
            ),
        ),
        registration_metadata=kanon_res.registration_metadata,
        revocation_list_metadata=kanon_res.revocation_list_metadata,
    )
