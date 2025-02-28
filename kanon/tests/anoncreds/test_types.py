from acapy_agent.anoncreds.base import (
    AnonCredsSchema as AcapyAnonCredsSchema,
    CredDef as AcapyAnonCredsCredDef,
    RevRegDef as AcapyRevRegDef,
    RevList as AcapyRevList,
)
from acapy_agent.anoncreds.models.credential_definition import (
    CredDefValue as AcapyCredDefValue,
    CredDefValuePrimary as AcapyCredDefValuePrimary,
    CredDefValueRevocation as AcapyCredDefValueRevocation,
)
from acapy_agent.anoncreds.models.revocation import (
    RevRegDefValue as AcapyRevRegDefValue,
)

from kanon.anoncreds.types import (
    build_acapy_cred_def_result,
    build_acapy_get_cred_def_result,
    build_acapy_get_rev_list_result,
    build_acapy_get_rev_reg_def_result,
    build_acapy_get_schema_result,
    build_acapy_rev_list_result,
    build_acapy_rev_reg_def_result,
    build_acapy_schema_result,
    build_kanon_anoncreds_schema,
    build_kanon_anoncreds_cred_def,
    build_kanon_anoncreds_rev_reg_def,
    build_kanon_anoncreds_rev_list,
    KanonAnonCredsSchema,
    KanonAnonCredsCredDef,
    KanonCredDefValue,
    KanonCredDefValuePrimary,
    KanonCredDefValueRevocation,
    KanonAnonCredsRevRegDef,
    KanonRevRegDefValue,
    KanonAnonCredsRevList,
    KanonSchemaState,
    KanonSchemaResult,
    KanonCredDefState,
    KanonCredDefResult,
    KanonRevRegDefState,
    KanonRegisterRevRegDefResult,
    KanonRevListState,
    KanonRegisterRevListResult,
    KanonGetRevListResult,
    KanonGetSchemaResult,
    KanonGetCredDefResult,
    KanonGetRevRegDefResult,
)


class TestTypes:
    def test_build_kanon_schema(self):
        name = "Example schema"
        issuer_id = (
            "did:kanon:testnet:zFwZUYPrhi333pC2anAnSkctXgZzLfeR8DXURo2N4xV1C_0.0.5284925"
        )
        attr_names = ["score"]
        version = "1.0"

        kanon_schema = build_kanon_anoncreds_schema(
            AcapyAnonCredsSchema(
                name=name, issuer_id=issuer_id, attr_names=attr_names, version=version
            )
        )
        
        assert kanon_schema.name == name
        assert kanon_schema.issuer_id == issuer_id
        assert kanon_schema.attr_names == attr_names
        assert kanon_schema.version == version

    def test_build_kanon_cred_def(self):
        issuer_id = (
            "did:kanon:testnet:zFwZUYPrhi333pC2anAnSkctXgZzLfeR8DXURo2N4xV1C_0.0.5284925"
        )
        schema_id = f"{issuer_id}/anoncreds/v0/SCHEMA/0.0.5284932"
        tag = "demo-cred-def-1.0"
        type_ = "CL"
        n = "0954456694171"
        s = "0954456694171"
        r = {"key": "value"}
        rctxt = "0954456694171"
        z = "0954456694171"
        g = "1 1F14F&ECB578F 2 095E45DDF417D"
        g_dash = "1 1D64716fCDC00C 1 0C781960FA66E3D3 2 095E45DDF417D"
        h = "1 16675DAE54BFAE8 2 095E45DD417D"
        h0 = "1 21E5EF9476EAF18 2 095E45DDF417D"
        h1 = "1 236D1D99236090 2 095E45DDF417D"
        h2 = "1 1C3AE8D1F1E277 2 095E45DDF417D"
        htilde = "1 1D8549E8C0F8 2 095E45DDF417D"
        h_cap = "1 1B2A32CF3167 1 2490FEBF6EE55 1 0000000000000000"
        u = "1 0C430AAB2B4710 1 1CB3A0932EE7E 1 0000000000000000"
        pk = "1 142CD5E5A7DC 1 153885BD903312 2 095E45DDF417D"
        y = "1 153558BD903312 2 095E45DDF417D 1 0000000000000000"

        kanon_cred_def = build_kanon_anoncreds_cred_def(
            AcapyAnonCredsCredDef(
                issuer_id=issuer_id,
                schema_id=schema_id,
                type=type_,
                tag=tag,
                value=AcapyCredDefValue(
                    primary=AcapyCredDefValuePrimary(n=n, s=s, r=r, rctxt=rctxt, z=z),
                    revocation=AcapyCredDefValueRevocation(
                        g=g,
                        g_dash=g_dash,
                        h=h,
                        h0=h0,
                        h1=h1,
                        h2=h2,
                        htilde=htilde,
                        h_cap=h_cap,
                        u=u,
                        pk=pk,
                        y=y,
                    ),
                ),
            )
        )
        
        assert kanon_cred_def.issuer_id == issuer_id
        assert kanon_cred_def.schema_id == schema_id
        assert kanon_cred_def.tag == tag
        assert kanon_cred_def.value.primary.n == n
        assert kanon_cred_def.value.primary.s == s
        assert kanon_cred_def.value.primary.r == r
        assert kanon_cred_def.value.primary.rctxt == rctxt
        assert kanon_cred_def.value.primary.z == z
        assert kanon_cred_def.value.revocation.g == g
        assert kanon_cred_def.value.revocation.g_dash == g_dash
        assert kanon_cred_def.value.revocation.h == h
        assert kanon_cred_def.value.revocation.h0 == h0

    def test_build_kanon_rev_reg_def(self):
        issuer_id = (
            "did:kanon:testnet:zFwZUYPrhi333pC2anAnSkctXgZzLfeR8DXURo2N4xV1C_0.0.5284925"
        )
        type_ = "CL_ACCUM"
        cred_def_id = "did:kanon:testnet:zcZMJMxUGZpxKmP35ACBWLhQyQVqtRc5T7LQhdyTDtEiP_0.0.5280965/anoncreds/v0/PUBLIC_CRED_DEF/0.0.5280968"
        tag = "demo-cred-def-1.0"
        public_keys = {}
        max_cred_num = 999
        tails_location = "./location/to/tails"
        tails_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

        kanon_anon_creds_rev_reg_def = build_kanon_anoncreds_rev_reg_def(
            AcapyRevRegDef(
                issuer_id=issuer_id,
                type=type_,
                cred_def_id=cred_def_id,
                tag=tag,
                value=AcapyRevRegDefValue(
                    public_keys=public_keys,
                    max_cred_num=max_cred_num,
                    tails_location=tails_location,
                    tails_hash=tails_hash,
                ),
            )
        )
        
        assert kanon_anon_creds_rev_reg_def.issuer_id == issuer_id
        assert kanon_anon_creds_rev_reg_def.cred_def_id == cred_def_id
        assert kanon_anon_creds_rev_reg_def.tag == tag
        assert kanon_anon_creds_rev_reg_def.value.public_keys == public_keys
        assert kanon_anon_creds_rev_reg_def.value.max_cred_num == max_cred_num
        assert kanon_anon_creds_rev_reg_def.value.tails_location == tails_location
        assert kanon_anon_creds_rev_reg_def.value.tails_hash == tails_hash

    def test_build_kanon_anoncreds_rev_list(self):
        issuer_id = (
            "did:kanon:testnet:zFwZUYPrhi333pC2anAnSkctXgZzLfeR8DXURo2N4xV1C_0.0.5284925"
        )
        rev_reg_def_id = f"{issuer_id}/anoncreds/v0/REV_REG/0.0.5281064"
        revocation_list = [0, 1, 1, 0]
        current_accumulator = "21118FFB"
        timestamp = 1735318300

        kanon_anoncreds_rev_list = build_kanon_anoncreds_rev_list(
            AcapyRevList(
                issuer_id=issuer_id,
                rev_reg_def_id=rev_reg_def_id,
                revocation_list=revocation_list,
                current_accumulator=current_accumulator,
                timestamp=timestamp,
            )
        )
        
        assert kanon_anoncreds_rev_list.issuer_id == issuer_id
        assert kanon_anoncreds_rev_list.rev_reg_def_id == rev_reg_def_id
        assert kanon_anoncreds_rev_list.revocation_list == revocation_list
        assert kanon_anoncreds_rev_list.current_accumulator == current_accumulator
        assert kanon_anoncreds_rev_list.timestamp == timestamp

    def test_build_acapy_get_schema_result(self):
        resolution_metadata = {"resolution_metadata_key": "test"}
        schema_metadata = {"schema_metadata_key": "test"}
        name = "Example schema"
        issuer_id = (
            "did:kanon:testnet:zFwZUYPrhi333pC2anAnSkctXgZzLfeR8DXURo2N4xV1C_0.0.5284925"
        )
        schema_id = f"{issuer_id}/anoncreds/v0/SCHEMA/0.0.5284932"
        attr_names = ["score"]
        version = "1.0"

        acapy_get_schema_result = build_acapy_get_schema_result(
            KanonGetSchemaResult(
                schema_id=schema_id,
                schema=KanonAnonCredsSchema(
                    issuer_id=issuer_id, name=name, attr_names=attr_names, version=version
                ),
                schema_metadata=schema_metadata,
                resolution_metadata=resolution_metadata,
            )
        )

        assert acapy_get_schema_result.resolution_metadata == resolution_metadata
        assert acapy_get_schema_result.schema_metadata == schema_metadata

        acapy_schema = acapy_get_schema_result.schema

        assert acapy_schema.issuer_id == issuer_id
        assert acapy_schema.name == name
        assert acapy_schema.attr_names == attr_names
        assert acapy_schema.version == version

    def test_build_acapy_get_cred_def_result(self):
        resolution_metadata = {"resolution_metadata_key": "test"}
        credential_definition_metadata = {"cred_def_metadata_key": "test"}
        credential_definition_id = "did:kanon:testnet:zcZMJMxUGZpxKmP35ACBWLhQyQVqtRc5T7LQhdyTDtEiP_0.0.5280965/anoncreds/v0/PUBLIC_CRED_DEF/0.0.5280968"
        issuer_id = (
            "did:kanon:testnet:zFwZUYPrhi333pC2anAnSkctXgZzLfeR8DXURo2N4xV1C_0.0.5284925"
        )
        schema_id = f"{issuer_id}/anoncreds/v0/SCHEMA/0.0.5284932"
        tag = "demo-cred-def-1.0"
        n = "0954456694171"
        s = "0954456694171"
        r = {"key": "value"}
        rctxt = "0954456694171"
        z = "0954456694171"
        g = "1 1F14F&ECB578F 2 095E45DDF417D"
        g_dash = "1 1D64716fCDC00C 1 0C781960FA66E3D3 2 095E45DDF417D"
        h = "1 16675DAE54BFAE8 2 095E45DD417D"
        h0 = "1 21E5EF9476EAF18 2 095E45DDF417D"
        h1 = "1 236D1D99236090 2 095E45DDF417D"
        h2 = "1 1C3AE8D1F1E277 2 095E45DDF417D"
        htilde = "1 1D8549E8C0F8 2 095E45DDF417D"
        h_cap = "1 1B2A32CF3167 1 2490FEBF6EE55 1 0000000000000000"
        u = "1 0C430AAB2B4710 1 1CB3A0932EE7E 1 0000000000000000"
        pk = "1 142CD5E5A7DC 1 153885BD903312 2 095E45DDF417D"
        y = "1 153558BD903312 2 095E45DDF417D 1 0000000000000000"

        acapy_get_cred_def_result = build_acapy_get_cred_def_result(
            KanonGetCredDefResult(
                credential_definition_id=credential_definition_id,
                credential_definition=KanonAnonCredsCredDef(
                    issuer_id=issuer_id,
                    schema_id=schema_id,
                    tag=tag,
                    value=KanonCredDefValue(
                        primary=KanonCredDefValuePrimary(n=n, s=s, r=r, rctxt=rctxt, z=z),
                        revocation=KanonCredDefValueRevocation(
                            g=g,
                            g_dash=g_dash,
                            h=h,
                            h0=h0,
                            h1=h1,
                            h2=h2,
                            htilde=htilde,
                            h_cap=h_cap,
                            u=u,
                            pk=pk,
                            y=y,
                        ),
                    ),
                ),
                credential_definition_metadata=credential_definition_metadata,
                resolution_metadata=resolution_metadata,
            )
        )

        assert acapy_get_cred_def_result.resolution_metadata == resolution_metadata
        assert acapy_get_cred_def_result.credential_definition_metadata == credential_definition_metadata

        acapy_cred_def = acapy_get_cred_def_result.credential_definition
        assert acapy_cred_def.issuer_id == issuer_id
        assert acapy_cred_def.schema_id == schema_id
        assert acapy_cred_def.tag == tag
        assert acapy_cred_def.value.primary.n == n
        assert acapy_cred_def.value.primary.s == s
        assert acapy_cred_def.value.primary.r == r
        assert acapy_cred_def.value.primary.rctxt == rctxt
        assert acapy_cred_def.value.primary.z == z
        assert acapy_cred_def.value.revocation
        assert acapy_cred_def.value.revocation.g == g
        assert acapy_cred_def.value.revocation.g_dash == g_dash
        assert acapy_cred_def.value.revocation.h == h
        assert acapy_cred_def.value.revocation.h0 == h0
        assert acapy_cred_def.value.revocation.h1 == h1
        assert acapy_cred_def.value.revocation.h2 == h2
        assert acapy_cred_def.value.revocation.htilde == htilde
        assert acapy_cred_def.value.revocation.h_cap == h_cap
        assert acapy_cred_def.value.revocation.u == u
        assert acapy_cred_def.value.revocation.pk == pk
        assert acapy_cred_def.value.revocation.y == y

    def test_build_acapy_get_rev_reg_def_result(self):
        issuer_id = (
            "did:kanon:testnet:zFwZUYPrhi333pC2anAnSkctXgZzLfeR8DXURo2N4xV1C_0.0.5284925"
        )
        cred_def_id = "did:kanon:testnet:zcZMJMxUGZpxKmP35ACBWLhQyQVqtRc5T7LQhdyTDtEiP_0.0.5280965/anoncreds/v0/PUBLIC_CRED_DEF/0.0.5280968"
        rev_reg_def_id = f"{issuer_id}/anoncreds/v0/REV_REG/0.0.5281064"
        resolution_metadata = {"resolution_metadata_key": "test"}
        revocation_registry_definition_metadata = {"registry_metadata_key": "test"}
        tag = "demo-cred-def-1.0"
        public_keys = {}
        max_cred_num = 999
        tails_location = "./location/to/tails"
        tails_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

        acapy_get_rev_reg_def_result = build_acapy_get_rev_reg_def_result(
            KanonGetRevRegDefResult(
                revocation_registry_definition_id=rev_reg_def_id,
                resolution_metadata=resolution_metadata,
                revocation_registry_definition_metadata=revocation_registry_definition_metadata,
                revocation_registry_definition=KanonAnonCredsRevRegDef(
                    issuer_id=issuer_id,
                    cred_def_id=cred_def_id,
                    tag=tag,
                    value=KanonRevRegDefValue(
                        public_keys=public_keys,
                        max_cred_num=max_cred_num,
                        tails_location=tails_location,
                        tails_hash=tails_hash,
                    ),
                ),
            )
        )

        assert acapy_get_rev_reg_def_result.resolution_metadata == resolution_metadata
        assert (
            acapy_get_rev_reg_def_result.revocation_registry_metadata
            == revocation_registry_definition_metadata
        )

        acapy_rev_reg_def = acapy_get_rev_reg_def_result.revocation_registry
        assert acapy_rev_reg_def.issuer_id == issuer_id
        assert acapy_rev_reg_def.cred_def_id == cred_def_id
        assert acapy_rev_reg_def.tag == tag
        assert acapy_rev_reg_def.value.public_keys == public_keys
        assert acapy_rev_reg_def.value.max_cred_num == max_cred_num
        assert acapy_rev_reg_def.value.tails_location == tails_location
        assert acapy_rev_reg_def.value.tails_hash == tails_hash

    def test_build_acapy_get_rev_list_result(self):
        issuer_id = (
            "did:kanon:testnet:zFwZUYPrhi333pC2anAnSkctXgZzLfeR8DXURo2N4xV1C_0.0.5284925"
        )
        rev_reg_def_id = f"{issuer_id}/anoncreds/v0/REV_REG/0.0.5281064"
        revocation_list = [0, 1, 1, 0]
        current_accumulator = "21118FFB"
        timestamp = 1735318300
        resolution_metadata = {"resolution_metadata_key": "test"}
        revocation_registry_metadata = {"registry_metadata_key": "test"}

        acapy_get_rev_list_result = build_acapy_get_rev_list_result(
            KanonGetRevListResult(
                revocation_registry_id=rev_reg_def_id,
                revocation_list=KanonAnonCredsRevList(
                    issuer_id=issuer_id,
                    rev_reg_def_id=rev_reg_def_id,
                    revocation_list=revocation_list,
                    current_accumulator=current_accumulator,
                    timestamp=timestamp,
                ),
                resolution_metadata=resolution_metadata,
                revocation_list_metadata=revocation_registry_metadata,
            )
        )

        assert acapy_get_rev_list_result.resolution_metadata == resolution_metadata
        assert (
            acapy_get_rev_list_result.revocation_registry_metadata
            == revocation_registry_metadata
        )

        acapy_rev_list = acapy_get_rev_list_result.revocation_list

        assert acapy_rev_list.issuer_id == issuer_id
        assert acapy_rev_list.rev_reg_def_id == rev_reg_def_id
        assert acapy_rev_list.revocation_list == revocation_list
        assert acapy_rev_list.current_accumulator == current_accumulator
        assert acapy_rev_list.timestamp == timestamp

    def test_build_acapy_schema_result(self):
        registration_metadata = {"registration_metadata_key": "test"}
        schema_metadata = {"schema_metadata_key": "test"}
        name = "Example schema"
        issuer_id = (
            "did:kanon:testnet:zFwZUYPrhi333pC2anAnSkctXgZzLfeR8DXURo2N4xV1C_0.0.5284925"
        )
        schema_id = f"{issuer_id}/anoncreds/v0/SCHEMA/0.0.5284932"
        attr_names = ["score"]
        version = "1.0"
        state = "finished"

        acapy_schema_result = build_acapy_schema_result(
            KanonSchemaResult(
                registration_metadata=registration_metadata,
                schema_metadata=schema_metadata,
                schema_state=KanonSchemaState(
                    state=state,
                    schema=KanonAnonCredsSchema(
                        name=name,
                        issuer_id=issuer_id,
                        attr_names=attr_names,
                        version=version,
                    ),
                    schema_id=schema_id,
                ),
            )
        )

        assert acapy_schema_result.registration_metadata == registration_metadata
        assert acapy_schema_result.schema_metadata == schema_metadata

        acapy_schema_state = acapy_schema_result.schema_state

        assert acapy_schema_state.state == state
        assert acapy_schema_state.schema_id == schema_id

        acapy_schema = acapy_schema_state.schema

        assert acapy_schema.issuer_id == issuer_id
        assert acapy_schema.attr_names == attr_names
        assert acapy_schema.name == name
        assert acapy_schema.version == version

    def test_build_acapy_rev_reg_def_result(self):
        registration_metadata = {"registration_metadata_key": "test"}
        revocation_registry_definition_metadata = {"rev_reg_def_metadata_key": "test"}
        state = "finished"
        issuer_id = (
            "did:kanon:testnet:zFwZUYPrhi333pC2anAnSkctXgZzLfeR8DXURo2N4xV1C_0.0.5284925"
        )
        rev_reg_def_id = f"{issuer_id}/anoncreds/v0/REV_REG/0.0.5281064"
        cred_def_id = "did:kanon:testnet:zcZMJMxUGZpxKmP35ACBWLhQyQVqtRc5T7LQhdyTDtEiP_0.0.5280965/anoncreds/v0/PUBLIC_CRED_DEF/0.0.5280968"
        tag = "demo-cred-def-1.0"
        public_keys = {}
        max_cred_num = 999
        tails_location = "./location/to/tails"
        tails_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

        acapy_rev_reg_def_result = build_acapy_rev_reg_def_result(
            KanonRegisterRevRegDefResult(
                revocation_registry_definition_state=KanonRevRegDefState(
                    state=state,
                    revocation_registry_definition_id=rev_reg_def_id,
                    revocation_registry_definition=KanonAnonCredsRevRegDef(
                        issuer_id=issuer_id,
                        cred_def_id=cred_def_id,
                        value=KanonRevRegDefValue(
                            public_keys=public_keys,
                            max_cred_num=max_cred_num,
                            tails_location=tails_location,
                            tails_hash=tails_hash,
                        ),
                        tag=tag,
                    ),
                ),
                revocation_registry_definition_metadata=revocation_registry_definition_metadata,
                registration_metadata=registration_metadata,
            )
        )

        assert acapy_rev_reg_def_result.registration_metadata == registration_metadata
        assert (
            acapy_rev_reg_def_result.revocation_registry_definition_metadata
            == revocation_registry_definition_metadata
        )

        acapy_rev_reg_def_state = (
            acapy_rev_reg_def_result.revocation_registry_definition_state
        )

        assert acapy_rev_reg_def_state.state == state
        assert acapy_rev_reg_def_state.revocation_registry_definition_id == rev_reg_def_id
    
    def test_build_acapy_rev_list_result(self):
        registration_metadata = {"registration_metadata_key": "test"}
        revocation_list_metadata = {"rev_list_metadata_key": "test"}
        issuer_id = (
            "did:kanon:testnet:zFwZUYPrhi333pC2anAnSkctXgZzLfeR8DXURo2N4xV1C_0.0.5284925"
        )
        rev_reg_def_id = f"{issuer_id}/anoncreds/v0/REV_REG/0.0.5281064"
        state = "finished"
        revocation_list = [0, 1, 1, 0]
        current_accumulator = "21118FFB"
        timestamp = 1735318300

        acapy_rev_list_result = build_acapy_rev_list_result(
            KanonRegisterRevListResult(
                registration_metadata=registration_metadata,
                revocation_list_metadata=revocation_list_metadata,
                revocation_list_state=KanonRevListState(
                    state=state,
                    revocation_list=KanonAnonCredsRevList(
                        issuer_id=issuer_id,
                        rev_reg_def_id=rev_reg_def_id,
                        revocation_list=revocation_list,
                        current_accumulator=current_accumulator,
                        timestamp=timestamp,
                    ),
                ),
            )
        )

        assert acapy_rev_list_result.registration_metadata == registration_metadata
        assert acapy_rev_list_result.revocation_list_metadata == revocation_list_metadata
        assert acapy_rev_list_result.revocation_list_state.state == state

        acapy_rev_list = acapy_rev_list_result.revocation_list_state.revocation_list

        assert acapy_rev_list.issuer_id == issuer_id
        assert acapy_rev_list.rev_reg_def_id == rev_reg_def_id
        assert acapy_rev_list.revocation_list == revocation_list
        assert acapy_rev_list.current_accumulator == current_accumulator
        assert acapy_rev_list.timestamp == timestamp

    def test_build_kanon_anoncreds_rev_reg_def_with_edge_cases(self):
        """Test the rev_reg_def builder with special cases."""
        # Test with minimal required fields
        issuer_id = "did:kanon:testnet:zFwZUYPrhi333pC2anAnSkctXgZzLfeR8DXURo2N4xV1C_0.0.5284925"
        cred_def_id = f"{issuer_id}/anoncreds/v0/CRED_DEF/0.0.5281064"
        tag = "minimal-test"
        
        # Create with minimal fields (testing branch conditions)
        minimal_rev_reg_def = AcapyRevRegDef(
            issuer_id=issuer_id,
            cred_def_id=cred_def_id,
            tag=tag,
            type="CL_ACCUM",
            value=AcapyRevRegDefValue(
                public_keys={},  # Empty public keys
                max_cred_num=100,
                tails_location="",  # Empty tails location
                tails_hash=""  # Empty tails hash
            )
        )
        
        # Convert to Kanon type
        kanon_rev_reg_def = build_kanon_anoncreds_rev_reg_def(minimal_rev_reg_def)
        
        # Verify conversion worked correctly
        assert kanon_rev_reg_def.issuer_id == issuer_id
        assert kanon_rev_reg_def.cred_def_id == cred_def_id
        assert kanon_rev_reg_def.tag == tag
        assert kanon_rev_reg_def.value.public_keys == {}
        assert kanon_rev_reg_def.value.max_cred_num == 100
        assert kanon_rev_reg_def.value.tails_location == ""
        assert kanon_rev_reg_def.value.tails_hash == ""

    def test_build_kanon_anoncreds_rev_list_with_edge_cases(self):
        """Test the rev_list builder with edge cases."""
        issuer_id = "did:kanon:testnet:zFwZUYPrhi333pC2anAnSkctXgZzLfeR8DXURo2N4xV1C_0.0.5284925"
        rev_reg_def_id = f"{issuer_id}/anoncreds/v0/REV_REG/0.0.5281064"
        
        # Test with empty revocation list
        empty_rev_list = AcapyRevList(
            issuer_id=issuer_id,
            rev_reg_def_id=rev_reg_def_id,
            revocation_list=[],
            current_accumulator="",
            timestamp=0
        )
        
        kanon_empty_rev_list = build_kanon_anoncreds_rev_list(empty_rev_list)
        
        assert kanon_empty_rev_list.issuer_id == issuer_id
        assert kanon_empty_rev_list.rev_reg_def_id == rev_reg_def_id
        assert kanon_empty_rev_list.revocation_list == []
        assert kanon_empty_rev_list.current_accumulator == ""
        assert kanon_empty_rev_list.timestamp == 0
        
        # Test with null fields in the input
        edge_case_rev_list = AcapyRevList(
            issuer_id=issuer_id,
            rev_reg_def_id=rev_reg_def_id,
            revocation_list=[1, 0, 0, 1, 0],
            current_accumulator=None,  # Test with None
            timestamp=None  # Test with None
        )
        
        kanon_edge_rev_list = build_kanon_anoncreds_rev_list(edge_case_rev_list)
        
        assert kanon_edge_rev_list.issuer_id == issuer_id
        assert kanon_edge_rev_list.rev_reg_def_id == rev_reg_def_id
        assert kanon_edge_rev_list.revocation_list == [1, 0, 0, 1, 0]
        assert kanon_edge_rev_list.current_accumulator is None
        assert kanon_edge_rev_list.timestamp is None

    def test_build_acapy_get_rev_list_result_with_edge_cases(self):
        """Test edge cases in get rev list result builder."""
        resolution_metadata = {"custom_field": "test value"}
        revocation_list_metadata = {"revocation_data": "test"}
        issuer_id = "did:kanon:testnet:zFwZUYPrhi333pC2anAnSkctXgZzLfeR8DXURo2N4xV1C_0.0.5284925"
        rev_reg_def_id = f"{issuer_id}/anoncreds/v0/REV_REG/0.0.5281064"
        
        # Test with minimal data - adding the required revocation_registry_id parameter
        minimal_result = KanonGetRevListResult(
            resolution_metadata=resolution_metadata,
            revocation_list_metadata=revocation_list_metadata,
            revocation_list=None,  # Specifically test with None to cover error cases
            revocation_registry_id=rev_reg_def_id  # Add the missing required parameter
        )
        
        acapy_result = build_acapy_get_rev_list_result(minimal_result)
        
        assert acapy_result.resolution_metadata == resolution_metadata
        assert acapy_result.revocation_registry_metadata == revocation_list_metadata
        assert acapy_result.revocation_list is None
