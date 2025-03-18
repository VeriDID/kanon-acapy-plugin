import json
import time
import requests
import logging
import secrets
import string
from typing import Dict, Any

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Agent URLs
ISSUER_URL = "http://localhost:3001"
HOLDER_URL = "http://localhost:4001"

def check_agent_status() -> bool:
    """Check if both agents are running."""
    try:
        issuer_status = requests.get(f"{ISSUER_URL}/status")
        holder_status = requests.get(f"{HOLDER_URL}/status")
        return issuer_status.status_code == 200 and holder_status.status_code == 200
    except requests.exceptions.ConnectionError:
        return False

def wait_for_connection_active(connection_id: str, agent_url: str, timeout: int = 30) -> Dict[str, Any]:
    """Wait for a connection to become active."""
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            response = requests.get(f"{agent_url}/connections/{connection_id}")
            connection = response.json()
            if connection["state"] == "active":
                return connection
            time.sleep(1)
        except Exception as e:
            logger.warning(f"Error checking connection status: {e}")
            time.sleep(1)
    raise TimeoutError(f"Connection {connection_id} did not become active within {timeout} seconds")

def create_connection() -> Dict[str, str]:
    """Create connection between issuer and holder."""
    # Create invitation from issuer
    logger.info("Creating invitation from issuer...")
    response = requests.post(
        f"{ISSUER_URL}/connections/create-invitation",
        json={"auto_accept": True}
    )
    if response.status_code != 200:
        raise Exception(f"Failed to create invitation: {response.text}")
    
    invitation = response.json()
    issuer_connection_id = invitation["connection_id"]
    logger.info(f"Invitation created with connection ID: {issuer_connection_id}")
    
    # Holder receives invitation
    logger.info("Holder receiving invitation...")
    response = requests.post(
        f"{HOLDER_URL}/connections/receive-invitation",
        json=invitation["invitation"]
    )
    if response.status_code != 200:
        raise Exception(f"Failed to receive invitation: {response.text}")
    
    holder_connection = response.json()
    holder_connection_id = holder_connection["connection_id"]
    logger.info(f"Holder connection ID: {holder_connection_id}")
    
    # Wait for both connections to be active
    logger.info("Waiting for connections to be active...")
    issuer_conn = wait_for_connection_active(issuer_connection_id, ISSUER_URL)
    holder_conn = wait_for_connection_active(holder_connection_id, HOLDER_URL)
    
    logger.info("Connection established successfully")
    return {
        "issuer_connection_id": issuer_connection_id,
        "holder_connection_id": holder_connection_id
    }

def get_kanon_did() -> str:
    """Get existing Kanon DID from wallet."""
    logger.info("Getting existing Kanon DID from wallet...")
    try:
        response = requests.get(f"{ISSUER_URL}/wallet/did/public")
        logger.debug(f"Get public DID response status: {response.status_code}")
        logger.debug(f"Get public DID response: {response.text}")
        
        if response.status_code == 200:
            result = response.json()
            if "result" in result and result["result"].get("did", "").startswith("did:kanon:"):
                did = result["result"]["did"]
                logger.info(f"Found existing Kanon DID: {did}")
                return did
            logger.debug("No Kanon DID found in wallet")
    except Exception as e:
        logger.warning(f"Error getting DID from wallet: {e}")
    return None

def generate_random_seed() -> str:
    """Generate a random 32 character seed."""
    # Create a string of allowed characters (letters and numbers)
    alphabet = string.ascii_letters + string.digits
    # Generate a 32 character random string
    return ''.join(secrets.choice(alphabet) for _ in range(32))

def register_did() -> str:
    """Register a new Kanon DID."""
    logger.info("Registering new Kanon DID...")
    
    # Generate a random seed
    seed = generate_random_seed()
    logger.debug(f"Generated random seed: {seed}")
    
    did_body = {
        "key_type": "Ed25519",
        "metadata": {
            "company_name": "Test Issuer",
            "logo_url": "https://example.com/logo.png",
            "website": "https://example.com"
        },
        "seed": seed
    }
    
    logger.debug(f"DID registration request body: {json.dumps({**did_body, 'seed': '***'}, indent=2)}")
    response = requests.post(
        f"{ISSUER_URL}/kanon/did/register",
        json=did_body
    )
    logger.debug(f"DID registration response status: {response.status_code}")
    logger.debug(f"DID registration response: {response.text}")
    
    # If registration succeeds, return the DID
    if response.status_code == 200:
        result = response.json()
        logger.info(f"DID registered: {json.dumps(result, indent=2)}")
        return result["did"]
    
    raise Exception(f"Failed to register DID: {response.text}")

def get_public_did() -> str:
    """Get the public DID from the wallet."""
    logger.info("Getting public DID...")
    try:
        # Try to register a new DID first
        return register_did()
    except Exception as e:
        logger.warning(f"Could not register DID: {e}")
        return None

def create_schema(issuer_did: str) -> str:
    """Create a test schema."""
    logger.info("Creating schema...")
    
    # Get or register DID
    # issuer_did = register_did()
    if not issuer_did or not issuer_did.startswith("did:kanon:"):
        raise Exception("Could not get a valid Kanon DID for schema creation")
    
    logger.info(f"Using issuer DID: {issuer_did}")
    schema_body = {
        "schema": {
            "attrNames": ["name", "age", "degree"],
            "issuerId": issuer_did,
            "name": "Example schema",
            "version": "1.0"
        },
        "options": {
            "create_transaction_for_endorser": False
        }
    }
    
    logger.debug(f"Schema creation request body: {json.dumps(schema_body, indent=2)}")
    response = requests.post(
        f"{ISSUER_URL}/anoncreds/schema",
        json=schema_body
    )
    logger.debug(f"Schema creation response status: {response.status_code}")
    logger.debug(f"Schema creation response: {response.text}")
    
    if response.status_code != 200:
        raise Exception(f"Failed to create schema: {response.text}")
    
    schema = response.json()
    logger.info(f"Schema created: {json.dumps(schema, indent=2)}")
    
    # Extract schema ID from the nested structure
    if "schema_state" in schema and "schema_id" in schema["schema_state"]:
        return schema["schema_state"]["schema_id"]
    else:
        raise Exception("Schema created but could not find schema_id in response")

def create_credential_definition(schema_id: str, issuer_did: str) -> str:
    """Create a credential definition for the schema."""
    logger.info("Creating credential definition...")
    
    # Get or register DID
    # issuer_did = register_did()
    if not issuer_did or not issuer_did.startswith("did:kanon:"):
        raise Exception("Could not get a valid Kanon DID for credential definition creation")
    
    logger.info(f"Using issuer DID: {issuer_did}")
    cred_def_body = {
        "credential_definition": {
            "issuerId": issuer_did,
            "schemaId": schema_id,
            "tag": "default",
        },
        "options": {
            "create_transaction_for_endorser": False
        }
    }
    
    logger.debug(f"Credential definition creation request body: {json.dumps(cred_def_body, indent=2)}")
    response = requests.post(
        f"{ISSUER_URL}/anoncreds/credential-definition",
        json=cred_def_body
    )
    logger.debug(f"Credential definition creation response status: {response.status_code}")
    logger.debug(f"Credential definition creation response: {response.text}")
    
    if response.status_code != 200:
        raise Exception(f"Failed to create credential definition: {response.text}")
    
    cred_def = response.json()
    logger.info(f"Credential definition created: {json.dumps(cred_def, indent=2)}")
    
    # Extract credential definition ID from the nested structure
    if "credential_definition_state" in cred_def and "credential_definition_id" in cred_def["credential_definition_state"]:
        return cred_def["credential_definition_state"]["credential_definition_id"]
    else:
        raise Exception("Credential definition created but could not find credential_definition_id in response")

def issue_credential(connection_id: str, cred_def_id: str, issuer_id: str = None, schema_id: str = None) -> Dict[str, Any]:
    """Issue a credential to the holder."""
    logger.info(f"Issuing credential with cred_def_id: {cred_def_id}")
    
    # Verify the credential definition exists
    try:
        logger.info("Verifying credential definition exists...")
        response = requests.get(f"{ISSUER_URL}/anoncreds/credential-definition/{cred_def_id}")
        if response.status_code == 200:
            cred_def = response.json()
            logger.info(f"Verified credential definition: {cred_def}")
        else:
            logger.error(f"Failed to verify credential definition: {response.status_code} - {response.text}")
            raise Exception(f"Credential definition not found: {cred_def_id}")
    except Exception as e:
        logger.error(f"Error verifying credential definition: {e}")
        raise
    
    # Get schema information
    schema_name = "schema"
    schema_version = "1.0"
    # Extract the full DID from the credential definition ID
    # Credential definition format: did:method:did-value:3:CL:schema-id:tag
    if issuer_id is None:
        issuer_id = cred_def_id.split(":3:")[0] if ":3:" in cred_def_id else ""
    schema_issuer_id = issuer_id
    
    try:
        if schema_id is None:
            schema_id = cred_def.get("credential_definition", {}).get("schemaId")
            if schema_id:
                logger.info(f"Found schema_id in credential definition: {schema_id}")
                
                # Get schema details
                try:
                    schema_response = requests.get(f"{ISSUER_URL}/anoncreds/schema/{schema_id}")
                    if schema_response.status_code == 200:
                        schema_data = schema_response.json()
                        schema = schema_data.get("schema")
                        if schema:
                            schema_name = schema.get("name", "schema")
                            schema_version = schema.get("version", "1.0")
                            schema_issuer_id = schema.get("issuerId", issuer_id)
                            logger.info(f"Retrieved schema details: name={schema_name}, version={schema_version}, issuer={schema_issuer_id}")
                except Exception as e:
                    logger.warning(f"Error fetching schema details: {e}")
    except Exception as e:
        logger.warning(f"Error extracting schema ID: {e}")
    
    credential_preview = {
        "@type": "issue-credential/2.0/credential-preview",
        "attributes": [
            {"name": "name", "value": "Alice Smith"},
            {"name": "age", "value": "25"},
            {"name": "degree", "value": "Computer Science"}
        ]
    }
    
    # Build issue request with all required fields
    anoncreds_filter = {
        "cred_def_id": cred_def_id,
        "issuer_id": issuer_id
    }
    
    # Add schema ID if we have one
    if schema_id:
        anoncreds_filter["schema_id"] = schema_id
    
    issue_body = {
        "auto_issue": True,
        "auto_remove": True,
        "connection_id": connection_id,
        "credential_preview": credential_preview,
        "filter": {
            "anoncreds": anoncreds_filter
        }
    }
    
    logger.info(f"Sending credential offer with body: {json.dumps(issue_body, indent=2)}")
    
    # Use send-offer endpoint which is more reliable
    response = requests.post(
        f"{ISSUER_URL}/issue-credential-2.0/send-offer",
        json=issue_body
    )
    
    if response.status_code != 200:
        logger.error(f"Failed to issue credential: {response.status_code} - {response.text}")
        
        # Try to get more details about the error
        try:
            error_data = response.json()
            logger.error(f"Error details: {json.dumps(error_data, indent=2)}")
        except:
            pass
            
        # Try the other endpoint as fallback
        logger.info("Trying the /issue-credential-2.0/send endpoint as fallback")
        response = requests.post(
            f"{ISSUER_URL}/issue-credential-2.0/send",
            json=issue_body
        )
        
        if response.status_code != 200:
            logger.error(f"Fallback also failed: {response.status_code} - {response.text}")
            raise Exception(f"Failed to issue credential: {response.text}")
    
    result = response.json()
    logger.info(f"Credential offer initiated: {json.dumps(result, indent=2)}")
    return result

def verify_credential_issued(cred_ex_id: str, timeout: int = 30) -> bool:
    """Verify that the credential was issued successfully."""
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            response = requests.get(f"{ISSUER_URL}/issue-credential-2.0/records/{cred_ex_id}")
            if response.status_code == 200:
                record = response.json()
                if record["state"] == "done":
                    return True
                elif record["state"] == "abandoned":
                    raise Exception("Credential exchange abandoned")
            time.sleep(1)
        except Exception as e:
            logger.warning(f"Error checking credential status: {e}")
            time.sleep(1)
    return False

def get_all_schemas() -> list:
    """Get all schemas from the wallet."""
    logger.info("Getting all schemas...")
    try:
        response = requests.get(f"{ISSUER_URL}/anoncreds/schemas")
        if response.status_code == 200:
            schemas = response.json()
            logger.info(f"Retrieved schemas: {json.dumps(schemas, indent=2)}")
            return schemas
        logger.error(f"Failed to get schemas: {response.status_code} - {response.text}")
        return []
    except Exception as e:
        logger.warning(f"Error getting schemas: {e}")
        return []

def verify_schema(schema_id: str) -> bool:
    """Verify that the schema was created successfully."""
    try:
        # First try getting all schemas
        schemas_response = get_all_schemas()
        if schemas_response and "schema_ids" in schemas_response:
            # Check if our schema_id exists in the results
            if schema_id in schemas_response["schema_ids"]:
                logger.info(f"Schema found in wallet: {schema_id}")
                return True
        
        # Fallback to direct schema lookup if not found in list
        response = requests.get(f"{ISSUER_URL}/anoncreds/schema/{schema_id}")
        if response.status_code == 200:
            schema = response.json()
            logger.info(f"Schema verified via direct lookup: {json.dumps(schema, indent=2)}")
            return True
        return False
    except Exception as e:
        logger.warning(f"Error verifying schema: {e}")
        return False

def verify_credential_definition(cred_def_id: str) -> bool:
    """Verify that the credential definition was created successfully."""
    try:
        response = requests.get(f"{ISSUER_URL}/anoncreds/credential-definition/{cred_def_id}")
        if response.status_code == 200:
            cred_def = response.json()
            logger.info(f"Credential definition verified: {json.dumps(cred_def, indent=2)}")
            return True
        return False
    except Exception as e:
        logger.warning(f"Error verifying credential definition: {e}")
        return False

def main():
    try:
        # Enable debug logging
        logging.getLogger().setLevel(logging.DEBUG)
        
        # Check if agents are running
        if not check_agent_status():
            raise Exception("One or both agents are not running. Please start the agents first.")
        
        # Step 1: Register DID
        logger.info("Step 1: Registering Kanon DID...")
        issuer_did = register_did()
        logger.info(f"Using DID: {issuer_did}")
        
        # Step 2: Create connection
        logger.info("Step 2: Creating connection between issuer and holder...")
        connection_ids = create_connection()
        logger.info(f"Connection established: {connection_ids}")
        
        # Step 3: Create schema
        logger.info("Step 3: Creating schema...")
        schema_id = create_schema(issuer_did)
        logger.info(f"Schema created with ID: {schema_id}")
        
        # Verify schema creation
        if not verify_schema(schema_id):
            raise Exception("Failed to verify schema creation")
        
        # # Step 4: Create credential definition
        # logger.info("Step 4: Creating credential definition...")
        cred_def_id = create_credential_definition(schema_id, issuer_did)
        # logger.info(f"Credential definition created with ID: {cred_def_id}")
        
        # # Verify credential definition creation
        # if not verify_credential_definition(cred_def_id):
        #     raise Exception("Failed to verify credential definition creation")
        
        # # Step 5: Issue credential
        # logger.info("Step 5: Issuing credential...")
        issuance_result = issue_credential(
            connection_ids["issuer_connection_id"],
            cred_def_id,
            issuer_did,
            schema_id
        )
        
        # # Step 6: Verify credential issuance
        if "credential_exchange_id" in issuance_result:
            logger.info("Waiting for credential issuance to complete...")
            if verify_credential_issued(issuance_result["credential_exchange_id"]):
                logger.info("Credential issued successfully!")
            else:
                logger.error("Credential issuance timed out or failed")
        
        logger.info("Test completed!")
        
    except Exception as e:
        logger.error(f"Error during test: {str(e)}")
        raise

if __name__ == "__main__":
    main() 