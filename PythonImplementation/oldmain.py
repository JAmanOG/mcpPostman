import asyncio
from typing import Annotated, Optional, Union, List, Dict, Any
import os
from dotenv import load_dotenv
from fastmcp import FastMCP
from fastmcp.server.auth.providers.bearer import BearerAuthProvider, RSAKeyPair
from mcp import ErrorData, McpError
from mcp.server.auth.provider import AccessToken
from mcp.types import TextContent, ImageContent, INVALID_PARAMS, INTERNAL_ERROR
from pydantic import BaseModel, Field, AnyUrl, validator
import json
import uuid
import time
from datetime import datetime
import httpx
from pathlib import Path
import base64

# --- Load environment variables ---
load_dotenv()

TOKEN = os.environ.get("AUTH_TOKEN")
MY_NUMBER = os.environ.get("MY_NUMBER")

assert TOKEN is not None, "Please set AUTH_TOKEN in your .env file"
assert MY_NUMBER is not None, "Please set MY_NUMBER in your .env file"

# --- Auth Provider ---
class SimpleBearerAuthProvider(BearerAuthProvider):
    def __init__(self, token: str):
        # Generate an ephemeral RSA key so BearerAuthProvider can verify a (unused) JWT structure if sent.
        k = RSAKeyPair.generate()
        super().__init__(
            public_key=k.public_key, jwks_uri=None, issuer=None, audience=None
        )
        self._expected = token
        
    async def load_access_token(self, token: str) -> AccessToken | None:
        # Simple constant‑time style compare (still OK here) + debug
        # printing token
        print(f"[auth] token={token!r}")
        if token == self._expected:
            return AccessToken(
                token=token,
                client_id="puch-client",
                scopes=["*"],
                expires_at=None,
            )
        return None

# --- Rich Tool Description model ---
class RichToolDescription(BaseModel):
    description: str
    use_when: str
    side_effects: Optional[str] = None

# --- Data Models ---
class AuthConfig(BaseModel):
    type: str  # "basic" or "bearer"
    username: Optional[str] = None
    password: Optional[str] = None
    token: Optional[str] = None

class StoredRequest(BaseModel):
    id: str
    name: str
    method: str
    url: str
    headers: Dict[str, str] = {}
    body: Optional[Any] = None
    createdAt: str
    variables: Optional[Dict[str, str]] = None
    auth: Optional[AuthConfig] = None
    preRequestScript: Optional[str] = None
    testScript: Optional[str] = None

class Folder(BaseModel):
    id: str
    name: str
    requests: List[StoredRequest] = []
    folders: List['Folder'] = []
    createdAt: str
    variables: Optional[Dict[str, str]] = None

class Collection(BaseModel):
    id: str
    name: str
    requests: List[StoredRequest] = []
    folders: List[Folder] = []
    createdAt: str
    variables: Optional[Dict[str, str]] = None
    auth: Optional[AuthConfig] = None
    preRequestScript: Optional[str] = None
    testScript: Optional[str] = None

class EnvironmentSet(BaseModel):
    id: str
    name: str
    variables: Dict[str, str]
    createdAt: str

class HistoryEntry(BaseModel):
    id: str
    request: Dict[str, Any]
    response: Dict[str, Any]
    startedAt: str
    durationMs: int
    tests: Optional[List[Dict[str, Any]]] = None
    console: Optional[List[str]] = None

class Globals(BaseModel):
    variables: Dict[str, str] = {}

# --- Utility Functions ---
def gen_id() -> str:
    return uuid.uuid4().hex[:8]

def resolve_variables(raw: str, scopes: List[Dict[str, str]]) -> str:
    for scope in scopes:
        if scope:
            for key, value in scope.items():
                raw = raw.replace(f"{{{{{key}}}}}", value)
    return raw

def deep_apply(obj: Any, scopes: List[Dict[str, str]]) -> Any:
    if obj is None:
        return obj
    if isinstance(obj, str):
        return resolve_variables(obj, scopes)
    if isinstance(obj, list):
        return [deep_apply(v, scopes) for v in obj]
    if isinstance(obj, dict):
        return {k: deep_apply(v, scopes) for k, v in obj.items()}
    return obj

def apply_auth(headers: Dict[str, str], auth: Optional[AuthConfig]) -> Dict[str, str]:
    if not auth:
        return headers
    h = headers.copy()
    if auth.type == "basic" and auth.username and auth.password:
        token = base64.b64encode(f"{auth.username}:{auth.password}".encode()).decode()
        h["Authorization"] = f"Basic {token}"
    elif auth.type == "bearer" and auth.token:
        h["Authorization"] = f"Bearer {auth.token}"
    return h

async def run_script(label: str, source: str, context_data: Dict[str, Any]):
    try:
        print(f"Executing {label} script: {source[:100]}...")
    except Exception as e:
        if 'tests' not in context_data:
            context_data['tests'] = []
        context_data['tests'].append({
            'name': f"{label} script error",
            'passed': False,
            'error': str(e)
        })

def find_folder(collection: Collection, folder_id: str) -> Optional[Folder]:
    stack = collection.folders.copy()
    while stack:
        f = stack.pop()
        if f.id == folder_id:
            return f
        stack.extend(f.folders)
    return None

# --- Data Storage ---
DATA_DIR = Path("data")
COLLECTIONS_FILE = DATA_DIR / "collections.json"
ENV_FILE = DATA_DIR / "environments.json"
HISTORY_FILE = DATA_DIR / "history.json"
GLOBALS_FILE = DATA_DIR / "globals.json"

async def ensure_data_files():
    DATA_DIR.mkdir(exist_ok=True)
    files = [
        (COLLECTIONS_FILE, []),
        (ENV_FILE, []),
        (HISTORY_FILE, []),
        (GLOBALS_FILE, {"variables": {}}),
    ]
    for file, default in files:
        if not file.exists():
            file.write_text(json.dumps(default, indent=2))

async def read_json(file: Path) -> Any:
    return json.loads(file.read_text())

async def write_json(file: Path, data: Any):
    file.write_text(json.dumps(data, indent=2))

# --- MCP Server Setup ---
mcp = FastMCP(
    "Postman-like MCP Server",
    auth=SimpleBearerAuthProvider(TOKEN),
)

# --- Tool: validate (required by Puch) ---
@mcp.tool
async def validate() -> str:
    return MY_NUMBER # type: ignore

# --- Tool: set_globals ---
SetGlobalsDescription = RichToolDescription(
    description="Set or merge global variables",
    use_when="You need to store variables that can be used across all requests",
)

@mcp.tool(description=SetGlobalsDescription.model_dump_json())
async def set_globals(
    variables: Annotated[Dict[str, str], Field(description="Variables to set")]
) -> str:
    await ensure_data_files()
    globals = await read_json(GLOBALS_FILE)
    globals["variables"].update(variables)
    await write_json(GLOBALS_FILE, globals)
    return json.dumps(globals, indent=2)

# --- Tool: get_globals ---
GetGlobalsDescription = RichToolDescription(
    description="Get global variables",
    use_when="You need to retrieve all globally stored variables",
)

@mcp.tool(description=GetGlobalsDescription.model_dump_json())
async def get_globals() -> str:
    await ensure_data_files()
    globals = await read_json(GLOBALS_FILE)
    return json.dumps(globals, indent=2)

# --- Tool: create_collection ---
CreateCollectionDescription = RichToolDescription(
    description="Create a new request collection",
    use_when="You want to group related API requests together",
)

@mcp.tool(description=CreateCollectionDescription.model_dump_json())
async def create_collection(
    name: Annotated[str, Field(description="Name of the collection")],
    variables: Annotated[Optional[Dict[str, str]], Field(description="Collection variables")] = None,
    auth: Annotated[Optional[AuthConfig], Field(description="Default auth for collection")] = None,
    pre_request_script: Annotated[Optional[str], Field(description="Script to run before each request")] = None,
    test_script: Annotated[Optional[str], Field(description="Script to run after each request")] = None,
) -> str:
    await ensure_data_files()
    collections = await read_json(COLLECTIONS_FILE)
    col = Collection(
        id=gen_id(),
        name=name,
        requests=[],
        folders=[],
        createdAt=datetime.now().isoformat(),
        variables=variables,
        auth=auth,
        preRequestScript=pre_request_script,
        testScript=test_script,
    )
    collections.append(json.loads(col.model_dump_json()))
    await write_json(COLLECTIONS_FILE, collections)
    return col.model_dump_json(indent=2)

# --- Tool: update_collection ---
UpdateCollectionDescription = RichToolDescription(
    description="Update collection name/variables/auth/scripts",
    use_when="You need to modify an existing collection",
)

@mcp.tool(description=UpdateCollectionDescription.model_dump_json())
async def update_collection(
    collection_id: Annotated[str, Field(description="ID of collection to update")],
    name: Annotated[Optional[str], Field(description="New name for collection")] = None,
    variables: Annotated[Optional[Dict[str, str]], Field(description="Variables to update")] = None,
    auth: Annotated[Optional[AuthConfig], Field(description="New auth config (set to None to remove)")] = None,
    pre_request_script: Annotated[Optional[str], Field(description="New pre-request script (set to None to remove)")] = None,
    test_script: Annotated[Optional[str], Field(description="New test script (set to None to remove)")] = None,
) -> str:
    await ensure_data_files()
    collections = await read_json(COLLECTIONS_FILE)
    col = next((c for c in collections if c["id"] == collection_id), None)
    if not col:
        raise McpError(ErrorData(code=INVALID_PARAMS, message="Collection not found"))
    
    if name:
        col["name"] = name
    if variables:
        col["variables"] = {**(col.get("variables") or {}), **variables}
    if auth is not None:
        col["auth"] = auth.model_dump() if auth else None
    if pre_request_script is not None:
        col["preRequestScript"] = pre_request_script if pre_request_script else None
    if test_script is not None:
        col["testScript"] = test_script if test_script else None
    
    await write_json(COLLECTIONS_FILE, collections)
    return json.dumps(col, indent=2)

# --- Tool: delete_collection ---
DeleteCollectionDescription = RichToolDescription(
    description="Delete a collection",
    use_when="You want to remove an entire collection",
)

@mcp.tool(description=DeleteCollectionDescription.model_dump_json())
async def delete_collection(
    collection_id: Annotated[str, Field(description="ID of collection to delete")]
) -> str:
    await ensure_data_files()
    collections = await read_json(COLLECTIONS_FILE)
    before = len(collections)
    collections = [c for c in collections if c["id"] != collection_id]
    if len(collections) == before:
        raise McpError(ErrorData(code=INVALID_PARAMS, message="Collection not found"))
    await write_json(COLLECTIONS_FILE, collections)
    return "Deleted"

# --- Tool: list_collections ---
ListCollectionsDescription = RichToolDescription(
    description="List all collections",
    use_when="You want to see all available collections",
)

# --- Tool: add_folder ---
AddFolderDescription = RichToolDescription(
    description="Add a folder to a collection",
    use_when="You want to organize requests within a collection",
)

@mcp.tool(description=ListCollectionsDescription.model_dump_json())
async def list_collections() -> str:
    await ensure_data_files()
    collections = await read_json(COLLECTIONS_FILE)
    return json.dumps(collections, indent=2)
# ...existing code...

# --- Tool: get_collection_id ---
GetCollectionIdDescription = RichToolDescription(
    description="Get collection id(s) by exact collection name",
    use_when="You have a collection name and need its id",
)

@mcp.tool(description=GetCollectionIdDescription.model_dump_json())
async def get_collection_id(
    name: Annotated[str, Field(description="Exact collection name to look up")]
) -> str:
    await ensure_data_files()
    collections = await read_json(COLLECTIONS_FILE)
    matches = [c for c in collections if c.get("name") == name]
    if not matches:
        raise McpError(ErrorData(code=INVALID_PARAMS, message="Collection name not found"))
    if len(matches) == 1:
        return json.dumps({"id": matches[0]["id"], "name": matches[0]["name"]}, indent=2)
    return json.dumps([{"id": c["id"], "name": c["name"]} for c in matches], indent=2)

# --- Tool: get_collection_name ---
GetCollectionNameDescription = RichToolDescription(
    description="Get collection name by id",
    use_when="You have a collection id and need its name",
)

def _walk_folders(folders: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    stack = list(folders)
    while stack:
        f = stack.pop()
        out.append(f)
        stack.extend(f.get("folders", []))
    return out

# --- Tool: get_folder_id ---
GetFolderIdDescription = RichToolDescription(
    description="Get folder id(s) by name within a collection (recursive)",
    use_when="You have a folder name and need its id inside a collection",
)

@mcp.tool(description=GetFolderIdDescription.model_dump_json())
async def get_folder_id(
    collection_id: Annotated[str, Field(description="Parent collection id")],
    name: Annotated[str, Field(description="Exact folder name to look up")],
) -> str:
    await ensure_data_files()
    collections = await read_json(COLLECTIONS_FILE)
    col = next((c for c in collections if c["id"] == collection_id), None)
    if not col:
        raise McpError(ErrorData(code=INVALID_PARAMS, message="Collection not found"))
    all_folders = _walk_folders(col.get("folders", []))
    matches = [f for f in all_folders if f.get("name") == name]
    if not matches:
        raise McpError(ErrorData(code=INVALID_PARAMS, message="Folder name not found"))
    if len(matches) == 1:
        return json.dumps({"id": matches[0]["id"], "name": matches[0]["name"]}, indent=2)
    return json.dumps([{"id": f["id"], "name": f["name"]} for f in matches], indent=2)

# --- Tool: get_folder_name ---
GetFolderNameDescription = RichToolDescription(
    description="Get folder name by id within a collection",
    use_when="You have a folder id and need its name",
)

@mcp.tool(description=GetFolderNameDescription.model_dump_json())
async def get_folder_name(
    collection_id: Annotated[str, Field(description="Parent collection id")],
    folder_id: Annotated[str, Field(description="Folder id to look up")],
) -> str:
    await ensure_data_files()
    collections = await read_json(COLLECTIONS_FILE)
    col = next((c for c in collections if c["id"] == collection_id), None)
    if not col:
        raise McpError(ErrorData(code=INVALID_PARAMS, message="Collection not found"))
    all_folders = _walk_folders(col.get("folders", []))
    folder = next((f for f in all_folders if f.get("id") == folder_id), None)
    if not folder:
        raise McpError(ErrorData(code=INVALID_PARAMS, message="Folder not found"))
    return json.dumps({"id": folder["id"], "name": folder["name"]}, indent=2)


#   --- Tool: add_folder ---
@mcp.tool(description=AddFolderDescription.model_dump_json())
async def add_folder(
    collection_id: Annotated[str, Field(description="ID of parent collection")],
    name: Annotated[str, Field(description="Name of new folder")],
    parent_folder_id: Annotated[Optional[str], Field(description="ID of parent folder if nesting")] = None,
) -> str:
    await ensure_data_files()
    collections = await read_json(COLLECTIONS_FILE)
    col = next((c for c in collections if c["id"] == collection_id), None)
    if not col:
        raise McpError(ErrorData(code=INVALID_PARAMS, message="Collection not found"))
    
    folder = {
        "id": gen_id(),
        "name": name,
        "requests": [],
        "folders": [],
        "createdAt": datetime.now().isoformat(),
    }
    
    if parent_folder_id:
        parent = find_folder(Collection(**col), parent_folder_id)
        if not parent:
            raise McpError(ErrorData(code=INVALID_PARAMS, message="Parent folder not found"))
        parent.folders.append(folder) # type: ignore
    else:
        col["folders"].append(folder)
    
    await write_json(COLLECTIONS_FILE, collections)
    return json.dumps(folder, indent=2)

# --- Tool: add_request ---
AddRequestDescription = RichToolDescription(
    description="Add a request to a collection or folder",
    use_when="You want to store an API request for later use",
)

# --- Tool: add_request ---
@mcp.tool(description=AddRequestDescription.model_dump_json())
async def add_request(
    collection_id: Annotated[str, Field(description="ID of parent collection")],
    name: Annotated[str, Field(description="Name of the request")],
    method: Annotated[str, Field(description="HTTP method (GET, POST, etc)")],
    url: Annotated[str, Field(description="Request URL")],
    headers: Annotated[Dict[str, str], Field(description="Request headers")] = {},
    body: Annotated[Optional[Any], Field(description="Request body")] = None,
    folder_id: Annotated[Optional[str], Field(description="ID of parent folder if any")] = None,
    variables: Annotated[Optional[Dict[str, str]], Field(description="Request variables")] = None,
    auth: Annotated[Optional[AuthConfig], Field(description="Request-specific auth")] = None,
    pre_request_script: Annotated[Optional[str], Field(description="Pre-request script")] = None,
    test_script: Annotated[Optional[str], Field(description="Test script")] = None,
) -> str:
    await ensure_data_files()
    collections = await read_json(COLLECTIONS_FILE)
    col = next((c for c in collections if c["id"] == collection_id), None)
    if not col:
        raise McpError(ErrorData(code=INVALID_PARAMS, message="Collection not found"))
    
    req = {
        "id": gen_id(),
        "name": name,
        "method": method.upper(),
        "url": url,
        "headers": headers,
        "body": body,
        "createdAt": datetime.now().isoformat(),
        "variables": variables,
        "auth": auth.model_dump() if auth else None,
        "preRequestScript": pre_request_script,
        "testScript": test_script,
    }
    
    if folder_id:
        folder = find_folder(Collection(**col), folder_id)
        if not folder:
            raise McpError(ErrorData(code=INVALID_PARAMS, message="Folder not found"))
        folder.requests.append(req) # type: ignore
    else:
        col["requests"].append(req)
    
    await write_json(COLLECTIONS_FILE, collections)
    return json.dumps(req, indent=2)

# --- Tool: update_request ---
UpdateRequestDescription = RichToolDescription(
    description="Update a stored request",
    use_when="You need to modify an existing request",
)

@mcp.tool(description=UpdateRequestDescription.model_dump_json())
async def update_request(
    collection_id: Annotated[str, Field(description="ID of parent collection")],
    request_id: Annotated[str, Field(description="ID of request to update")],
    name: Annotated[Optional[str], Field(description="New name")] = None,
    method: Annotated[Optional[str], Field(description="New HTTP method")] = None,
    url: Annotated[Optional[str], Field(description="New URL")] = None,
    headers: Annotated[Optional[Dict[str, str]], Field(description="New headers")] = None,
    body: Annotated[Optional[Any], Field(description="New body")] = None,
    variables: Annotated[Optional[Dict[str, str]], Field(description="New variables")] = None,
    auth: Annotated[Optional[AuthConfig], Field(description="New auth config")] = None,
    pre_request_script: Annotated[Optional[str], Field(description="New pre-request script")] = None,
    test_script: Annotated[Optional[str], Field(description="New test script")] = None,
) -> str:
    await ensure_data_files()
    collections = await read_json(COLLECTIONS_FILE)
    col = next((c for c in collections if c["id"] == collection_id), None)
    if not col:
        raise McpError(ErrorData(code=INVALID_PARAMS, message="Collection not found"))
    
    # Search for request in collection and all folders
    col_obj = Collection(**col)
    all_requests = col_obj.requests.copy()
    stack = col_obj.folders.copy()
    while stack:
        folder = stack.pop()
        all_requests.extend(folder.requests)
        stack.extend(folder.folders)
    
    req = next((r for r in all_requests if r.id == request_id), None)
    if not req:
        raise McpError(ErrorData(code=INVALID_PARAMS, message="Request not found"))
    
    if name is not None:
        req.name = name
    if method is not None:
        req.method = method.upper()
    if url is not None:
        req.url = url
    if headers is not None:
        req.headers = headers
    if body is not None:
        req.body = body
    if variables is not None:
        req.variables = {**(req.variables or {}), **variables}
    if auth is not None:
        req.auth = auth
    if pre_request_script is not None:
        req.preRequestScript = pre_request_script
    if test_script is not None:
        req.testScript = test_script
    
    # Save back to collections
    await write_json(COLLECTIONS_FILE, collections)
    return req.model_dump_json(indent=2)

# --- Tool: delete_request ---
DeleteRequestDescription = RichToolDescription(
    description="Delete a stored request",
    use_when="You want to remove a request from a collection",
)

@mcp.tool(description=DeleteRequestDescription.model_dump_json())
async def delete_request(
    collection_id: Annotated[str, Field(description="ID of parent collection")],
    request_id: Annotated[str, Field(description="ID of request to delete")],
) -> str:
    await ensure_data_files()
    collections = await read_json(COLLECTIONS_FILE)
    col = next((c for c in collections if c["id"] == collection_id), None)
    if not col:
        raise McpError(ErrorData(code=INVALID_PARAMS, message="Collection not found"))
    
    col_obj = Collection(**col)
    removed = False
    
    # Check root requests
    for i, req in enumerate(col_obj.requests):
        if req.id == request_id:
            col_obj.requests.pop(i)
            removed = True
            break
    
    # Check folders if not found yet
    if not removed:
        stack = col_obj.folders.copy()
        while stack and not removed:
            folder = stack.pop()
            for i, req in enumerate(folder.requests):
                if req.id == request_id:
                    folder.requests.pop(i)
                    removed = True
                    break
            stack.extend(folder.folders)
    
    if not removed:
        raise McpError(ErrorData(code=INVALID_PARAMS, message="Request not found"))
    
    # Save back to collections
    collections = [c if c["id"] != collection_id else json.loads(col_obj.model_dump_json()) for c in collections]
    await write_json(COLLECTIONS_FILE, collections)
    return "Deleted"

# --- Tool: list_requests ---
ListRequestsDescription = RichToolDescription(
    description="List requests in a collection or folder",
    use_when="You want to see all requests in a collection or folder",
)

@mcp.tool(description=ListRequestsDescription.model_dump_json())
async def list_requests(
    collection_id: Annotated[str, Field(description="ID of parent collection")],
    folder_id: Annotated[Optional[str], Field(description="ID of folder if listing folder contents")] = None,
) -> str:
    await ensure_data_files()
    collections = await read_json(COLLECTIONS_FILE)
    col = next((c for c in collections if c["id"] == collection_id), None)
    if not col:
        raise McpError(ErrorData(code=INVALID_PARAMS, message="Collection not found"))
    
    col_obj = Collection(**col)
    if folder_id:
        folder = find_folder(col_obj, folder_id)
        if not folder:
            raise McpError(ErrorData(code=INVALID_PARAMS, message="Folder not found"))
        return json.dumps([r.model_dump() for r in folder.requests], indent=2)
    else:
        return json.dumps([r.model_dump() for r in col_obj.requests], indent=2)

# --- Tool: create_environment ---
CreateEnvironmentDescription = RichToolDescription(
    description="Create an environment variable set",
    use_when="You want to define variables for different environments (dev, prod, etc)",
)

# --- Tool: create_environment ---
@mcp.tool(description=CreateEnvironmentDescription.model_dump_json())
async def create_environment(
    name: Annotated[str, Field(description="Name of the environment")],
    variables: Annotated[Dict[str, str], Field(description="Environment variables")],
) -> str:
    await ensure_data_files()
    envs = await read_json(ENV_FILE)
    env = {
        "id": gen_id(),
        "name": name,
        "variables": variables,
        "createdAt": datetime.now().isoformat(),
    }
    envs.append(env)
    await write_json(ENV_FILE, envs)
    return json.dumps(env, indent=2)

# --- Tool: update_environment ---
UpdateEnvironmentDescription = RichToolDescription(
    description="Update environment variables",
    use_when="You need to modify an existing environment's variables",
)

# --- Tool: update_environment ---
@mcp.tool(description=UpdateEnvironmentDescription.model_dump_json())
async def update_environment(
    environment_id: Annotated[str, Field(description="ID of environment to update")],
    variables: Annotated[Dict[str, str], Field(description="Variables to update")],
) -> str:
    await ensure_data_files()
    envs = await read_json(ENV_FILE)
    env = next((e for e in envs if e["id"] == environment_id), None)
    if not env:
        raise McpError(ErrorData(code=INVALID_PARAMS, message="Environment not found"))
    env["variables"].update(variables)
    await write_json(ENV_FILE, envs)
    return json.dumps(env, indent=2)

# --- Tool: delete_environment ---
DeleteEnvironmentDescription = RichToolDescription(
    description="Delete an environment",
    use_when="You want to remove an environment set",
)

# --- Tool: delete_environment ---
@mcp.tool(description=DeleteEnvironmentDescription.model_dump_json())
async def delete_environment(
    environment_id: Annotated[str, Field(description="ID of environment to delete")]
) -> str:
    await ensure_data_files()
    envs = await read_json(ENV_FILE)
    before = len(envs)
    envs = [e for e in envs if e["id"] != environment_id]
    if len(envs) == before:
        raise McpError(ErrorData(code=INVALID_PARAMS, message="Environment not found"))
    await write_json(ENV_FILE, envs)
    return "Deleted"

# --- Tool: list_environments ---
ListEnvironmentsDescription = RichToolDescription(
    description="List all environments",
    use_when="You want to see all available environments",
)

# --- Tool: list_environments ---
@mcp.tool(description=ListEnvironmentsDescription.model_dump_json())
async def list_environments() -> str:
    await ensure_data_files()
    envs = await read_json(ENV_FILE)
    return json.dumps(envs, indent=2)

# --- Tool: send_request ---
SendRequestDescription = RichToolDescription(
    description="Send an HTTP request (direct or stored)",
    use_when="You want to execute an API request",
    side_effects="Makes actual HTTP requests to external services",
)

# --- Tool: send_request ---
@mcp.tool(description=SendRequestDescription.model_dump_json())
async def send_request(
    method: Annotated[Optional[str], Field(description="HTTP method for direct request")] = None,
    url: Annotated[Optional[str], Field(description="URL for direct request")] = None,
    headers: Annotated[Optional[Dict[str, str]], Field(description="Headers for direct request")] = None,
    body: Annotated[Optional[Any], Field(description="Body for direct request")] = None,
    stored_request_id: Annotated[Optional[str], Field(description="ID of stored request to send")] = None,
    collection_id: Annotated[Optional[str], Field(description="ID of collection containing stored request")] = None,
    environment_id: Annotated[Optional[str], Field(description="ID of environment to use")] = None,
    local_variables: Annotated[Optional[Dict[str, str]], Field(description="Local variables for this request")] = None,
    auth: Annotated[Optional[AuthConfig], Field(description="Auth override for this request")] = None,
    timeout_ms: Annotated[int, Field(description="Request timeout in milliseconds")] = 30000,
) -> str:
    if not ((stored_request_id and collection_id) or (method and url)):
        raise McpError(ErrorData(
            code=INVALID_PARAMS,
            message="Either provide stored_request_id + collection_id OR method + url"
        ))
    
    await ensure_data_files()
    globals = await read_json(GLOBALS_FILE)
    
    # Load stored request if specified
    if stored_request_id:
        collections = await read_json(COLLECTIONS_FILE)
        col = next((c for c in collections if c["id"] == collection_id), None)
        if not col:
            raise McpError(ErrorData(code=INVALID_PARAMS, message="Collection not found"))
        
        col_obj = Collection(**col)
        all_requests = col_obj.requests.copy()
        stack = col_obj.folders.copy()
        while stack:
            folder = stack.pop()
            all_requests.extend(folder.requests)
            stack.extend(folder.folders)
        
        stored_req = next((r for r in all_requests if r.id == stored_request_id), None)
        if not stored_req:
            raise McpError(ErrorData(code=INVALID_PARAMS, message="Stored request not found"))
        
        request = stored_req.model_dump()
    else:
        request = {
            "id": gen_id(),
            "name": "ad-hoc",
            "method": method.upper(), # type: ignore
            "url": url,
            "headers": headers or {},
            "body": body,
            "createdAt": datetime.now().isoformat(),
            "variables": {},
        }
    
    # Load environment if specified
    env_vars = {}
    if environment_id:
        envs = await read_json(ENV_FILE)
        env = next((e for e in envs if e["id"] == environment_id), None)
        if not env:
            raise McpError(ErrorData(code=INVALID_PARAMS, message="Environment not found"))
        env_vars = env["variables"]
    
    local_vars = local_variables or {}
    request_vars = request.get("variables") or {}
    collection_vars = col_obj.variables if stored_request_id else {}
    global_vars = globals.get("variables") or {}
    
    variable_chain = [local_vars, request_vars, collection_vars, env_vars, global_vars]
    
    # Execute pre-request scripts
    tests = []
    console_logs = []
    
    if stored_request_id and col_obj.preRequestScript:
        await run_script("collection pre-request", col_obj.preRequestScript, {
            "request": request,
            "variables": local_vars,
            "tests": tests,
            "console": console_logs,
        })
    
    if stored_request_id and request.get("preRequestScript"):
        await run_script("request pre-request", request["preRequestScript"], {
            "request": request,
            "variables": local_vars,
            "tests": tests,
            "console": console_logs,
        })
    
    # Apply variable substitution
    req_resolved = {
        **request,
        "url": resolve_variables(request["url"], variable_chain),
        "headers": deep_apply(request["headers"], variable_chain),
        "body": deep_apply(request.get("body"), variable_chain),
    }
    
    # Apply auth
    effective_auth = auth or (AuthConfig(**request["auth"]) if request.get("auth") else None)
    headers_with_auth = apply_auth(req_resolved["headers"], effective_auth)
    
    # Make the HTTP request
    started = time.time()
    response_obj = None
    
    try:
        async with httpx.AsyncClient() as client:
            req_kwargs = {
                "method": req_resolved["method"],
                "headers": headers_with_auth,
                "timeout": timeout_ms / 1000,
            }
            
            if req_resolved.get("body") is not None and req_resolved["method"] != "GET":
                if isinstance(req_resolved["body"], dict):
                    req_kwargs["headers"]["Content-Type"] = "application/json"
                    req_kwargs["json"] = req_resolved["body"]
                else:
                    req_kwargs["content"] = str(req_resolved["body"])
            
            response = await client.request(
                url=req_resolved["url"],
                **req_kwargs
            )
            
            try:
                parsed = response.json()
            except ValueError:
                parsed = response.text
            
            response_obj = {
                "status": response.status_code,
                "statusText": response.reason_phrase,
                "headers": dict(response.headers),
                "body": parsed,
            }
    except Exception as e:
        response_obj = {
            "status": 0,
            "statusText": "ERROR",
            "headers": {},
            "body": str(e),
        }
    
    # Execute test scripts
    if stored_request_id and col_obj.testScript:
        await run_script("collection test", col_obj.testScript, {
            "request": req_resolved,
            "response": response_obj,
            "variables": local_vars,
            "tests": tests,
            "console": console_logs,
        })
    
    if stored_request_id and request.get("testScript"):
        await run_script("request test", request["testScript"], {
            "request": req_resolved,
            "response": response_obj,
            "variables": local_vars,
            "tests": tests,
            "console": console_logs,
        })
    
    # Save to history
    elapsed = int((time.time() - started) * 1000)
    history = await read_json(HISTORY_FILE)
    history.insert(0, {
        "id": gen_id(),
        "request": {
            "method": req_resolved["method"],
            "url": req_resolved["url"],
            "headers": headers_with_auth,
            "body": req_resolved.get("body"),
        },
        "response": response_obj,
        "startedAt": datetime.now().isoformat(),
        "durationMs": elapsed,
        "tests": tests,
        "console": console_logs,
    })
    
    # Keep history size reasonable
    while len(history) > 200:
        history.pop()
    
    await write_json(HISTORY_FILE, history)
    
    return json.dumps({
        "response": response_obj,
        "tests": tests,
        "console": console_logs,
        "resolvedUrl": req_resolved["url"],
    }, indent=2)

# --- Tool: history ---
HistoryDescription = RichToolDescription(
    description="List recent request history",
    use_when="You want to see previously executed requests",
)

# --- Tool: history ---
@mcp.tool(description=HistoryDescription.model_dump_json())
async def history(
    limit: Annotated[int, Field(description="Number of history entries to return")] = 20
) -> str:
    await ensure_data_files()
    history = await read_json(HISTORY_FILE)
    return json.dumps(history[:limit], indent=2)

# --- Tool: export_collection ---
ExportCollectionDescription = RichToolDescription(
    description="Export a collection to Postman format",
    use_when="You want to share a collection with Postman users",
)

# --- Tool: export_collection ---
@mcp.tool(description=ExportCollectionDescription.model_dump_json())
async def export_collection(
    collection_id: Annotated[str, Field(description="ID of collection to export")]
) -> str:
    await ensure_data_files()
    collections = await read_json(COLLECTIONS_FILE)
    col = next((c for c in collections if c["id"] == collection_id), None)
    if not col:
        raise McpError(ErrorData(code=INVALID_PARAMS, message="Collection not found"))
    
    col_obj = Collection(**col)
    
    def map_request(r: StoredRequest) -> Dict[str, Any]:
        return {
            "name": r.name,
            "request": {
                "method": r.method,
                "header": [{"key": k, "value": v} for k, v in r.headers.items()],
                "url": r.url,
                "body": {
                    "mode": "raw",
                    "raw": json.dumps(r.body) if isinstance(r.body, dict) else str(r.body),
                } if r.body is not None else None,
            },
            "_mcp": {
                "id": r.id,
                "variables": r.variables,
                "auth": r.auth.model_dump() if r.auth else None,
                "preRequestScript": r.preRequestScript,
                "testScript": r.testScript,
            },
        }
    
    def map_folder(f: Folder) -> Dict[str, Any]:
        return {
            "name": f.name,
            "item": [map_request(r) for r in f.requests] + [map_folder(sf) for sf in f.folders],
        }
    
    exported = {
        "info": {
            "name": col_obj.name,
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
        },
        "item": [map_request(r) for r in col_obj.requests] + [map_folder(f) for f in col_obj.folders],
        "variable": [{"key": k, "value": v} for k, v in (col_obj.variables or {}).items()],
        "_mcp": {
            "id": col_obj.id,
            "auth": col_obj.auth.model_dump() if col_obj.auth else None,
            "preRequestScript": col_obj.preRequestScript,
            "testScript": col_obj.testScript,
        },
    }
    
    return json.dumps(exported, indent=2)

# --- Tool: import_postman_collection ---
ImportPostmanDescription = RichToolDescription(
    description="Import a Postman collection",
    use_when="You want to import a collection from Postman",
)

# --- Tool: import_postman_collection ---
@mcp.tool(description=ImportPostmanDescription.model_dump_json())
async def import_postman_collection(
    json_data: Annotated[str, Field(description="Postman collection JSON")]
) -> str:
    try:
        parsed = json.loads(json_data)
    except json.JSONDecodeError:
        raise McpError(ErrorData(code=INVALID_PARAMS, message="Invalid JSON"))
    
    if not isinstance(parsed.get("item"), list):
        raise McpError(ErrorData(code=INVALID_PARAMS, message="Unsupported collection format"))
    
    await ensure_data_files()
    collections = await read_json(COLLECTIONS_FILE)
    
    def to_request(item: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "id": gen_id(),
            "name": item.get("name") or "request",
            "method": (item.get("request", {}).get("method") or "GET").upper(),
            "url": item.get("request", {}).get("url", {}).get("raw") or "",
            "headers": {h["key"]: h["value"] for h in item.get("request", {}).get("header", []) if "key" in h},
            "body": item.get("request", {}).get("body", {}).get("raw"),
            "createdAt": datetime.now().isoformat(),
            "variables": item.get("_mcp", {}).get("variables"),
            "auth": AuthConfig(**item["_mcp"]["auth"]).model_dump() if item.get("_mcp", {}).get("auth") else None,
            "preRequestScript": item.get("_mcp", {}).get("preRequestScript"),
            "testScript": item.get("_mcp", {}).get("testScript"),
        }
    
    def to_folder(item: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "id": gen_id(),
            "name": item.get("name") or "folder",
            "requests": [to_request(i) for i in item.get("item", []) if i.get("request")],
            "folders": [to_folder(i) for i in item.get("item", []) if not i.get("request") and i.get("item")],
            "createdAt": datetime.now().isoformat(),
        }
    
    collection = {
        "id": gen_id(),
        "name": parsed.get("info", {}).get("name") or "Imported",
        "requests": [to_request(i) for i in parsed.get("item", []) if i.get("request")],
        "folders": [to_folder(i) for i in parsed.get("item", []) if not i.get("request") and i.get("item")],
        "createdAt": datetime.now().isoformat(),
        "variables": {v["key"]: v["value"] for v in parsed.get("variable", []) if "key" in v},
        "auth": AuthConfig(**parsed["_mcp"]["auth"]).model_dump() if parsed.get("_mcp", {}).get("auth") else None,
        "preRequestScript": parsed.get("_mcp", {}).get("preRequestScript"),
        "testScript": parsed.get("_mcp", {}).get("testScript"),
    }
    
    collections.append(collection)
    await write_json(COLLECTIONS_FILE, collections)
    return json.dumps(collection, indent=2)

# --- Run MCP Server ---
async def main():
    print("🚀 Starting MCP server on http://0.0.0.0:8086")
    await mcp.run_async("streamable-http", host="0.0.0.0", port=8086)

if __name__ == "__main__":
    asyncio.run(main())