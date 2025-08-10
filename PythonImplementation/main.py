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
from datetime import datetime,timezone
import httpx
import base64
import redis

# Load env early
load_dotenv()

# Add required env variables
TOKEN = os.environ.get("AUTH_TOKEN", "dev-token")
MY_NUMBER = os.environ.get("MY_NUMBER", "")

# --- Redis configuration via environment ---
REDIS_HOST = os.environ.get("REDIS_HOST", "localhost")
REDIS_PORT = int(os.environ.get("REDIS_PORT", "6379"))
REDIS_PASSWORD = os.environ.get("ACCESS_TOKEN")  # optional


print("Redis configuration:")
print(f" Host: {REDIS_HOST}")
print(f" Port: {REDIS_PORT}")
print(f" Auth: {'yes' if REDIS_PASSWORD else 'no'}")

redis_client: Optional[redis.Redis] = None
try:
    redis_client = redis.Redis(
        host=REDIS_HOST,
        port=REDIS_PORT,
        password=REDIS_PASSWORD,
        ssl=bool(int(os.environ.get("REDIS_SSL", "0"))),
        decode_responses=True,
        socket_timeout=10,
        socket_connect_timeout=10,
    )
    if redis_client is not None:
        try:
            redis_client.ping()
            print("✅ Connected to Redis")
        except Exception as e:
            print(f"❌ Failed to ping Redis: {e}")
    else:
        print("⚠️ Redis client not initialized; data tools will fail until configured.")
except Exception as e:
    print(f"❌ Failed to connect to Redis: {e}")
    redis_client = None

# Helper to access redis safely

def get_redis() -> redis.Redis:
    if redis_client is None:
        raise RuntimeError("Redis client not initialized")
    return redis_client

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

# --- Data Storage (Redis-backed instead of filesystem) ---
# Redis key names
COLLECTIONS_KEY = "mcp:collections"
ENVIRONMENTS_KEY = "mcp:environments"
HISTORY_KEY = "mcp:history"
GLOBALS_KEY = "mcp:globals"

async def ensure_data_files():  # kept name for minimal downstream changes
    r = get_redis()
    # Initialize each structure if missing
    defaults = {
        COLLECTIONS_KEY: [],
        ENVIRONMENTS_KEY: [],
        HISTORY_KEY: [],
        GLOBALS_KEY: {"variables": {}},
    }
    pipe = r.pipeline()
    for k in defaults:
        if not r.exists(k):
            pipe.set(k, json.dumps(defaults[k]))
    pipe.execute()

async def read_json(key: str) -> Any:
    r = get_redis()
    raw = r.get(key)
    if raw is None:
        # If not present, re-init defaults
        await ensure_data_files()
        raw = r.get(key) or "null"
    return json.loads(raw) # type: ignore

async def write_json(key: str, data: Any):
    r = get_redis()
    r.set(key, json.dumps(data))

# --- User Namespacing & RBAC ---
USER_META_KEY_PREFIX = "mcp:user:meta:"  # per user key storing role & classification
DEFAULT_ROLE = "admin"  # fallback role
VALID_ROLES = {"admin", "editor", "reader", "tester"}
# Action constants
A_CREATE = "create"
A_UPDATE = "update"
A_DELETE = "delete"
A_READ = "read"
A_EXECUTE = "execute"  # sending requests
A_EXPORT = "export"
A_IMPORT = "import"
A_ADMIN = "admin"

ROLE_PERMISSIONS = {
    "admin": {A_CREATE, A_UPDATE, A_DELETE, A_READ, A_EXECUTE, A_EXPORT, A_IMPORT, A_ADMIN},
    "editor": {A_CREATE, A_UPDATE, A_DELETE, A_READ, A_EXECUTE, A_EXPORT},
    "reader": {A_READ, A_EXPORT},
    "tester": {A_READ, A_EXECUTE},
}

def _user_meta_key(user_id: str) -> str:
    return f"{USER_META_KEY_PREFIX}{user_id}"  # single JSON doc

async def get_user_meta(user_id: str) -> Dict[str, Any]:
    await ensure_data_files_global()  # ensure redis up
    r = get_redis()
    raw = r.get(_user_meta_key(user_id))
    if not raw:
        meta = {"role": DEFAULT_ROLE, "classification": None, "createdAt": datetime.now(timezone.utc).isoformat()}
        r.set(_user_meta_key(user_id), json.dumps(meta))
        return meta
    return json.loads(raw)

async def set_user_meta(user_id: str, role: Optional[str] = None, classification: Optional[str] = None):
    meta = await get_user_meta(user_id)
    if role:
        if role not in VALID_ROLES:
            raise McpError(ErrorData(code=INVALID_PARAMS, message=f"Invalid role {role}"))
        meta["role"] = role
    if classification is not None:
        meta["classification"] = classification
    get_redis().set(_user_meta_key(user_id), json.dumps(meta))
    return meta

async def require_permission(user_id: str, action: str):
    meta = await get_user_meta(user_id)
    role = meta.get("role", DEFAULT_ROLE)
    allowed = ROLE_PERMISSIONS.get(role, set())
    if action not in allowed:
        raise McpError(ErrorData(code=INVALID_PARAMS, message=f"Role '{role}' lacks permission for action '{action}'"))

# Namespaced key helpers per user
class UserKeys:
    def __init__(self, user_id: str):
        self.collections = f"mcp:{user_id}:collections"
        self.environments = f"mcp:{user_id}:environments"
        self.history = f"mcp:{user_id}:history"
        self.globals = f"mcp:{user_id}:globals"

def user_keys(user_id: str) -> UserKeys:
    return UserKeys(user_id)

# Modify data ensure & read/write to optionally accept user scope
async def ensure_data_files_global():
    # only ensures redis connectivity defaults; per-user ensure will call this then create namespaced keys
    await ensure_data_files()  # existing global initializer (kept for backwards compatibility)

async def ensure_user_data(user_id: str):
    r = get_redis()
    keys = user_keys(user_id)
    defaults = {
        keys.collections: [],
        keys.environments: [],
        keys.history: [],
        keys.globals: {"variables": {}},
    }
    pipe = r.pipeline()
    for k, v in defaults.items():
        if not r.exists(k):
            pipe.set(k, json.dumps(v))
    pipe.execute()

async def read_user_json(user_id: str, kind: str) -> Any:
    keys = user_keys(user_id)
    m = {
        'collections': keys.collections,
        'environments': keys.environments,
        'history': keys.history,
        'globals': keys.globals,
    }
    redis_key = m[kind]
    r = get_redis()
    raw = r.get(redis_key)
    if raw is None:
        await ensure_user_data(user_id)
        raw = r.get(redis_key) or 'null'
    return json.loads(raw)

async def write_user_json(user_id: str, kind: str, data: Any):
    keys = user_keys(user_id)
    m = {
        'collections': keys.collections,
        'environments': keys.environments,
        'history': keys.history,
        'globals': keys.globals,
    }
    get_redis().set(m[kind], json.dumps(data))
    
    # --- MCP Server Setup ---
mcp = FastMCP(
    "Postman-like MCP Server",
    auth=SimpleBearerAuthProvider(TOKEN),
)


# --- User Meta Tools ---
UserMetaSetDesc = RichToolDescription(
    description="Set a user's role and/or classification (admin only)",
    use_when="You need to change access level or data classification for a user",
    side_effects="Updates user metadata controlling RBAC",
)

@mcp.tool(description=UserMetaSetDesc.model_dump_json())
async def set_user_metadata(
    puch_user_id: Annotated[str, Field(description="Acting (admin) user id")],
    target_user_id: Annotated[str, Field(description="User id whose metadata to modify")],
    role: Annotated[Optional[str], Field(description=f"New role ({', '.join(sorted(VALID_ROLES))})")] = None,
    classification: Annotated[Optional[str], Field(description="Data classification label e.g. internal, confidential")]=None,
) -> str:
    await require_permission(puch_user_id, A_ADMIN)
    meta = await set_user_meta(target_user_id, role=role, classification=classification)
    return json.dumps({"updated": meta, "target": target_user_id}, indent=2)

UserMetaGetDesc = RichToolDescription(
    description="Get your user metadata (role & classification)",
    use_when="You need to know current permissions or classification context",
)

@mcp.tool(description=UserMetaGetDesc.model_dump_json())
async def get_my_metadata(puch_user_id: Annotated[str, Field(description="Your user id")]) -> str:
    meta = await get_user_meta(puch_user_id)
    return json.dumps(meta, indent=2)


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
    globals = await read_json(GLOBALS_KEY)
    globals["variables"].update(variables)
    await write_json(GLOBALS_KEY, globals)
    return json.dumps(globals, indent=2)

# --- Tool: get_globals ---
GetGlobalsDescription = RichToolDescription(
    description="Get global variables",
    use_when="You need to retrieve all globally stored variables",
)

@mcp.tool(description=ExecuteRequestDescription.model_dump_json())
async def execute_request(
    puch_user_id: Annotated[str, Field(description="User id performing action")],
    collection_ref: Annotated[str, Field(description="Collection id or exact name containing the request")],
    request_ref: Annotated[str, Field(description="Request id or exact name (if unique)")],
    environment_ref: Annotated[Optional[str], Field(description="Environment id or name to apply (optional)")] = None,
    timeout_seconds: Annotated[int, Field(description="Request timeout in seconds", ge=1, le=120)] = 30,
) -> str:
    await require_permission(puch_user_id, A_EXECUTE)
    await ensure_user_data(puch_user_id)

    # Load user data
    collections = await read_user_json(puch_user_id, 'collections')
    globals_obj = await read_user_json(puch_user_id, 'globals')
    environments = await read_user_json(puch_user_id, 'environments')
    env_vars: Dict[str, str] = {}

    # Resolve environment (optional)
    if environment_ref:
        env = next((e for e in environments if e.get('id') == environment_ref or e.get('name') == environment_ref), None)
        if not env:
            raise McpError(ErrorData(code=INVALID_PARAMS, message="Environment not found"))
        env_vars = env.get('variables', {})

    # Resolve collection & request
    col = await _resolve_collection(collections, collection_ref)
    col_obj = Collection(**col)

    all_requests: List[StoredRequest] = []
    all_requests.extend(col_obj.requests)
    stack = col_obj.folders.copy()
    while stack:
        f = stack.pop()
        all_requests.extend(f.requests)
        stack.extend(f.folders)

    req = next((r for r in all_requests if r.id == request_ref), None)
    if not req:
        named = [r for r in all_requests if r.name == request_ref]
        if len(named) == 1:
            req = named[0]
        elif len(named) > 1:
            raise McpError(ErrorData(code=INVALID_PARAMS, message="Request name ambiguous; use id"))
    if not req:
        raise McpError(ErrorData(code=INVALID_PARAMS, message="Request not found"))

    # Variable resolution order (lowest precedence first)
    scopes: List[Dict[str, str]] = [
        globals_obj.get('variables') or {},
        env_vars,
        col_obj.variables or {},
        req.variables or {},
    ]

    # Build final URL / body / headers
    final_url = resolve_variables(req.url, scopes)
    final_headers = {k: resolve_variables(v, scopes) for k, v in (req.headers or {}).items()}
    final_headers = apply_auth(final_headers, req.auth or col_obj.auth)

    final_body = None
    if isinstance(req.body, dict) or isinstance(req.body, list):
        final_body = deep_apply(req.body, scopes)
    elif isinstance(req.body, str):
        final_body = resolve_variables(req.body, scopes)

    context: Dict[str, Any] = {
        "collection": json.loads(col_obj.model_dump_json()),
        "request": json.loads(req.model_dump_json()),
        "resolved": {
            "url": final_url,
            "headers": final_headers,
            "body": final_body,
        },
        "variables": {
            "globals": globals_obj.get('variables') or {},
            "environment": env_vars,
            "collection": col_obj.variables or {},
            "request": req.variables or {},
        },
        "tests": [],
        "console": [],
    }

    # Run pre-request script (stubbed)
    if req.preRequestScript:
        await run_script("pre-request", req.preRequestScript, context)
    elif col_obj.preRequestScript:
        await run_script("pre-request (collection)", col_obj.preRequestScript, context)

    started = time.time()
    status_code = None
    resp_headers: Dict[str, str] = {}
    resp_body_snippet: Union[str, Dict[str, Any], None] = None
    error: Optional[str] = None

    try:
        async with httpx.AsyncClient(timeout=timeout_seconds) as client:
            method = req.method.upper()
            if method in {"GET", "DELETE", "HEAD"}:
                response = await client.request(method, final_url, headers=final_headers)
            else:
                # JSON vs raw
                if isinstance(final_body, (dict, list)):
                    response = await client.request(method, final_url, headers=final_headers, json=final_body)
                else:
                    response = await client.request(method, final_url, headers=final_headers, content=final_body if final_body else None)
        status_code = response.status_code
        resp_headers = {k: v for k, v in response.headers.items()}
        content_type = response.headers.get("content-type", "")
        try:
            if "application/json" in content_type:
                resp_body_snippet = response.json()
            else:
                text = response.text
                resp_body_snippet = text[:5000]  # limit
        except Exception:
            resp_body_snippet = response.text[:5000]
    except Exception as e:
        error = str(e)

    duration_ms = int((time.time() - started) * 1000)

    # Run test script (stub) if success
    if error is None:
        if req.testScript:
            await run_script("test", req.testScript, context)
        elif col_obj.testScript:
            await run_script("test (collection)", col_obj.testScript, context)

    history_entry = {
        "id": gen_id(),
        "request": {
            "id": req.id,
            "name": req.name,
            "method": req.method,
            "resolvedUrl": final_url,
            "headers": final_headers,
            "body": final_body,
        },
        "response": {
            "status": status_code,
            "headers": resp_headers,
            "body": resp_body_snippet,
            "error": error,
        },
        "startedAt": datetime.utcnow().isoformat() + "Z",
        "durationMs": duration_ms,
        "tests": context.get("tests"),
        "console": context.get("console"),
        "environment": environment_ref,
    }

    # Persist history (prepend)
    hist = await read_user_json(puch_user_id, 'history')
    if not isinstance(hist, list):
        hist = []
    hist.insert(0, history_entry)
    await write_user_json(puch_user_id, 'history', hist)

    return json.dumps(history_entry, indent=2)


@mcp.tool(description=GetGlobalsDescription.model_dump_json())
async def get_globals() -> str:
    await ensure_data_files()
    globals = await read_json(GLOBALS_KEY)
    return json.dumps(globals, indent=2)

# --- Tool: create_collection ---
CreateCollectionDescription = RichToolDescription(
    description="Create a new request collection",
    use_when="You want to group related API requests together",
)

@mcp.tool(description=CreateCollectionDescription.model_dump_json())
async def create_collection(
    puch_user_id: Annotated[str, Field(description="User id performing action")],
    name: Annotated[str, Field(description="Name of the collection")],
    variables: Annotated[Optional[Dict[str, str]], Field(description="Collection variables")] = None,
    auth: Annotated[Optional[AuthConfig], Field(description="Default auth for collection")] = None,
    pre_request_script: Annotated[Optional[str], Field(description="Script to run before each request")] = None,
    test_script: Annotated[Optional[str], Field(description="Script to run after each request")] = None,
) -> str:
    await require_permission(puch_user_id, A_CREATE)
    await ensure_user_data(puch_user_id)
    collections = await read_user_json(puch_user_id, 'collections')
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
    await write_user_json(puch_user_id, 'collections', collections)
    return col.model_dump_json(indent=2)

# --- Tool: update_collection ---
UpdateCollectionDescription = RichToolDescription(
    description="Update collection name/variables/auth/scripts",
    use_when="You need to modify an existing collection",
)

@mcp.tool(description=UpdateCollectionDescription.model_dump_json())
async def update_collection(
    puch_user_id: Annotated[str, Field(description="User id performing action")],
    collection_ref: Annotated[str, Field(description="Collection id or exact name")],
    name: Annotated[Optional[str], Field(description="New name for collection")] = None,
    variables: Annotated[Optional[Dict[str, str]], Field(description="Variables to merge")] = None,
    auth: Annotated[Optional[AuthConfig], Field(description="New auth config (null to clear)")] = None,
    clear_auth: Annotated[bool, Field(description="Set true to remove auth")] = False,
    pre_request_script: Annotated[Optional[str], Field(description="Pre-request script (null to clear)")] = None,
    clear_pre_request: Annotated[bool, Field(description="Set true to remove pre-request script")] = False,
    test_script: Annotated[Optional[str], Field(description="Test script (null to clear)")] = None,
    clear_test: Annotated[bool, Field(description="Set true to remove test script")] = False,
) -> str:
    await require_permission(puch_user_id, A_UPDATE)
    await ensure_user_data(puch_user_id)
    collections = await read_user_json(puch_user_id, 'collections')
    col = await _resolve_collection(collections, collection_ref)
    if name:
        col['name'] = name
    if variables:
        col['variables'] = {**(col.get('variables') or {}), **variables}
    if clear_auth:
        col.pop('auth', None)
    elif auth is not None:
        col['auth'] = auth.model_dump()
    if clear_pre_request:
        col.pop('preRequestScript', None)
    elif pre_request_script is not None:
        col['preRequestScript'] = pre_request_script
    if clear_test:
        col.pop('testScript', None)
    elif test_script is not None:
        col['testScript'] = test_script
    await write_user_json(puch_user_id, 'collections', collections)
    return json.dumps(col, indent=2)

# --- Tool: delete_collection ---
DeleteCollectionDescription = RichToolDescription(
    description="Delete a collection",
    use_when="You want to remove an entire collection",
)

@mcp.tool(description=DeleteCollectionDescription.model_dump_json())
async def delete_collection(
    puch_user_id: Annotated[str, Field(description="User id performing action")],
    collection_ref: Annotated[str, Field(description="Collection id or exact name to delete")],
) -> str:
    await require_permission(puch_user_id, A_DELETE)
    await ensure_user_data(puch_user_id)
    collections = await read_user_json(puch_user_id, 'collections')
    # resolve to id first
    col = await _resolve_collection(collections, collection_ref)
    target_id = col['id']
    new_cols = [c for c in collections if c.get('id') != target_id]
    if len(new_cols) == len(collections):
        raise McpError(ErrorData(code=INVALID_PARAMS, message="Collection not found"))
    await write_user_json(puch_user_id, 'collections', new_cols)
    return json.dumps({"deleted": target_id}, indent=2)

# --- Tool: list_collections ---
ListCollectionsDescription = RichToolDescription(
    description="List all collections for the user",
    use_when="You want to see your collections",
)

@mcp.tool(description=ListCollectionsDescription.model_dump_json())
async def list_collections(
    puch_user_id: Annotated[str, Field(description="User id performing action")]
) -> str:
    await require_permission(puch_user_id, A_READ)
    await ensure_user_data(puch_user_id)
    collections = await read_user_json(puch_user_id, 'collections')
    return json.dumps(collections, indent=2)

# --- Tool: get_collection_id ---
GetCollectionIdDescription = RichToolDescription(
    description="Get collection id(s) by exact collection name",
    use_when="You have a collection name and need its id",
)

@mcp.tool(description=GetCollectionIdDescription.model_dump_json())
async def get_collection_id(
    puch_user_id: Annotated[str, Field(description="User id performing action")],
    name: Annotated[str, Field(description="Exact collection name to look up")]
) -> str:
    await require_permission(puch_user_id, A_READ)
    collections = await read_user_json(puch_user_id, 'collections')
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

@mcp.tool(description=GetCollectionNameDescription.model_dump_json())
async def get_collection_name(
    puch_user_id: Annotated[str, Field(description="User id performing action")],
    collection_id: Annotated[str, Field(description="Collection id")],
) -> str:
    await require_permission(puch_user_id, A_READ)
    collections = await read_user_json(puch_user_id, 'collections')
    col = next((c for c in collections if c.get('id') == collection_id), None)
    if not col:
        raise McpError(ErrorData(code=INVALID_PARAMS, message="Collection not found"))
    return json.dumps({"id": col['id'], "name": col['name']}, indent=2)

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

# Replaced with per-user variant (previous global version removed)
@mcp.tool(description=GetFolderIdDescription.model_dump_json(), name="get_folder_id")
async def get_folder_id_per_user(
    puch_user_id: Annotated[str, Field(description="User id performing action")],
    collection_ref: Annotated[str, Field(description="Parent collection id or exact name")],
    name: Annotated[str, Field(description="Exact folder name to look up")],
) -> str:
    await require_permission(puch_user_id, A_READ)
    await ensure_user_data(puch_user_id)
    collections = await read_user_json(puch_user_id, 'collections')
    col = await _resolve_collection(collections, collection_ref)
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

# Replaced with per-user variant (previous global version removed)
@mcp.tool(description=GetFolderNameDescription.model_dump_json(), name="get_folder_name")
async def get_folder_name_per_user(
    puch_user_id: Annotated[str, Field(description="User id performing action")],
    collection_ref: Annotated[str, Field(description="Parent collection id or exact name")],
    folder_id: Annotated[str, Field(description="Folder id to look up")],
) -> str:
    await require_permission(puch_user_id, A_READ)
    await ensure_user_data(puch_user_id)
    collections = await read_user_json(puch_user_id, 'collections')
    col = await _resolve_collection(collections, collection_ref)
    all_folders = _walk_folders(col.get("folders", []))
    folder = next((f for f in all_folders if f.get("id") == folder_id), None)
    if not folder:
        raise McpError(ErrorData(code=INVALID_PARAMS, message="Folder not found"))
    return json.dumps({"id": folder["id"], "name": folder["name"]}, indent=2)


#   --- Tool: add_folder ---
AddFolderDescription = RichToolDescription(
    description="Add a folder to a collection",
    use_when="You want to organize requests within a collection",
)

# Helper: resolve collection by id or (exact) name
async def _resolve_collection(collections: List[Dict[str, Any]], ref: str) -> Dict[str, Any]:
    col = next((c for c in collections if c.get("id") == ref), None)
    if col:
        return col
    # fallback: exact name match (case-sensitive first)
    matches = [c for c in collections if c.get("name") == ref]
    if not matches:
        # try case-insensitive
        matches_ci = [c for c in collections if c.get("name", "").lower() == ref.lower()]
        if not matches_ci:
            raise McpError(ErrorData(code=INVALID_PARAMS, message="Collection not found (by id or name)"))
        matches = matches_ci
    if len(matches) > 1:
        raise McpError(ErrorData(code=INVALID_PARAMS, message="Multiple collections share this name; use id"))
    return matches[0]

@mcp.tool(description=AddFolderDescription.model_dump_json())
async def add_folder(
    puch_user_id: Annotated[str, Field(description="User id performing action")],
    collection_id: Annotated[str, Field(description="ID or exact name of parent collection")],
    name: Annotated[str, Field(description="Name of new folder")],
    parent_folder_id: Annotated[Optional[str], Field(description="ID of parent folder if nesting")] = None,
) -> str:
    await require_permission(puch_user_id, A_CREATE)
    await ensure_user_data(puch_user_id)
    collections = await read_user_json(puch_user_id, 'collections')
    # Use helper to resolve either id or name
    try:
        col = await _resolve_collection(collections, collection_id)
    except McpError as e:
        raise e
    # Work on a Pydantic instance for folder traversal
    col_obj = Collection(**col)
    folder = {
        "id": gen_id(),
        "name": name,
        "requests": [],
        "folders": [],
        "createdAt": datetime.now().isoformat(),
    }
    if parent_folder_id:
        parent = find_folder(col_obj, parent_folder_id)
        if not parent:
            raise McpError(ErrorData(code=INVALID_PARAMS, message="Parent folder not found"))
        parent.folders.append(Folder(**folder))
        # Need to serialize back the updated structure
        col.update(json.loads(col_obj.model_dump_json()))
    else:
        col.setdefault("folders", []).append(folder)
    await write_user_json(puch_user_id, 'collections', collections)
    return json.dumps(folder, indent=2)

# --- Tool: add_request ---
AddRequestDescription = RichToolDescription(
    description="Add a request to a collection or folder",
    use_when="You want to store an API request for later use",
)

# --- Tool: add_request ---
@mcp.tool(description=AddRequestDescription.model_dump_json())
async def add_request(
    puch_user_id: Annotated[str, Field(description="User id performing action")],
    collection_ref: Annotated[str, Field(description="Collection id or name")],
    name: Annotated[str, Field(description="Request name")],
    method: Annotated[str, Field(description="HTTP method")],
    url: Annotated[str, Field(description="Request URL")],
    headers: Annotated[Optional[Dict[str, str]], Field(description="Headers map")] = None,
    body: Annotated[Optional[Any], Field(description="Body (json or string)")] = None,
    folder_ref: Annotated[Optional[str], Field(description="Folder id or name (optional)")] = None,
    variables: Annotated[Optional[Dict[str, str]], Field(description="Request variables")] = None,
    auth: Annotated[Optional[AuthConfig], Field(description="Request auth override")] = None,
    pre_request_script: Annotated[Optional[str], Field(description="Pre-request script")]=None,
    test_script: Annotated[Optional[str], Field(description="Test script")]=None,
) -> str:
    await require_permission(puch_user_id, A_CREATE)
    await ensure_user_data(puch_user_id)
    collections = await read_user_json(puch_user_id, 'collections')
    col = await _resolve_collection(collections, collection_ref)
    col_obj = Collection(**col)
    target_folder = None
    if folder_ref:
        # allow id or unique name
            # search by id first
        target_folder = find_folder(col_obj, folder_ref)
        if not target_folder:
            # name search
            all_folders = []
            stack = col_obj.folders.copy()
            while stack:
                f = stack.pop()
                all_folders.append(f)
                stack.extend(f.folders)
            named = [f for f in all_folders if f.name == folder_ref]
            if len(named) == 1:
                target_folder = named[0]
            elif len(named) > 1:
                raise McpError(ErrorData(code=INVALID_PARAMS, message="Folder name ambiguous; use id"))
            else:
                raise McpError(ErrorData(code=INVALID_PARAMS, message="Folder not found"))
    req = StoredRequest(
        id=gen_id(),
        name=name,
        method=method.upper(),
        url=url,
        headers=headers or {},
        body=body,
        createdAt=datetime.now().isoformat(),
        variables=variables,
        auth=auth,
        preRequestScript=pre_request_script,
        testScript=test_script,
    )
    if target_folder:
        target_folder.requests.append(req)
        col.update(json.loads(col_obj.model_dump_json()))
    else:
        col.setdefault('requests', []).append(json.loads(req.model_dump_json()))
    await write_user_json(puch_user_id, 'collections', collections)
    return req.model_dump_json(indent=2)

# --- Tool: update_request ---
UpdateRequestDescription = RichToolDescription(
    description="Update a stored request",
    use_when="You need to modify an existing request",
)

@mcp.tool(description=UpdateRequestDescription.model_dump_json())
async def update_request(
    puch_user_id: Annotated[str, Field(description="User id performing action")],
    collection_ref: Annotated[str, Field(description="Collection id or name")],
    request_ref: Annotated[str, Field(description="Request id or exact name (if unique)")],
    name: Annotated[Optional[str], Field(description="New name")]=None,
    method: Annotated[Optional[str], Field(description="New HTTP method")]=None,
    url: Annotated[Optional[str], Field(description="New URL")]=None,
    headers: Annotated[Optional[Dict[str, str]], Field(description="New headers")]=None,
    body: Annotated[Optional[Any], Field(description="New body")]=None,
    variables: Annotated[Optional[Dict[str, str]], Field(description="Variables to merge")]=None,
    clear_variables: Annotated[bool, Field(description="If true, reset variables before merge")]=False,
    auth: Annotated[Optional[AuthConfig], Field(description="Auth override")]=None,
    clear_auth: Annotated[bool, Field(description="Remove auth if true")]=False,
    pre_request_script: Annotated[Optional[str], Field(description="Set pre-request script")]=None,
    clear_pre_request: Annotated[bool, Field(description="Remove pre-request script if true")]=False,
    test_script: Annotated[Optional[str], Field(description="Set test script")]=None,
    clear_test: Annotated[bool, Field(description="Remove test script if true")]=False,
) -> str:
    await require_permission(puch_user_id, A_UPDATE)
    await ensure_user_data(puch_user_id)
    collections = await read_user_json(puch_user_id, 'collections')
    col = await _resolve_collection(collections, collection_ref)
    col_obj = Collection(**col)
    # gather all requests
    all_requests: List[StoredRequest] = []
    all_requests.extend(col_obj.requests)
    stack = col_obj.folders.copy()
    while stack:
        f = stack.pop()
        all_requests.extend(f.requests)
        stack.extend(f.folders)
    target = next((r for r in all_requests if r.id == request_ref), None)
    if not target:
        named = [r for r in all_requests if r.name == request_ref]
        if len(named) == 1:
            target = named[0]
        elif len(named) > 1:
            raise McpError(ErrorData(code=INVALID_PARAMS, message="Request name ambiguous; use id"))
    if not target:
        raise McpError(ErrorData(code=INVALID_PARAMS, message="Request not found"))
    if name is not None:
        target.name = name
    if method is not None:
        target.method = method.upper()
    if url is not None:
        target.url = url
    if headers is not None:
        target.headers = headers
    if body is not None:
        target.body = body
    if clear_variables:
        target.variables = {}
    if variables:
        target.variables = {**(target.variables or {}), **variables}
    if clear_auth:
        target.auth = None
    elif auth is not None:
        target.auth = auth
    if clear_pre_request:
        target.preRequestScript = None
    elif pre_request_script is not None:
        target.preRequestScript = pre_request_script
    if clear_test:
        target.testScript = None
    elif test_script is not None:
        target.testScript = test_script
    # persist
    col.update(json.loads(col_obj.model_dump_json()))
    await write_user_json(puch_user_id, 'collections', collections)
    return target.model_dump_json(indent=2)

# --- Tool: delete_request ---
DeleteRequestDescription = RichToolDescription(
    description="Delete a stored request",
    use_when="You want to remove a request from a collection",
)

@mcp.tool(description=DeleteRequestDescription.model_dump_json())
async def delete_request(
    puch_user_id: Annotated[str, Field(description="User id performing action")],
    collection_ref: Annotated[str, Field(description="Collection id or name")],
    request_ref: Annotated[str, Field(description="Request id or exact name (if unique)")],
) -> str:
    await require_permission(puch_user_id, A_DELETE)
    await ensure_user_data(puch_user_id)
    collections = await read_user_json(puch_user_id, 'collections')
    col = await _resolve_collection(collections, collection_ref)
    col_obj = Collection(**col)
    def remove_from(list_ref: List[StoredRequest]) -> bool:
        for i, r in enumerate(list_ref):
            if r.id == request_ref or r.name == request_ref:
                list_ref.pop(i)
                return True
        return False
    removed = False
    if remove_from(col_obj.requests):
        removed = True
    stack = col_obj.folders.copy()
    while stack and not removed:
        f = stack.pop()
        if remove_from(f.requests):
            removed = True
            break
        stack.extend(f.folders)
    if not removed:
        raise McpError(ErrorData(code=INVALID_PARAMS, message="Request not found"))
    col.update(json.loads(col_obj.model_dump_json()))
    await write_user_json(puch_user_id, 'collections', collections)
    return json.dumps({"deleted": request_ref}, indent=2)

@mcp.tool(name="list_requests")
async def list_requests_per_user( # type: ignore
    puch_user_id: Annotated[str, Field(description="User id performing action")],
    collection_ref: Annotated[str, Field(description="Collection id or name")],
    folder_ref: Annotated[Optional[str], Field(description="Folder id or name (optional)")]=None,
) -> str:
    await require_permission(puch_user_id, A_READ)
    await ensure_user_data(puch_user_id)
    collections = await read_user_json(puch_user_id, 'collections')
    col = await _resolve_collection(collections, collection_ref)
    col_obj = Collection(**col)
    if folder_ref:
        target_folder = find_folder(col_obj, folder_ref)
        if not target_folder:
            # name search
            all_folders: List[Folder] = []
            stack = col_obj.folders.copy()
            while stack:
                f = stack.pop()
                all_folders.append(f)
                stack.extend(f.folders)
            named = [f for f in all_folders if f.name == folder_ref]
            if len(named) == 1:
                target_folder = named[0]
            elif len(named) > 1:
                raise McpError(ErrorData(code=INVALID_PARAMS, message="Folder name ambiguous; use id"))
            else:
                raise McpError(ErrorData(code=INVALID_PARAMS, message="Folder not found"))
        return json.dumps([r.model_dump() for r in target_folder.requests], indent=2)
    else:
        return json.dumps([r.model_dump() for r in col_obj.requests], indent=2)

# --- REPLACED: environments per-user ---
@mcp.tool(name="create_environment")
async def create_environment_per_user(
    puch_user_id: Annotated[str, Field(description="User id performing action")],
    name: Annotated[str, Field(description="Environment name")],
    variables: Annotated[Dict[str, str], Field(description="Variables map")],
) -> str:
    await require_permission(puch_user_id, A_CREATE)
    await ensure_user_data(puch_user_id)
    envs = await read_user_json(puch_user_id, 'environments')
    env = {"id": gen_id(), "name": name, "variables": variables, "createdAt": datetime.now().isoformat()}
    envs.append(env)
    await write_user_json(puch_user_id, 'environments', envs)
    return json.dumps(env, indent=2)

@mcp.tool(name="update_environment")
async def update_environment_per_user(
    puch_user_id: Annotated[str, Field(description="User id performing action")],
    environment_ref: Annotated[str, Field(description="Environment id or name")],
    variables: Annotated[Dict[str, str], Field(description="Variables to merge")],
) -> str:
    await require_permission(puch_user_id, A_UPDATE)
    await ensure_user_data(puch_user_id)
    envs = await read_user_json(puch_user_id, 'environments')
    env = await _resolve_environment(puch_user_id, environment_ref)
    env['variables'].update(variables)
    await write_user_json(puch_user_id, 'environments', envs)
    return json.dumps(env, indent=2)

@mcp.tool(name="delete_environment")
async def delete_environment_per_user(
    puch_user_id: Annotated[str, Field(description="User id performing action")],
    environment_ref: Annotated[str, Field(description="Environment id or name")],
) -> str:
    await require_permission(puch_user_id, A_DELETE)
    await ensure_user_data(puch_user_id)
    envs = await read_user_json(puch_user_id, 'environments')
    env = await _resolve_environment(puch_user_id, environment_ref)
    target_id = env['id']
    new_envs = [e for e in envs if e.get('id') != target_id]
    await write_user_json(puch_user_id, 'environments', new_envs)
    return json.dumps({"deleted": target_id}, indent=2)

@mcp.tool(name="list_environments")
async def list_environments_per_user(
    puch_user_id: Annotated[str, Field(description="User id performing action")]
) -> str:
    await require_permission(puch_user_id, A_READ)
    await ensure_user_data(puch_user_id)
    envs = await read_user_json(puch_user_id, 'environments')
    return json.dumps(envs, indent=2)

# --- REPLACED: history per-user ---
@mcp.tool(name="history")
async def history_per_user(
    puch_user_id: Annotated[str, Field(description="User id performing action")],
    limit: Annotated[int, Field(description="Max entries", ge=1, le=100)] = 20,
) -> str:
    await require_permission(puch_user_id, A_READ)
    await ensure_user_data(puch_user_id)
    h = await read_user_json(puch_user_id, 'history')
    return json.dumps(h[:limit], indent=2)

# --- REPLACED: export_collection / import_postman_collection per-user ---
@mcp.tool(name="export_collection")
async def export_collection_per_user(
    puch_user_id: Annotated[str, Field(description="User id performing action")],
    collection_ref: Annotated[str, Field(description="Collection id or name")],
) -> str:
    await require_permission(puch_user_id, A_EXPORT)
    await ensure_user_data(puch_user_id)
    collections = await read_user_json(puch_user_id, 'collections')
    col = await _resolve_collection(collections, collection_ref)
    col_obj = Collection(**col)
    def map_request(r: StoredRequest) -> Dict[str, Any]:
        return {
            "name": r.name,
            "request": {
                "method": r.method,
                "header": [{"key": k, "value": v} for k, v in r.headers.items()],
                "url": r.url,
                "body": {"mode": "raw", "raw": json.dumps(r.body) if isinstance(r.body, dict) else str(r.body)} if r.body is not None else None,
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
        "info": {"name": col_obj.name, "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
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

@mcp.tool(name="import_postman_collection")
async def import_postman_collection_per_user(
    puch_user_id: Annotated[str, Field(description="User id performing action")],
    json_data: Annotated[str, Field(description="Postman collection JSON")],
    overwrite_name: Annotated[Optional[str], Field(description="Optional new collection name")]=None,
) -> str:
    await require_permission(puch_user_id, A_IMPORT)
    await ensure_user_data(puch_user_id)
    try:
        parsed = json.loads(json_data)
    except json.JSONDecodeError:
        raise McpError(ErrorData(code=INVALID_PARAMS, message="Invalid JSON"))
    if not isinstance(parsed.get('item'), list):
        raise McpError(ErrorData(code=INVALID_PARAMS, message="Unsupported collection format"))
    collections = await read_user_json(puch_user_id, 'collections')
    def to_request(item: Dict[str, Any]) -> Dict[str, Any]:
        body_raw = item.get('request', {}).get('body', {})
        body_val = body_raw.get('raw') if isinstance(body_raw, dict) else None
        return {
            'id': gen_id(),
            'name': item.get('name') or 'request',
            'method': (item.get('request', {}).get('method') or 'GET').upper(),
            'url': item.get('request', {}).get('url', {}).get('raw') or item.get('request', {}).get('url') or '',
            'headers': {h['key']: h['value'] for h in item.get('request', {}).get('header', []) if isinstance(h, dict) and 'key' in h},
            'body': body_val,
            'createdAt': datetime.now().isoformat(),
            'variables': item.get('_mcp', {}).get('variables'),
            'auth': item.get('_mcp', {}).get('auth'),
            'preRequestScript': item.get('_mcp', {}).get('preRequestScript'),
            'testScript': item.get('_mcp', {}).get('testScript'),
        }
    def to_folder(item: Dict[str, Any]) -> Dict[str, Any]:
        return {
            'id': gen_id(),
            'name': item.get('name') or 'folder',
            'requests': [to_request(i) for i in item.get('item', []) if i.get('request')],
            'folders': [to_folder(i) for i in item.get('item', []) if not i.get('request') and i.get('item')],
            'createdAt': datetime.now().isoformat(),
        }
    collection = {
        'id': gen_id(),
        'name': overwrite_name or parsed.get('info', {}).get('name') or 'Imported',
        'requests': [to_request(i) for i in parsed.get('item', []) if i.get('request')],
        'folders': [to_folder(i) for i in parsed.get('item', []) if not i.get('request') and i.get('item')],
        'createdAt': datetime.now().isoformat(),
        'variables': {v['key']: v['value'] for v in parsed.get('variable', []) if isinstance(v, dict) and 'key' in v},
        'auth': parsed.get('_mcp', {}).get('auth'),
        'preRequestScript': parsed.get('_mcp', {}).get('preRequestScript'),
        'testScript': parsed.get('_mcp', {}).get('testScript'),
    }
    collections.append(collection)
    await write_user_json(puch_user_id, 'collections', collections)
    return json.dumps(collection, indent=2)

# Helper: resolve environment by id or (unique) name within user namespace (with legacy migration)
async def _resolve_environment(user_id: str, env_ref: str) -> Dict[str, Any]:
    envs = await read_user_json(user_id, 'environments')
    env = next((e for e in envs if e.get('id') == env_ref), None)
    if env:
        return env
    matches = [e for e in envs if e.get('name') == env_ref]
    if not matches:
        # attempt legacy migration if empty
        legacy_envs = await read_json(ENVIRONMENTS_KEY)
        migrated = False
        if legacy_envs:
            existing_ids = {e.get('id') for e in envs}
            for le in legacy_envs:
                if le.get('id') not in existing_ids:
                    envs.append(le)
                    migrated = True
            if migrated:
                await write_user_json(user_id, 'environments', envs)
            matches = [e for e in envs if e.get('name') == env_ref]
            if matches:
                if len(matches) == 1:
                    return matches[0]
                raise McpError(ErrorData(code=INVALID_PARAMS, message="Multiple environments share this name; use id"))
        raise McpError(ErrorData(code=INVALID_PARAMS, message="Environment not found (by id or name)"))
    if len(matches) > 1:
        raise McpError(ErrorData(code=INVALID_PARAMS, message="Multiple environments share this name; use id"))
    return matches[0]

# --- REPLACED: set_globals / get_globals to per-user ---
@mcp.tool(name="set_globals")
async def set_globals_per_user(
    puch_user_id: Annotated[str, Field(description="User id performing action")],
    variables: Annotated[Dict[str, str], Field(description="Variables to set (merged)")],
) -> str:
    await require_permission(puch_user_id, A_UPDATE)
    await ensure_user_data(puch_user_id)
    globals_obj = await read_user_json(puch_user_id, 'globals')
    globals_obj.setdefault('variables', {}).update(variables)
    await write_user_json(puch_user_id, 'globals', globals_obj)
    return json.dumps(globals_obj, indent=2)

@mcp.tool(name="get_globals")
async def get_globals_per_user(
    puch_user_id: Annotated[str, Field(description="User id performing action")]
) -> str:
    await require_permission(puch_user_id, A_READ)
    await ensure_user_data(puch_user_id)
    globals_obj = await read_user_json(puch_user_id, 'globals')
    return json.dumps(globals_obj, indent=2)

# --- REPLACED: update_collection / delete_collection with per-user scope ---
@mcp.tool(name="update_collection")
async def update_collection_per_user(
    puch_user_id: Annotated[str, Field(description="User id performing action")],
    collection_ref: Annotated[str, Field(description="Collection id or exact name")],
    name: Annotated[Optional[str], Field(description="New name for collection")] = None,
    variables: Annotated[Optional[Dict[str, str]], Field(description="Variables to merge")] = None,
    auth: Annotated[Optional[AuthConfig], Field(description="New auth config (null to clear)")] = None,
    clear_auth: Annotated[bool, Field(description="Set true to remove auth")] = False,
    pre_request_script: Annotated[Optional[str], Field(description="Pre-request script (null to clear)")] = None,
    clear_pre_request: Annotated[bool, Field(description="Set true to remove pre-request script")] = False,
    test_script: Annotated[Optional[str], Field(description="Test script (null to clear)")] = None,
    clear_test: Annotated[bool, Field(description="Set true to remove test script")] = False,
) -> str:
    await require_permission(puch_user_id, A_UPDATE)
    await ensure_user_data(puch_user_id)
    collections = await read_user_json(puch_user_id, 'collections')
    col = await _resolve_collection(collections, collection_ref)
    if name:
        col['name'] = name
    if variables:
        col['variables'] = {**(col.get('variables') or {}), **variables}
    if clear_auth:
        col.pop('auth', None)
    elif auth is not None:
        col['auth'] = auth.model_dump()
    if clear_pre_request:
        col.pop('preRequestScript', None)
    elif pre_request_script is not None:
        col['preRequestScript'] = pre_request_script
    if clear_test:
        col.pop('testScript', None)
    elif test_script is not None:
        col['testScript'] = test_script
    await write_user_json(puch_user_id, 'collections', collections)
    return json.dumps(col, indent=2)

@mcp.tool(name="delete_collection")
async def delete_collection_per_user(
    puch_user_id: Annotated[str, Field(description="User id performing action")],
    collection_ref: Annotated[str, Field(description="Collection id or exact name to delete")],
) -> str:
    await require_permission(puch_user_id, A_DELETE)
    await ensure_user_data(puch_user_id)
    collections = await read_user_json(puch_user_id, 'collections')
    # resolve to id first
    col = await _resolve_collection(collections, collection_ref)
    target_id = col['id']
    new_cols = [c for c in collections if c.get('id') != target_id]
    if len(new_cols) == len(collections):
        raise McpError(ErrorData(code=INVALID_PARAMS, message="Collection not found"))
    await write_user_json(puch_user_id, 'collections', new_cols)
    return json.dumps({"deleted": target_id}, indent=2)

# --- New: get_collection_name per-user ---
@mcp.tool(name="get_collection_name")
async def get_collection_name_per_user(
    puch_user_id: Annotated[str, Field(description="User id performing action")],
    collection_id: Annotated[str, Field(description="Collection id")],
) -> str:
    await require_permission(puch_user_id, A_READ)
    collections = await read_user_json(puch_user_id, 'collections')
    col = next((c for c in collections if c.get('id') == collection_id), None)
    if not col:
        raise McpError(ErrorData(code=INVALID_PARAMS, message="Collection not found"))
    return json.dumps({"id": col['id'], "name": col['name']}, indent=2)

# --- REPLACED: get_collection_id (per-user, name->ids) ---
@mcp.tool(name="get_collection_id")
async def get_collection_id_per_user(
    puch_user_id: Annotated[str, Field(description="User id performing action")],
    name: Annotated[str, Field(description="Exact collection name")],
) -> str:
    await require_permission(puch_user_id, A_READ)
    collections = await read_user_json(puch_user_id, 'collections')
    matches = [c for c in collections if c.get("name") == name]
    if not matches:
        raise McpError(ErrorData(code=INVALID_PARAMS, message="Collection name not found"))
    if len(matches) == 1:
        return json.dumps({"id": matches[0]["id"], "name": matches[0]["name"]}, indent=2)
    return json.dumps([{"id": c["id"], "name": c["name"]} for c in matches], indent=2)

# --- REPLACED: request CRUD per-user ---
@mcp.tool(name="add_request")
async def add_request_per_user(
    puch_user_id: Annotated[str, Field(description="User id performing action")],
    collection_ref: Annotated[str, Field(description="Collection id or name")],
    name: Annotated[str, Field(description="Request name")],
    method: Annotated[str, Field(description="HTTP method")],
    url: Annotated[str, Field(description="Request URL")],
    headers: Annotated[Optional[Dict[str, str]], Field(description="Headers map")] = None,
    body: Annotated[Optional[Any], Field(description="Body (json or string)")] = None,
    folder_ref: Annotated[Optional[str], Field(description="Folder id or name (optional)")] = None,
    variables: Annotated[Optional[Dict[str, str]], Field(description="Request variables")] = None,
    auth: Annotated[Optional[AuthConfig], Field(description="Request auth override")] = None,
    pre_request_script: Annotated[Optional[str], Field(description="Pre-request script")]=None,
    test_script: Annotated[Optional[str], Field(description="Test script")]=None,
) -> str:
    await require_permission(puch_user_id, A_CREATE)
    await ensure_user_data(puch_user_id)
    collections = await read_user_json(puch_user_id, 'collections')
    col = await _resolve_collection(collections, collection_ref)
    col_obj = Collection(**col)
    target_folder = None
    if folder_ref:
        # allow id or unique name
            # search by id first
        target_folder = find_folder(col_obj, folder_ref)
        if not target_folder:
            # name search
            all_folders = []
            stack = col_obj.folders.copy()
            while stack:
                f = stack.pop()
                all_folders.append(f)
                stack.extend(f.folders)
            named = [f for f in all_folders if f.name == folder_ref]
            if len(named) == 1:
                target_folder = named[0]
            elif len(named) > 1:
                raise McpError(ErrorData(code=INVALID_PARAMS, message="Folder name ambiguous; use id"))
            else:
                raise McpError(ErrorData(code=INVALID_PARAMS, message="Folder not found"))
    req = StoredRequest(
        id=gen_id(),
        name=name,
        method=method.upper(),
        url=url,
        headers=headers or {},
        body=body,
        createdAt=datetime.now().isoformat(),
        variables=variables,
        auth=auth,
        preRequestScript=pre_request_script,
        testScript=test_script,
    )
    if target_folder:
        target_folder.requests.append(req)
        col.update(json.loads(col_obj.model_dump_json()))
    else:
        col.setdefault('requests', []).append(json.loads(req.model_dump_json()))
    await write_user_json(puch_user_id, 'collections', collections)
    return req.model_dump_json(indent=2)

@mcp.tool(name="update_request")
async def update_request_per_user(
    puch_user_id: Annotated[str, Field(description="User id performing action")],
    collection_ref: Annotated[str, Field(description="Collection id or name")],
    request_ref: Annotated[str, Field(description="Request id or exact name (if unique)")],
    name: Annotated[Optional[str], Field(description="New name")]=None,
    method: Annotated[Optional[str], Field(description="New HTTP method")]=None,
    url: Annotated[Optional[str], Field(description="New URL")]=None,
    headers: Annotated[Optional[Dict[str, str]], Field(description="New headers")]=None,
    body: Annotated[Optional[Any], Field(description="New body")]=None,
    variables: Annotated[Optional[Dict[str, str]], Field(description="Variables to merge")]=None,
    clear_variables: Annotated[bool, Field(description="If true, reset variables before merge")]=False,
    auth: Annotated[Optional[AuthConfig], Field(description="Auth override")]=None,
    clear_auth: Annotated[bool, Field(description="Remove auth if true")]=False,
    pre_request_script: Annotated[Optional[str], Field(description="Set pre-request script")]=None,
    clear_pre_request: Annotated[bool, Field(description="Remove pre-request script if true")]=False,
    test_script: Annotated[Optional[str], Field(description="Set test script")]=None,
    clear_test: Annotated[bool, Field(description="Remove test script if true")]=False,
) -> str:
    await require_permission(puch_user_id, A_UPDATE)
    await ensure_user_data(puch_user_id)
    collections = await read_user_json(puch_user_id, 'collections')
    col = await _resolve_collection(collections, collection_ref)
    col_obj = Collection(**col)
    # gather all requests
    all_requests: List[StoredRequest] = []
    all_requests.extend(col_obj.requests)
    stack = col_obj.folders.copy()
    while stack:
        f = stack.pop()
        all_requests.extend(f.requests)
        stack.extend(f.folders)
    target = next((r for r in all_requests if r.id == request_ref), None)
    if not target:
        named = [r for r in all_requests if r.name == request_ref]
        if len(named) == 1:
            target = named[0]
        elif len(named) > 1:
            raise McpError(ErrorData(code=INVALID_PARAMS, message="Request name ambiguous; use id"))
    if not target:
        raise McpError(ErrorData(code=INVALID_PARAMS, message="Request not found"))
    if name is not None:
        target.name = name
    if method is not None:
        target.method = method.upper()
    if url is not None:
        target.url = url
    if headers is not None:
        target.headers = headers
    if body is not None:
        target.body = body
    if clear_variables:
        target.variables = {}
    if variables:
        target.variables = {**(target.variables or {}), **variables}
    if clear_auth:
        target.auth = None
    elif auth is not None:
        target.auth = auth
    if clear_pre_request:
        target.preRequestScript = None
    elif pre_request_script is not None:
        target.preRequestScript = pre_request_script
    if clear_test:
        target.testScript = None
    elif test_script is not None:
        target.testScript = test_script
    # persist
    col.update(json.loads(col_obj.model_dump_json()))
    await write_user_json(puch_user_id, 'collections', collections)
    return target.model_dump_json(indent=2)

@mcp.tool(name="delete_request")
async def delete_request_per_user(
    puch_user_id: Annotated[str, Field(description="User id performing action")],
    collection_ref: Annotated[str, Field(description="Collection id or name")],
    request_ref: Annotated[str, Field(description="Request id or exact name (if unique)")],
) -> str:
    await require_permission(puch_user_id, A_DELETE)
    await ensure_user_data(puch_user_id)
    collections = await read_user_json(puch_user_id, 'collections')
    col = await _resolve_collection(collections, collection_ref)
    col_obj = Collection(**col)
    def remove_from(list_ref: List[StoredRequest]) -> bool:
        for i, r in enumerate(list_ref):
            if r.id == request_ref or r.name == request_ref:
                list_ref.pop(i)
                return True
        return False
    removed = False
    if remove_from(col_obj.requests):
        removed = True
    stack = col_obj.folders.copy()
    while stack and not removed:
        f = stack.pop()
        if remove_from(f.requests):
            removed = True
            break
        stack.extend(f.folders)
    if not removed:
        raise McpError(ErrorData(code=INVALID_PARAMS, message="Request not found"))
    col.update(json.loads(col_obj.model_dump_json()))
    await write_user_json(puch_user_id, 'collections', collections)
    return json.dumps({"deleted": request_ref}, indent=2)

@mcp.tool(name="list_requests")
async def list_requests_per_user(
    puch_user_id: Annotated[str, Field(description="User id performing action")],
    collection_ref: Annotated[str, Field(description="Collection id or name")],
    folder_ref: Annotated[Optional[str], Field(description="Folder id or name (optional)")]=None,
) -> str:
    await require_permission(puch_user_id, A_READ)
    await ensure_user_data(puch_user_id)
    collections = await read_user_json(puch_user_id, 'collections')
    col = await _resolve_collection(collections, collection_ref)
    col_obj = Collection(**col)
    if folder_ref:
        target_folder = find_folder(col_obj, folder_ref)
        if not target_folder:
            # name search
            all_folders: List[Folder] = []
            stack = col_obj.folders.copy()
            while stack:
                f = stack.pop()
                all_folders.append(f)
                stack.extend(f.folders)
            named = [f for f in all_folders if f.name == folder_ref]
            if len(named) == 1:
                target_folder = named[0]
            elif len(named) > 1:
                raise McpError(ErrorData(code=INVALID_PARAMS, message="Folder name ambiguous; use id"))
            else:
                raise McpError(ErrorData(code=INVALID_PARAMS, message="Folder not found"))
        return json.dumps([r.model_dump() for r in target_folder.requests], indent=2)
    else:
        return json.dumps([r.model_dump() for r in col_obj.requests], indent=2)

# --- REPLACED: environments per-user ---
@mcp.tool(name="create_environment")
async def create_environment_per_user(
    puch_user_id: Annotated[str, Field(description="User id performing action")],
    name: Annotated[str, Field(description="Environment name")],
    variables: Annotated[Dict[str, str], Field(description="Variables map")],
) -> str:
    await require_permission(puch_user_id, A_CREATE)
    await ensure_user_data(puch_user_id)
    envs = await read_user_json(puch_user_id, 'environments')
    env = {"id": gen_id(), "name": name, "variables": variables, "createdAt": datetime.now().isoformat()}
    envs.append(env)
    await write_user_json(puch_user_id, 'environments', envs)
    return json.dumps(env, indent=2)

@mcp.tool(name="update_environment")
async def update_environment_per_user(
    puch_user_id: Annotated[str, Field(description="User id performing action")],
    environment_ref: Annotated[str, Field(description="Environment id or name")],
    variables: Annotated[Dict[str, str], Field(description="Variables to merge")],
) -> str:
    await require_permission(puch_user_id, A_UPDATE)
    await ensure_user_data(puch_user_id)
    envs = await read_user_json(puch_user_id, 'environments')
    env = await _resolve_environment(puch_user_id, environment_ref)
    env['variables'].update(variables)
    await write_user_json(puch_user_id, 'environments', envs)
    return json.dumps(env, indent=2)

@mcp.tool(name="delete_environment")
async def delete_environment_per_user(
    puch_user_id: Annotated[str, Field(description="User id performing action")],
    environment_ref: Annotated[str, Field(description="Environment id or name")],
) -> str:
    await require_permission(puch_user_id, A_DELETE)
    await ensure_user_data(puch_user_id)
    envs = await read_user_json(puch_user_id, 'environments')
    env = await _resolve_environment(puch_user_id, environment_ref)
    target_id = env['id']
    new_envs = [e for e in envs if e.get('id') != target_id]
    await write_user_json(puch_user_id, 'environments', new_envs)
    return json.dumps({"deleted": target_id}, indent=2)

@mcp.tool(name="list_environments")
async def list_environments_per_user(
    puch_user_id: Annotated[str, Field(description="User id performing action")]
) -> str:
    await require_permission(puch_user_id, A_READ)
    await ensure_user_data(puch_user_id)
    envs = await read_user_json(puch_user_id, 'environments')
    return json.dumps(envs, indent=2)

# --- REPLACED: history per-user ---
@mcp.tool(name="history")
async def history_per_user(
    puch_user_id: Annotated[str, Field(description="User id performing action")],
    limit: Annotated[int, Field(description="Max entries", ge=1, le=100)] = 20,
) -> str:
    await require_permission(puch_user_id, A_READ)
    await ensure_user_data(puch_user_id)
    h = await read_user_json(puch_user_id, 'history')
    return json.dumps(h[:limit], indent=2)

# --- REPLACED: export_collection / import_postman_collection per-user ---
@mcp.tool(name="export_collection")
async def export_collection_per_user(
    puch_user_id: Annotated[str, Field(description="User id performing action")],
    collection_ref: Annotated[str, Field(description="Collection id or name")],
) -> str:
    await require_permission(puch_user_id, A_EXPORT)
    await ensure_user_data(puch_user_id)
    collections = await read_user_json(puch_user_id, 'collections')
    col = await _resolve_collection(collections, collection_ref)
    col_obj = Collection(**col)
    def map_request(r: StoredRequest) -> Dict[str, Any]:
        return {
            "name": r.name,
            "request": {
                "method": r.method,
                "header": [{"key": k, "value": v} for k, v in r.headers.items()],
                "url": r.url,
                "body": {"mode": "raw", "raw": json.dumps(r.body) if isinstance(r.body, dict) else str(r.body)} if r.body is not None else None,
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
        "info": {"name": col_obj.name, "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
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

@mcp.tool(name="import_postman_collection")
async def import_postman_collection_per_user(
    puch_user_id: Annotated[str, Field(description="User id performing action")],
    json_data: Annotated[str, Field(description="Postman collection JSON")],
    overwrite_name: Annotated[Optional[str], Field(description="Optional new collection name")]=None,
) -> str:
    await require_permission(puch_user_id, A_IMPORT)
    await ensure_user_data(puch_user_id)
    try:
        parsed = json.loads(json_data)
    except json.JSONDecodeError:
        raise McpError(ErrorData(code=INVALID_PARAMS, message="Invalid JSON"))
    if not isinstance(parsed.get('item'), list):
        raise McpError(ErrorData(code=INVALID_PARAMS, message="Unsupported collection format"))
    collections = await read_user_json(puch_user_id, 'collections')
    def to_request(item: Dict[str, Any]) -> Dict[str, Any]:
        body_raw = item.get('request', {}).get('body', {})
        body_val = body_raw.get('raw') if isinstance(body_raw, dict) else None
        return {
            'id': gen_id(),
            'name': item.get('name') or 'request',
            'method': (item.get('request', {}).get('method') or 'GET').upper(),
            'url': item.get('request', {}).get('url', {}).get('raw') or item.get('request', {}).get('url') or '',
            'headers': {h['key']: h['value'] for h in item.get('request', {}).get('header', []) if isinstance(h, dict) and 'key' in h},
            'body': body_val,
            'createdAt': datetime.now().isoformat(),
            'variables': item.get('_mcp', {}).get('variables'),
            'auth': item.get('_mcp', {}).get('auth'),
            'preRequestScript': item.get('_mcp', {}).get('preRequestScript'),
            'testScript': item.get('_mcp', {}).get('testScript'),
        }
    def to_folder(item: Dict[str, Any]) -> Dict[str, Any]:
        return {
            'id': gen_id(),
            'name': item.get('name') or 'folder',
            'requests': [to_request(i) for i in item.get('item', []) if i.get('request')],
            'folders': [to_folder(i) for i in item.get('item', []) if not i.get('request') and i.get('item')],
            'createdAt': datetime.now().isoformat(),
        }
    collection = {
        'id': gen_id(),
        'name': overwrite_name or parsed.get('info', {}).get('name') or 'Imported',
        'requests': [to_request(i) for i in parsed.get('item', []) if i.get('request')],
        'folders': [to_folder(i) for i in parsed.get('item', []) if not i.get('request') and i.get('item')],
        'createdAt': datetime.now().isoformat(),
        'variables': {v['key']: v['value'] for v in parsed.get('variable', []) if isinstance(v, dict) and 'key' in v},
        'auth': parsed.get('_mcp', {}).get('auth'),
        'preRequestScript': parsed.get('_mcp', {}).get('preRequestScript'),
        'testScript': parsed.get('_mcp', {}).get('testScript'),
    }
    collections.append(collection)
    await write_user_json(puch_user_id, 'collections', collections)
    return json.dumps(collection, indent=2)

# --- Diagnostic tool: list_folders ---
ListFoldersDescription = RichToolDescription(
    description="List folder tree for a collection (per-user namespace)",
    use_when="You need to inspect existing folders or obtain their IDs",
)

@mcp.tool(description=ListFoldersDescription.model_dump_json())
async def list_folders(
    puch_user_id: Annotated[str, Field(description="User id performing action")],
    collection_ref: Annotated[Optional[str], Field(description="Collection id or exact name; if omitted, first collection is used")] = None,
) -> str:
    await require_permission(puch_user_id, A_READ)
    await ensure_user_data(puch_user_id)
    user_cols = await read_user_json(puch_user_id, 'collections')
    # Auto-pick first collection if none specified
    if collection_ref is None:
        if not user_cols:
            # Attempt legacy migration (one-time) to help user
           
            legacy = await read_json(COLLECTIONS_KEY)
            if legacy:
                # migrate all legacy collections to this user namespace
                for c in legacy:
                    if c not in user_cols:
                        user_cols.append(c)
                await write_user_json(puch_user_id, 'collections', user_cols)
            if not user_cols:
                return json.dumps({"message": "No collections found for user", "folders": []}, indent=2)
        # pick first
        collection_ref = user_cols[0].get('id')
    try:
        col = await _resolve_collection(user_cols, collection_ref)
    except McpError:
        return json.dumps({"error": "Collection not found in user namespace", "collection_ref": collection_ref}, indent=2)
    def build(folder_list):
        out = []
        for f in folder_list:
            out.append({
                'id': f['id'],
                'name': f['name'],
                'folders': build(f.get('folders', [])),
                'requestCount': len(f.get('requests', []))
            })
        return out
    tree = build(col.get('folders', []))
    return json.dumps({'collection': {'id': col['id'], 'name': col['name']}, 'folders': tree}, indent=2)

# --- Tool: move_folder ---
MoveFolderDescription = RichToolDescription(
    description="Move a folder to another collection or different parent folder",
    use_when="You need to reorganize folder structure across collections",
    side_effects="Changes folder hierarchy and collection contents",
)

@mcp.tool(description=MoveFolderDescription.model_dump_json())
async def move_folder(
    puch_user_id: Annotated[str, Field(description="User id performing action")],
    folder_id: Annotated[str, Field(description="ID OR exact name of the folder being moved")],
    source_collection_id: Annotated[str, Field(description="ID or name of the source collection containing the folder")],
    target_collection_id: Annotated[str, Field(description="ID or name of the destination collection")],
    target_parent_folder_id: Annotated[Optional[str], Field(description="Optional ID or name of destination parent folder (omit for root)")] = None,
) -> str:
    await require_permission(puch_user_id, A_UPDATE)
    await ensure_user_data(puch_user_id)
    user_collections = await read_user_json(puch_user_id, 'collections')

    # Resolve source / target collections (initially only in user namespace)
    try:
        source_col = await _resolve_collection(user_collections, source_collection_id)
    except McpError:
        source_col = None  # may exist only in legacy global storage
    try:
        target_col = await _resolve_collection(user_collections, target_collection_id)
    except McpError:
        target_col = None

    legacy_migration_note = None

    # If either collection not found in user namespace, attempt legacy global lookup & migrate
    if source_col is None or target_col is None:
        legacy_cols = await read_json(COLLECTIONS_KEY)
        if source_col is None:
            try:
                source_col = await _resolve_collection(legacy_cols, source_collection_id)
                # migrate source to user namespace if not already
                user_collections.append(source_col)
                legacy_migration_note = (legacy_migration_note or []) + [f"Migrated source collection '{source_col.get('name')}' to user namespace"]
            except McpError:
                pass
        if target_col is None:
            try:
                target_col = await _resolve_collection(user_collections, target_collection_id)  # maybe already migrated via source
            except McpError:
                try:
                    target_col = await _resolve_collection(legacy_cols, target_collection_id)
                    user_collections.append(target_col)
                    legacy_migration_note = (legacy_migration_note or []) + [f"Migrated target collection '{target_col.get('name')}' to user namespace"]
                except McpError:
                    pass
        # Persist user namespace if migrations occurred
        if legacy_migration_note:
            await write_user_json(puch_user_id, 'collections', user_collections)

    if source_col is None:
        raise McpError(ErrorData(code=INVALID_PARAMS, message="Source collection not found (user or legacy)"))
    if target_col is None:
        raise McpError(ErrorData(code=INVALID_PARAMS, message="Target collection not found (user or legacy)"))

    # Helper: locate folder (by id first, then unique name) and return (parent_list, idx, folder)
    def locate_folder(col_dict: Dict[str, Any], ref: str) -> Optional[tuple]:
        stack: List[tuple[List[Dict[str, Any]], int]] = []
        for i in range(len(col_dict.get('folders', []))):
            stack.append((col_dict.setdefault('folders', []), i))
        matches_by_name: List[tuple[List[Dict[str, Any]], int, Dict[str, Any]]] = []
        while stack:
            parent_list, idx = stack.pop()
            if idx >= len(parent_list):
                continue
            f = parent_list[idx]
            if f.get('id') == ref:
                return (parent_list, idx, f)
            if f.get('name') == ref:
                matches_by_name.append((parent_list, idx, f))
            for ci in range(len(f.get('folders', []) or [])):
                stack.append((f.setdefault('folders', []), ci))
        if len(matches_by_name) == 1:
            return matches_by_name[0]
        if len(matches_by_name) > 1:
            raise McpError(ErrorData(code=INVALID_PARAMS, message=f"Folder name '{ref}' is ambiguous; specify folder id"))
        return None

    # Helper: locate parent destination folder by id OR name (unique)
    def locate_folder_obj_only(col_dict: Dict[str, Any], ref: str) -> Optional[Dict[str, Any]]:
        stack = list(col_dict.get('folders', []))
        candidates: List[Dict[str, Any]] = []
        while stack:
            f = stack.pop()
            if f.get('id') == ref:
                return f
            if f.get('name') == ref:
                candidates.append(f)
            stack.extend(f.get('folders', []) or [])
        if len(candidates) == 1:
            return candidates[0]
        if len(candidates) > 1:
            raise McpError(ErrorData(code=INVALID_PARAMS, message=f"Destination parent folder name '{ref}' is ambiguous; use id"))
        return None

    # Locate folder in declared source; if not present try other collections (user namespace only)
    loc = locate_folder(source_col, folder_id)
    if not loc:
        # search across user namespace
        found = []
        for c in user_collections:
            test = locate_folder(c, folder_id)
            if test:
                found.append((c, test))
        if len(found) == 1:
            source_col, loc = found[0]
        elif len(found) == 0:
            raise McpError(ErrorData(code=INVALID_PARAMS, message=f"Folder '{folder_id}' not found in any collection (user namespace). Use list_folders to inspect."))
        else:
            raise McpError(ErrorData(code=INVALID_PARAMS, message=f"Folder reference '{folder_id}' matches multiple folders; use exact id"))

    parent_list, idx, folder_obj = loc
    moved_folder = parent_list.pop(idx)

    # Prevent self/descendant move
    if source_col is target_col and target_parent_folder_id:
        desc_ids = []
        stack_ids = [moved_folder]
        while stack_ids:
            f = stack_ids.pop()
            desc_ids.append(f.get('id'))
            stack_ids.extend(f.get('folders', []) or [])
        if target_parent_folder_id in desc_ids or any(f.get('name') == target_parent_folder_id for f in moved_folder.get('folders', [])):
            raise McpError(ErrorData(code=INVALID_PARAMS, message="Cannot move folder into itself or its descendant"))

    # Attach to destination
    if target_parent_folder_id:
        col_obj = Collection(**target_col)
        dest_parent = find_folder(col_obj, target_parent_folder_id) or locate_folder_obj_only(target_col, target_parent_folder_id)
        if not dest_parent:
            raise McpError(ErrorData(code=INVALID_PARAMS, message="Destination parent folder not found"))
        dest_parent.folders.append(Folder(**moved_folder))
        target_col.update(json.loads(col_obj.model_dump_json()))
    else:
        target_col.setdefault('folders', []).append(moved_folder)

    # Persist updated collections
    await write_user_json(puch_user_id, 'collections', user_collections)

    result = {
        'moved_folder_id': moved_folder.get('id'),
        'moved_folder_name': moved_folder.get('name'),
        'from_collection_id': source_col['id'],
        'to_collection_id': target_col['id'],
        'new_parent_folder_ref': target_parent_folder_id,
        'legacy_migration': legacy_migration_note,
    }
    return json.dumps(result, indent=2)

# --- Run MCP Server ---
async def main():
    print("🚀 Starting MCP server on http://0.0.0.0:8086")
    await mcp.run_async("streamable-http", host="0.0.0.0", port=8086)

if __name__ == "__main__":
    asyncio.run(main())