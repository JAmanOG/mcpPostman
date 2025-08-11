import os, json, uuid, time, asyncio, base64
import redis, httpx
from typing import Annotated, Optional, Union, List, Dict, Any
from dotenv import load_dotenv
from fastmcp import FastMCP
from fastmcp.server.auth.providers.bearer import BearerAuthProvider, RSAKeyPair
from mcp import ErrorData, McpError
from mcp.server.auth.provider import AccessToken
from mcp.types import TextContent, ImageContent, INVALID_PARAMS, INTERNAL_ERROR
from pydantic import BaseModel, Field, AnyUrl, validator
from datetime import datetime,timezone
from textwrap import dedent  

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
    headers: Dict[str, str] = Field(default_factory=dict)
    body: Optional[Any] = None
    createdAt: str
    variables: Optional[Dict[str, str]] = None
    auth: Optional[AuthConfig] = None
    preRequestScript: Optional[str] = None
    testScript: Optional[str] = None

class Folder(BaseModel):
    id: str
    name: str
    requests: List[StoredRequest] = Field(default_factory=list)
    folders: List['Folder'] = Field(default_factory=list)
    createdAt: str
    variables: Optional[Dict[str, str]] = None

class Collection(BaseModel):
    id: str
    name: str
    requests: List[StoredRequest] = Field(default_factory=list)
    folders: List[Folder] = Field(default_factory=list)
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
    return json.loads(raw)# type: ignore

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
    return json.loads(raw)# type: ignore

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

@mcp.tool
async def about() -> str:
    """
    Return a human-readable description of this MCP server for UI / client display.
    """
    description = dedent("""
    MCP ReqForge Server is a Postman-like API automation and testing platform
    exposed via the Model Context Protocol. It provides:
      • Per-user RBAC, isolated collections, environments, globals, and history (Redis-backed)
      • Hierarchical collections, folders, and requests with variable scoping
      • Pre-request & test scripts (JavaScript) and auth inheritance (basic/bearer)
      • Request execution with retries, variable resolution chain (local > request > collection > environment > global)
      • Import / export (Postman subset) and rich history logging (tests + console output)
      • User metadata & role management tools for multi-tenant agent workflows
    Optimized for Puch.ai agent integration and scalable automation use cases.
    """).strip()

    meta = {
        "name": "MCP ReqForge Server",
        "version": "1.0",
        "description": description,
        "homepage": "https://mcppostman-1.onrender.com",
        "try_link": "https://puch.ai/mcp/WoFsL1UMUc",
        "features": [
            "RBAC",
            "Redis storage",
            "Collections & folders",
            "Variable resolution",
            "Pre-request & test scripts",
            "History & test reporting",
            "Postman import/export",
            "User metadata tools"
        ]
    }
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

SendRequestDescription = RichToolDescription(
    description="Send an HTTP request (direct or stored)",
    use_when="You want to execute an API request",
    side_effects="Makes actual HTTP requests to external services",
)

# --- Tool: send_request ---
@mcp.tool(description=SendRequestDescription.model_dump_json())
async def send_request(
    puch_user_id: Annotated[str, Field(description="User id performing action")],
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
    max_attempts: Annotated[int, Field(description="Total attempts including first (>=1, default 2)")] = 2,
    retry_backoff_ms: Annotated[int, Field(description="Backoff between attempts in ms")] = 300,
) -> str:
    await require_permission(puch_user_id, A_EXECUTE)
    if not ((stored_request_id and collection_id) or (method and url)):
        raise McpError(ErrorData(code=INVALID_PARAMS, message="Either provide stored_request_id + collection_id OR method + url"))
    if max_attempts < 1:
        max_attempts = 1
    await ensure_user_data(puch_user_id)
    globals = await read_user_json(puch_user_id, 'globals')
    col_obj = None
    if stored_request_id:
        collections = await read_user_json(puch_user_id, 'collections')
        col = next((c for c in collections if c['id'] == collection_id), None)
        if not col:
            raise McpError(ErrorData(code=INVALID_PARAMS, message="Collection not found"))
        col_obj = Collection(**col)
        search_reqs = col_obj.requests.copy()
        stack = col_obj.folders.copy()
        while stack:
            f = stack.pop()
            search_reqs.extend(f.requests)
            stack.extend(f.folders)
        stored = next((r for r in search_reqs if r.id == stored_request_id), None)
        if not stored:
            raise McpError(ErrorData(code=INVALID_PARAMS, message="Stored request not found"))
        request = stored.model_dump()
    else:
        request = {"id": gen_id(), "name": "ad-hoc", "method": method.upper(), "url": url, "headers": headers or {}, "body": body, "createdAt": datetime.now().isoformat(), "variables": {}} # type: ignore
    env_vars = {}
    if environment_id:
        envs = await read_user_json(puch_user_id, 'environments')
        env = next((e for e in envs if e['id'] == environment_id), None)
        if not env:
            raise McpError(ErrorData(code=INVALID_PARAMS, message="Environment not found"))
        env_vars = env['variables']
    local_vars = local_variables or {}
    request_vars = request.get('variables') or {}
    collection_vars = col_obj.variables if col_obj else {}
    global_vars = globals.get('variables') or {}
    chain = [local_vars, request_vars, collection_vars, env_vars, global_vars]
    tests = []
    console_logs = []
    req_resolved = {**request, 'url': resolve_variables(request['url'], chain), 'headers': deep_apply(request['headers'], chain), 'body': deep_apply(request.get('body'), chain)}
    effective_auth = auth or (AuthConfig(**request['auth']) if request.get('auth') else None)
    headers_with_auth = apply_auth(req_resolved['headers'], effective_auth)

    last_error: Optional[str] = None
    response_obj: Dict[str, Any] = {"status": 0, "statusText": "UNSENT", "headers": {}, "body": None}
    attempt = 0
    started_total = time.time()
    while attempt < max_attempts:
        attempt += 1
        try:
            async with httpx.AsyncClient() as client:
                req_kwargs = {"method": req_resolved['method'], "headers": headers_with_auth, "timeout": timeout_ms/1000}
                if req_resolved.get('body') is not None and req_resolved['method'] != 'GET':
                    if isinstance(req_resolved['body'], dict):
                        req_kwargs['headers']['Content-Type'] = 'application/json'
                        req_kwargs['json'] = req_resolved['body']
                    else:
                        req_kwargs['content'] = str(req_resolved['body'])
                r = await client.request(url=req_resolved['url'], **req_kwargs)
                try:
                    parsed = r.json()
                except ValueError:
                    parsed = r.text
                response_obj = {"status": r.status_code, "statusText": r.reason_phrase, "headers": dict(r.headers), "body": parsed}
                # Retry on 5xx if attempts remain
                if 500 <= r.status_code < 600 and attempt < max_attempts:
                    last_error = f"Server error {r.status_code}, retrying {attempt}/{max_attempts}"
                else:
                    last_error = None
                    break
        except Exception as e:
            last_error = str(e)
            if attempt >= max_attempts:
                response_obj = {"status": 0, "statusText": "ERROR", "headers": {}, "body": last_error}
                break
        # backoff if another attempt pending
        if attempt < max_attempts and retry_backoff_ms > 0:
            await asyncio.sleep(retry_backoff_ms / 1000)

    elapsed = int((time.time() - started_total) * 1000)
    history = await read_user_json(puch_user_id, 'history')
    history.insert(0, {"id": gen_id(), "request": {"method": req_resolved['method'], "url": req_resolved['url'], "headers": headers_with_auth, "body": req_resolved.get('body')}, "response": response_obj, "startedAt": datetime.now().isoformat(), "durationMs": elapsed, "tests": tests, "console": console_logs, "attempts": attempt, "lastError": last_error})
    while len(history) > 200:
        history.pop()
    await write_user_json(puch_user_id, 'history', history)
    return json.dumps({"response": response_obj, "attempts": attempt, "lastError": last_error, "resolvedUrl": req_resolved['url']}, indent=2)

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
async def create_environment_per_user( # type: ignore
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
async def update_environment_per_user( # type: ignore
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
async def delete_environment_per_user( # type: ignore
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
async def list_environments_per_user( # type: ignore
    puch_user_id: Annotated[str, Field(description="User id performing action")]
) -> str:
    await require_permission(puch_user_id, A_READ)
    await ensure_user_data(puch_user_id)
    envs = await read_user_json(puch_user_id, 'environments')
    return json.dumps(envs, indent=2)

# --- REPLACED: history per-user ---
@mcp.tool(name="history")
async def history_per_user( # type: ignore
    puch_user_id: Annotated[str, Field(description="User id performing action")],
    limit: Annotated[int, Field(description="Max entries", ge=1, le=100)] = 20,
) -> str:
    await require_permission(puch_user_id, A_READ)
    await ensure_user_data(puch_user_id)
    entries = await read_user_json(puch_user_id, 'history')
    return json.dumps(entries[:limit], indent=2)


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
    # FIX: previously passed numeric limit as 'kind' causing KeyError. Retrieve 'history' then slice.
    entries = await read_user_json(puch_user_id, 'history')
    return json.dumps(entries[:limit], indent=2)

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
        body_block = None
        if r.body is not None:
            if isinstance(r.body, dict):
                body_block = {"mode": "raw", "raw": json.dumps(r.body)}
            else:
                body_block = {"mode": "raw", "raw": str(r.body)}
        return {
            "name": r.name,
            "request": {
                "method": r.method,
                "header": [{"key": k, "value": v} for k, v in r.headers.items()],
                "url": r.url,
                "body": body_block,
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
            "_mcp": {
                "id": f.id,
                "variables": f.variables,
            },
        }

    exported = {
        "info": {
            "name": col_obj.name,
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
            "description": col.get("description"),
            "_postman_id": col_obj.id,  # optional compatibility
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

@mcp.tool(name="import_postman_collection")
async def import_postman_collection_per_user(
    puch_user_id: Annotated[str, Field(description="User id performing action")],
    json_data: Annotated[str, Field(description="Postman collection JSON (single, bundle, or list)")],
    overwrite_name: Annotated[Optional[str], Field(description="Force a name for single collection (ignored for bundles)")] = None,
) -> str:
    await require_permission(puch_user_id, A_IMPORT)
    await ensure_user_data(puch_user_id)

    if not json_data or not json_data.strip():
        raise McpError(ErrorData(code=INVALID_PARAMS, message="Empty JSON payload"))

    try:
        parsed = json.loads(json_data)
    except json.JSONDecodeError as e:
        raise McpError(ErrorData(code=INVALID_PARAMS, message=f"Invalid JSON: {e.msg}"))

    if isinstance(parsed, dict) and "item" in parsed:
        raw_collections = [parsed]
    elif isinstance(parsed, dict) and isinstance(parsed.get("collections"), list):
        raw_collections = [c for c in parsed["collections"] if isinstance(c, dict) and "item" in c]
    elif isinstance(parsed, list):
        raw_collections = [c for c in parsed if isinstance(c, dict) and "item" in c]
    else:
        raise McpError(ErrorData(code=INVALID_PARAMS, message="Unsupported format (expected single collection, {collections:[]}, or list)"))

    if not raw_collections:
        raise McpError(ErrorData(code=INVALID_PARAMS, message="No collection objects found"))

    existing = await read_user_json(puch_user_id, 'collections')
    if not isinstance(existing, list):
        existing = []

    def normalize_headers(request_dict: Dict[str, Any]) -> Dict[str, str]:
        hdrs = request_dict.get("header") or request_dict.get("headers") or []
        out: Dict[str, str] = {}
        for h in hdrs:
            if isinstance(h, dict):
                k = h.get("key") or h.get("name")
                if k:
                    out[k] = "" if h.get("value") is None else str(h.get("value"))
        return out

    def extract_body(req_block: Dict[str, Any]) -> Any:
        body = req_block.get("body")
        if not body:
            return None
        mode = body.get("mode")
        if mode == "raw":
            return body.get("raw")
        # Fallback: store whole structure
        return body

    def to_request(node: Dict[str, Any]) -> Dict[str, Any]:
        req_block = node.get("request") or {}
        method = (req_block.get("method") or node.get("method") or "GET").upper()
        url = req_block.get("url") or node.get("url") or ""
        if isinstance(url, dict):
            url = url.get("raw") or ""
        meta = node.get("_mcp", {})
        return {
            "id": meta.get("id") or node.get("id") or gen_id(),
            "name": node.get("name") or "Untitled Request",
            "method": method,
            "url": url,
            "headers": normalize_headers(req_block),
            "body": extract_body(req_block),
            "createdAt": datetime.now(timezone.utc).isoformat(),
            "variables": meta.get("variables") or {},
            "auth": meta.get("auth"),
            "preRequestScript": meta.get("preRequestScript"),
            "testScript": meta.get("testScript"),
        }

    def to_folder(node: Dict[str, Any]) -> Dict[str, Any]:
        children = node.get("item") or []
        meta = node.get("_mcp", {})
        folder_obj = {
            "id": meta.get("id") or node.get("id") or gen_id(),
            "name": node.get("name") or "Folder",
            "folders": [],
            "requests": [],
            "createdAt": datetime.now(timezone.utc).isoformat(),
            "variables": meta.get("variables"),
        }
        for child in children:
            if not isinstance(child, dict):
                continue
            if "item" in child and "request" not in child:
                folder_obj["folders"].append(to_folder(child))
            else:
                folder_obj["requests"].append(to_request(child))
        return folder_obj

    imported = 0
    for rc in raw_collections:
        items = rc.get("item")
        if not isinstance(items, list):
            continue
        info = rc.get("info") or {}
        meta = rc.get("_mcp", {})
        name = overwrite_name if (overwrite_name and len(raw_collections) == 1) else (info.get("name") or "Imported Collection")
        col_obj = {
            "id": meta.get("id") or info.get("_postman_id") or info.get("id") or gen_id(),
            "name": name,
            "description": info.get("description"),
            "folders": [],
            "requests": [],
            "createdAt": datetime.now(timezone.utc).isoformat(),
            "variables": {v["key"]: v["value"] for v in (rc.get("variable") or []) if isinstance(v, dict) and "key" in v},
            "auth": meta.get("auth"),
            "preRequestScript": meta.get("preRequestScript"),
            "testScript": meta.get("testScript"),
        }
        for element in items:
            if not isinstance(element, dict):
                continue
            if "item" in element and "request" not in element:
                col_obj["folders"].append(to_folder(element))
            else:
                col_obj["requests"].append(to_request(element))
        existing.append(col_obj)
        imported += 1

    if imported == 0:
        raise McpError(ErrorData(code=INVALID_PARAMS, message="No collections imported"))

    await write_user_json(puch_user_id, 'collections', existing)
    return json.dumps({"imported": imported, "totalCollections": len(existing)}, indent=2)


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
        col = await _resolve_collection(user_cols, collection_ref) # type: ignore
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
        dest_parent.folders.append(Folder(**moved_folder)) # type: ignore
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