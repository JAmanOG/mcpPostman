import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { promises as fs } from "fs";
import path from "path";
import crypto from "crypto";
import vm from "vm";
import http from "http";
import { fileURLToPath } from "url";
import express from "express";
import jwt from "jsonwebtoken";
import { config } from "dotenv";

config();

const app = express();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Simple persistence paths
const DATA_DIR = path.join(__dirname, "data");
const COLLECTIONS_FILE = path.join(DATA_DIR, "collections.json");
const ENV_FILE = path.join(DATA_DIR, "environments.json");
const HISTORY_FILE = path.join(DATA_DIR, "history.json");
const GLOBALS_FILE = path.join(DATA_DIR, "globals.json");

type AuthConfig = {
  type: "basic" | "bearer";
  username?: string;
  password?: string;
  token?: string;
};

type StoredRequest = {
  id: string;
  name: string;
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: any;
  createdAt: string;
  variables?: Record<string, string>; // request-scope vars
  auth?: AuthConfig; // overrides collection
  preRequestScript?: string;
  testScript?: string;
};

type Folder = {
  id: string;
  name: string;
  requests: StoredRequest[];
  folders: Folder[];
  createdAt: string;
  variables?: Record<string, string>; // treated as collection-level (between collection & request) but simple; not in minimal resolution chain now
};

type Collection = {
  id: string;
  name: string;
  requests: StoredRequest[]; // root-level
  folders?: Folder[];
  createdAt: string;
  variables?: Record<string, string>; // collection-scope vars
  auth?: AuthConfig; // inherited by requests
  preRequestScript?: string; // runs before every request in collection
  testScript?: string; // runs after every request
};

type EnvironmentSet = {
  id: string;
  name: string;
  variables: Record<string, string>;
  createdAt: string;
};

type HistoryEntry = {
  id: string;
  request: {
    method: string;
    url: string;
    headers: Record<string, string>;
    body?: any;
  };
  response: {
    status: number;
    statusText: string;
    headers: Record<string, string>;
    body: any;
  };
  startedAt: string;
  durationMs: number;
  tests?: { name: string; passed: boolean; error?: string }[];
  console?: string[];
};

async function ensureDataFiles() {
  await fs.mkdir(DATA_DIR, { recursive: true });
  const init = async (file: string, empty: any) => {
    try {
      await fs.access(file);
    } catch {
      await fs.writeFile(file, JSON.stringify(empty, null, 2), "utf-8");
    }
  };
  await Promise.all([
    init(COLLECTIONS_FILE, []),
    init(ENV_FILE, []),
    init(HISTORY_FILE, []),
    init(GLOBALS_FILE, { variables: {} }),
  ]);
}

async function readJSON<T>(file: string): Promise<T> {
  return JSON.parse(await fs.readFile(file, "utf-8"));
}

async function writeJSON(file: string, data: any) {
  await fs.writeFile(file, JSON.stringify(data, null, 2), "utf-8");
}

function genId() {
  return crypto.randomBytes(8).toString("hex");
}

// Variable resolution across scopes: local > request > collection > environment > global
function resolveVariables(
  raw: string,
  scopes: Record<string, string>[]
): string {
  return raw.replace(/\{\{(\w+)\}\}/g, (_, key) => {
    for (const scope of scopes) if (key in scope) return scope[key];
    return `{{${key}}}`; // leave unresolved
  });
}

function deepApply(obj: any, scopes: Record<string, string>[]): any {
  if (obj == null) return obj;
  if (typeof obj === "string") return resolveVariables(obj, scopes);
  if (Array.isArray(obj)) return obj.map((v) => deepApply(v, scopes));
  if (typeof obj === "object") {
    const out: any = {};
    for (const [k, v] of Object.entries(obj)) out[k] = deepApply(v, scopes);
    return out;
  }
  return obj;
}

function applyAuth(
  headers: Record<string, string>,
  auth?: AuthConfig
): Record<string, string> {
  if (!auth) return headers;
  const h = { ...headers };
  if (
    auth.type === "basic" &&
    auth.username !== undefined &&
    auth.password !== undefined
  ) {
    const token = Buffer.from(`${auth.username}:${auth.password}`).toString(
      "base64"
    );
    h["Authorization"] = `Basic ${token}`;
  } else if (auth.type === "bearer" && auth.token) {
    h["Authorization"] = `Bearer ${auth.token}`;
  }
  return h;
}

function runScript(
  label: string,
  source: string,
  contextData: {
    request: any;
    response?: any;
    variables: Record<string, string>;
    tests: { name: string; passed: boolean; error?: string }[];
    console: string[];
  }
) {
  const sandbox: any = {
    request: contextData.request,
    response: contextData.response,
    setVar: (k: string, v: string) => {
      contextData.variables[k] = String(v);
    },
    getVar: (k: string) => contextData.variables[k],
    test: (name: string, cond: any) => {
      try {
        const passed = !!cond;
        contextData.tests.push({
          name,
          passed,
          ...(passed ? {} : { error: "Assertion failed" }),
        });
      } catch (e: any) {
        contextData.tests.push({
          name,
          passed: false,
          error: e?.message || "error",
        });
      }
    },
    console: {
      log: (...args: any[]) =>
        contextData.console.push(
          args
            .map((a) => (typeof a === "string" ? a : JSON.stringify(a)))
            .join(" ")
        ),
    },
  };
  try {
    vm.runInNewContext(source, sandbox, {
      timeout: 100,
      microtaskMode: "afterEvaluate",
    });
  } catch (e: any) {
    contextData.tests.push({
      name: `${label} script error`,
      passed: false,
      error: e?.message || String(e),
    });
  }
}

function findFolder(
  collection: Collection,
  folderId: string
): Folder | undefined {
  const stack: Folder[] = [...(collection.folders || [])];
  while (stack.length) {
    const f = stack.pop()!;
    if (f.id === folderId) return f;
    stack.push(...f.folders);
  }
  return undefined;
}

const server = new McpServer({
  name: "mcp-postman",
  version: "1.1.0",
  capabilities: {
    resources: {},
    tools: {},
  },
});

// Tool: set_globals
server.tool(
  "set_globals",
  "Set or merge global variables",
  { data: z.object({ variables: z.record(z.string()) }) },
  async ({ data: { variables } }) => {
    await ensureDataFiles();
    const globals = JSON.parse(await fs.readFile(GLOBALS_FILE, "utf-8"));
    globals.variables = { ...(globals.variables || {}), ...variables };
    await fs.writeFile(GLOBALS_FILE, JSON.stringify(globals, null, 2), "utf-8");
    return {
      content: [{ type: "text", text: JSON.stringify(globals, null, 2) }],
    };
  }
);

// Tool: get_globals
server.tool("get_globals", "Get global variables", {}, async () => {
  await ensureDataFiles();
  const globals = JSON.parse(await fs.readFile(GLOBALS_FILE, "utf-8"));
  return {
    content: [{ type: "text", text: JSON.stringify(globals, null, 2) }],
  };
});

server.tool(
  "create_collection",
  "Create a new request collection",
  {
    name: z.object({
      name: z.string().min(1),
      variables: z.record(z.string()).optional(),
      auth: z
        .object({
          type: z.enum(["basic", "bearer"]),
          username: z.string().optional(),
          password: z.string().optional(),
          token: z.string().optional(),
        })
        .optional(),
      preRequestScript: z.string().optional(),
      testScript: z.string().optional(),
    }),
  },
  async ({ name: { name, variables, auth, preRequestScript, testScript } }) => {
    await ensureDataFiles();
    const collections: Collection[] = JSON.parse(
      await fs.readFile(COLLECTIONS_FILE, "utf-8")
    );
    const col: Collection = {
      id: genId(),
      name,
      requests: [],
      folders: [],
      createdAt: new Date().toISOString(),
      variables,
      auth,
      preRequestScript,
      testScript,
    };
    collections.push(col);
    await fs.writeFile(
      COLLECTIONS_FILE,
      JSON.stringify(collections, null, 2),
      "utf-8"
    );
    return { content: [{ type: "text", text: JSON.stringify(col, null, 2) }] };
  }
);

// Tool: update_collection
server.tool(
  "update_collection",
  "Update collection name/variables/auth/scripts",
  {
    data: z.object({
      collectionId: z.string(),
      name: z.string().optional(),
      variables: z.record(z.string()).optional(),
      auth: z
        .object({
          type: z.enum(["basic", "bearer"]),
          username: z.string().optional(),
          password: z.string().optional(),
          token: z.string().optional(),
        })
        .optional()
        .nullable(),
      preRequestScript: z.string().optional().nullable(),
      testScript: z.string().optional().nullable(),
    }),
  },
  async ({
    data: { collectionId, name, variables, auth, preRequestScript, testScript },
  }) => {
    await ensureDataFiles();
    const collections: Collection[] = JSON.parse(
      await fs.readFile(COLLECTIONS_FILE, "utf-8")
    );
    const col = collections.find((c) => c.id === collectionId);
    if (!col) throw new Error("Collection not found");
    if (name) col.name = name;
    if (variables) col.variables = { ...(col.variables || {}), ...variables };
    if (auth === null) delete col.auth;
    else if (auth) col.auth = auth;
    if (preRequestScript === null) delete col.preRequestScript;
    else if (preRequestScript !== undefined)
      col.preRequestScript = preRequestScript;
    if (testScript === null) delete col.testScript;
    else if (testScript !== undefined) col.testScript = testScript;
    await fs.writeFile(
      COLLECTIONS_FILE,
      JSON.stringify(collections, null, 2),
      "utf-8"
    );
    return { content: [{ type: "text", text: JSON.stringify(col, null, 2) }] };
  }
);

// Tool: delete_collection
server.tool(
  "delete_collection",
  "Delete a collection",
  { data: z.object({ collectionId: z.string() }) },
  async ({ data: { collectionId } }) => {
    await ensureDataFiles();
    let collections: Collection[] = JSON.parse(
      await fs.readFile(COLLECTIONS_FILE, "utf-8")
    );
    const before = collections.length;
    collections = collections.filter((c) => c.id !== collectionId);
    if (collections.length === before) throw new Error("Collection not found");
    await fs.writeFile(
      COLLECTIONS_FILE,
      JSON.stringify(collections, null, 2),
      "utf-8"
    );
    return { content: [{ type: "text", text: "Deleted" }] };
  }
);

// Tool: list_collections (unchanged but uses new shape)
server.tool("list_collections", "List all collections", {}, async () => {
  await ensureDataFiles();
  const collections: Collection[] = JSON.parse(
    await fs.readFile(COLLECTIONS_FILE, "utf-8")
  );
  return {
    content: [{ type: "text", text: JSON.stringify(collections, null, 2) }],
  };
});

// Tool: add_folder
server.tool(
  "add_folder",
  "Add a folder to a collection (optionally nested)",
  {
    data: z.object({
      collectionId: z.string(),
      parentFolderId: z.string().optional(),
      name: z.string(),
    }),
  },
  async ({ data: { collectionId, parentFolderId, name } }) => {
    await ensureDataFiles();
    const collections: Collection[] = JSON.parse(
      await fs.readFile(COLLECTIONS_FILE, "utf-8")
    );
    const col = collections.find((c) => c.id === collectionId);
    if (!col) throw new Error("Collection not found");
    const folder: Folder = {
      id: genId(),
      name,
      requests: [],
      folders: [],
      createdAt: new Date().toISOString(),
    };
    if (parentFolderId) {
      const parent = findFolder(col, parentFolderId);
      if (!parent) throw new Error("Parent folder not found");
      parent.folders.push(folder);
    } else {
      col.folders = col.folders || [];
      col.folders.push(folder);
    }
    await fs.writeFile(
      COLLECTIONS_FILE,
      JSON.stringify(collections, null, 2),
      "utf-8"
    );
    return {
      content: [{ type: "text", text: JSON.stringify(folder, null, 2) }],
    };
  }
);

// Tool: add_request (extended with folder, vars, auth, scripts)
server.tool(
  "add_request",
  "Add a request definition to a collection or folder",
  {
    data: z.object({
      collectionId: z.string(),
      folderId: z.string().optional(),
      name: z.string(),
      method: z.string().transform((s) => s.toUpperCase()),
      url: z.string(),
      headers: z.record(z.string()).default({}),
      body: z.any().optional(),
      variables: z.record(z.string()).optional(),
      auth: z
        .object({
          type: z.enum(["basic", "bearer"]),
          username: z.string().optional(),
          password: z.string().optional(),
          token: z.string().optional(),
        })
        .optional(),
      preRequestScript: z.string().optional(),
      testScript: z.string().optional(),
    }),
  },
  async ({
    data: {
      collectionId,
      folderId,
      name,
      method,
      url,
      headers,
      body,
      variables,
      auth,
      preRequestScript,
      testScript,
    },
  }) => {
    await ensureDataFiles();
    const collections: Collection[] = JSON.parse(
      await fs.readFile(COLLECTIONS_FILE, "utf-8")
    );
    const col = collections.find((c) => c.id === collectionId);
    if (!col) throw new Error("Collection not found");
    const req: StoredRequest = {
      id: genId(),
      name,
      method,
      url,
      headers,
      body,
      createdAt: new Date().toISOString(),
      variables,
      auth,
      preRequestScript,
      testScript,
    };
    if (folderId) {
      const folder = findFolder(col, folderId);
      if (!folder) throw new Error("Folder not found");
      folder.requests.push(req);
    } else {
      col.requests.push(req);
    }
    await fs.writeFile(
      COLLECTIONS_FILE,
      JSON.stringify(collections, null, 2),
      "utf-8"
    );
    return { content: [{ type: "text", text: JSON.stringify(req, null, 2) }] };
  }
);

// Tool: update_request
server.tool(
  "update_request",
  "Update a stored request (searches all folders)",
  {
    data: z.object({
      collectionId: z.string(),
      requestId: z.string(),
      name: z.string().optional(),
      method: z
        .string()
        .transform((s) => s.toUpperCase())
        .optional(),
      url: z.string().optional(),
      headers: z.record(z.string()).optional(),
      body: z.any().optional(),
      variables: z.record(z.string()).optional(),
      auth: z
        .object({
          type: z.enum(["basic", "bearer"]),
          username: z.string().optional(),
          password: z.string().optional(),
          token: z.string().optional(),
        })
        .optional()
        .nullable(),
      preRequestScript: z.string().optional().nullable(),
      testScript: z.string().optional().nullable(),
    }),
  },
  async ({ data }) => {
    await ensureDataFiles();
    const collections: Collection[] = JSON.parse(
      await fs.readFile(COLLECTIONS_FILE, "utf-8")
    );
    const col = collections.find((c) => c.id === data.collectionId);
    if (!col) throw new Error("Collection not found");
    const allRequestArrays: StoredRequest[][] = [col.requests];
    const stack: Folder[] = [...(col.folders || [])];
    while (stack.length) {
      const f = stack.pop()!;
      allRequestArrays.push(f.requests);
      stack.push(...f.folders);
    }
    let target: StoredRequest | undefined;
    for (const arr of allRequestArrays) {
      target = arr.find((r) => r.id === data.requestId);
      if (target) break;
    }
    if (!target) throw new Error("Request not found");
    if (data.name) target.name = data.name;
    if (data.method) target.method = data.method.toUpperCase();
    if (data.url) target.url = data.url;
    if (data.headers) target.headers = data.headers;
    if (data.body !== undefined) target.body = data.body;
    if (data.variables)
      target.variables = { ...(target.variables || {}), ...data.variables };
    if (data.auth === null) delete target.auth;
    else if (data.auth) target.auth = data.auth;
    if (data.preRequestScript === null) delete target.preRequestScript;
    else if (data.preRequestScript !== undefined)
      target.preRequestScript = data.preRequestScript;
    if (data.testScript === null) delete target.testScript;
    else if (data.testScript !== undefined) target.testScript = data.testScript;
    await fs.writeFile(
      COLLECTIONS_FILE,
      JSON.stringify(collections, null, 2),
      "utf-8"
    );
    return {
      content: [{ type: "text", text: JSON.stringify(target, null, 2) }],
    };
  }
);

// Tool: delete_request
server.tool(
  "delete_request",
  "Delete a stored request",
  { data: z.object({ collectionId: z.string(), requestId: z.string() }) },
  async ({ data: { collectionId, requestId } }) => {
    await ensureDataFiles();
    const collections: Collection[] = JSON.parse(
      await fs.readFile(COLLECTIONS_FILE, "utf-8")
    );
    const col = collections.find((c) => c.id === collectionId);
    if (!col) throw new Error("Collection not found");
    let removed = false;
    const tryRemove = (arr: StoredRequest[]) => {
      const idx = arr.findIndex((r) => r.id === requestId);
      if (idx >= 0) {
        arr.splice(idx, 1);
        removed = true;
      }
    };
    tryRemove(col.requests);
    const stack: Folder[] = [...(col.folders || [])];
    while (stack.length && !removed) {
      const f = stack.pop()!;
      tryRemove(f.requests);
      stack.push(...f.folders);
    }
    if (!removed) throw new Error("Request not found");
    await fs.writeFile(
      COLLECTIONS_FILE,
      JSON.stringify(collections, null, 2),
      "utf-8"
    );
    return { content: [{ type: "text", text: "Deleted" }] };
  }
);

// Tool: list_requests (extended optional folderId)
server.tool(
  "list_requests",
  "List stored requests in a collection or folder",
  {
    data: z.object({
      collectionId: z.string(),
      folderId: z.string().optional(),
    }),
  },
  async ({ data: { collectionId, folderId } }) => {
    await ensureDataFiles();
    const collections: Collection[] = JSON.parse(
      await fs.readFile(COLLECTIONS_FILE, "utf-8")
    );
    const col = collections.find((c) => c.id === collectionId);
    if (!col) throw new Error("Collection not found");
    if (folderId) {
      const folder = findFolder(col, folderId);
      if (!folder) throw new Error("Folder not found");
      return {
        content: [
          { type: "text", text: JSON.stringify(folder.requests, null, 2) },
        ],
      };
    }
    return {
      content: [{ type: "text", text: JSON.stringify(col.requests, null, 2) }],
    };
  }
);

// Tool: create_environment
server.tool(
  "create_environment",
  "Create an environment variable set",
  { data: z.object({ name: z.string(), variables: z.record(z.string()) }) },
  async ({ data: { name, variables } }) => {
    await ensureDataFiles();
    const envs: EnvironmentSet[] = JSON.parse(
      await fs.readFile(ENV_FILE, "utf-8")
    );
    const env: EnvironmentSet = {
      id: genId(),
      name,
      variables,
      createdAt: new Date().toISOString(),
    };
    envs.push(env);
    await fs.writeFile(ENV_FILE, JSON.stringify(envs, null, 2), "utf-8");
    return { content: [{ type: "text", text: JSON.stringify(env, null, 2) }] };
  }
);

// Tool: update_environment
server.tool(
  "update_environment",
  "Update environment variables (merge)",
  {
    data: z.object({
      environmentId: z.string(),
      variables: z.record(z.string()),
    }),
  },
  async ({ data: { environmentId, variables } }) => {
    await ensureDataFiles();
    const envs: EnvironmentSet[] = JSON.parse(
      await fs.readFile(ENV_FILE, "utf-8")
    );
    const env = envs.find((e) => e.id === environmentId);
    if (!env) throw new Error("Environment not found");
    env.variables = { ...env.variables, ...variables };
    await fs.writeFile(ENV_FILE, JSON.stringify(envs, null, 2), "utf-8");
    return { content: [{ type: "text", text: JSON.stringify(env, null, 2) }] };
  }
);

// Tool: delete_environment
server.tool(
  "delete_environment",
  "Delete an environment set",
  { data: z.object({ environmentId: z.string() }) },
  async ({ data: { environmentId } }) => {
    await ensureDataFiles();
    let envs: EnvironmentSet[] = JSON.parse(
      await fs.readFile(ENV_FILE, "utf-8")
    );
    const before = envs.length;
    envs = envs.filter((e) => e.id !== environmentId);
    if (envs.length === before) throw new Error("Environment not found");
    await fs.writeFile(ENV_FILE, JSON.stringify(envs, null, 2), "utf-8");
    return { content: [{ type: "text", text: "Deleted" }] };
  }
);

// Tool: list_environments
server.tool("list_environments", "List environments", {}, async () => {
  await ensureDataFiles();
  const envs: EnvironmentSet[] = JSON.parse(
    await fs.readFile(ENV_FILE, "utf-8")
  );
  return { content: [{ type: "text", text: JSON.stringify(envs, null, 2) }] };
});

// Tool: send_request (extended for variables, auth, scripts, folder search)
server.tool(
  "send_request",
  "Send an HTTP request (direct or stored). Applies variable scopes, auth, scripts.",
  {
    data: z
      .object({
        method: z.string().optional(),
        url: z.string().optional(),
        headers: z.record(z.string()).optional(),
        body: z.any().optional(),
        storedRequestId: z.string().optional(),
        collectionId: z.string().optional(),
        environmentId: z.string().optional(),
        localVariables: z.record(z.string()).optional(),
        auth: z
          .object({
            type: z.enum(["basic", "bearer"]),
            username: z.string().optional(),
            password: z.string().optional(),
            token: z.string().optional(),
          })
          .optional(),
        timeoutMs: z.number().int().positive().max(120000).default(30000),
      })
      .refine(
        (data) =>
          (data.storedRequestId && data.collectionId) ||
          (data.method && data.url),
        {
          message:
            "Either provide storedRequestId + collectionId OR method + url",
        }
      ),
  },
  async ({
    data: {
      method,
      url,
      headers,
      body,
      storedRequestId,
      collectionId,
      environmentId,
      localVariables,
      auth,
      timeoutMs,
    },
  }) => {
    await ensureDataFiles();
    const globals = JSON.parse(await fs.readFile(GLOBALS_FILE, "utf-8"));
    let request: StoredRequest;
    let collection: Collection | undefined;
    let envVars: Record<string, string> = {};

    if (storedRequestId) {
      const collections: Collection[] = JSON.parse(
        await fs.readFile(COLLECTIONS_FILE, "utf-8")
      );
      collection = collections.find((c) => c.id === collectionId);
      if (!collection) throw new Error("Collection not found");
      // search root and folders
      const arrays: StoredRequest[][] = [collection.requests];
      const stack: Folder[] = [...(collection.folders || [])];
      while (stack.length) {
        const f = stack.pop()!;
        arrays.push(f.requests);
        stack.push(...f.folders);
      }
      let found: StoredRequest | undefined;
      for (const arr of arrays) {
        found = arr.find((r) => r.id === storedRequestId);
        if (found) break;
      }
      if (!found) throw new Error("Stored request not found");
      request = found;
    } else {
      request = {
        id: genId(),
        name: "ad-hoc",
        method: (method as string).toUpperCase(),
        url: url as string,
        headers: headers || {},
        body,
        createdAt: new Date().toISOString(),
        variables: {},
      };
    }

    if (environmentId) {
      const envs: EnvironmentSet[] = JSON.parse(
        await fs.readFile(ENV_FILE, "utf-8")
      );
      const env = envs.find((e) => e.id === environmentId);
      if (!env) throw new Error("Environment not found");
      envVars = env.variables;
    }

    const localVars = { ...(localVariables || {}) };
    const requestVars = request.variables || {};
    const collectionVars = collection?.variables || {};
    const globalVars = globals.variables || {};

    const variableChain = [
      localVars,
      requestVars,
      collectionVars,
      envVars,
      globalVars,
    ];

    // Pre-request scripts (collection then request)
    const tests: { name: string; passed: boolean; error?: string }[] = [];
    const consoleLogs: string[] = [];
    if (collection?.preRequestScript)
      runScript("collection pre-request", collection.preRequestScript, {
        request,
        variables: localVars,
        tests,
        console: consoleLogs,
      });
    if (request.preRequestScript)
      runScript("request pre-request", request.preRequestScript, {
        request,
        variables: localVars,
        tests,
        console: consoleLogs,
      });

    // After pre-request scripts, variable chain may have new local vars
    const finalVariableChain = [
      localVars,
      requestVars,
      collectionVars,
      envVars,
      globalVars,
    ];

    // Apply variable substitution to request clone
    const reqResolved = {
      ...request,
      url: resolveVariables(request.url, finalVariableChain),
      headers: deepApply(request.headers, finalVariableChain),
      body: deepApply(request.body, finalVariableChain),
    };

    // Auth precedence: explicit in send_request > request.auth > collection.auth
    const effectiveAuth = auth || request.auth || collection?.auth;
    const headersWithAuth = applyAuth(reqResolved.headers, effectiveAuth);

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    const started = performance.now();
    let responseObj: any;
    try {
      const fetchOpts: any = {
        method: reqResolved.method,
        headers: headersWithAuth,
        signal: controller.signal,
      };
      if (
        reqResolved.body !== undefined &&
        reqResolved.body !== null &&
        reqResolved.method !== "GET"
      ) {
        if (
          typeof reqResolved.body === "object" &&
          !Array.isArray(reqResolved.body)
        ) {
          fetchOpts.headers = {
            "Content-Type": "application/json",
            ...fetchOpts.headers,
          };
          fetchOpts.body = JSON.stringify(reqResolved.body);
        } else {
          fetchOpts.body =
            typeof reqResolved.body === "string"
              ? reqResolved.body
              : JSON.stringify(reqResolved.body);
        }
      }
      const res = await fetch(reqResolved.url, fetchOpts);
      const resText = await res.text();
      let parsed: any;
      try {
        parsed = JSON.parse(resText);
      } catch {
        parsed = resText;
      }
      const resHeaders: Record<string, string> = {};
      res.headers.forEach((v, k) => (resHeaders[k] = v));
      responseObj = {
        status: res.status,
        statusText: res.statusText,
        headers: resHeaders,
        body: parsed,
      };
    } finally {
      clearTimeout(timer);
    }

    // Test scripts
    if (collection?.testScript)
      runScript("collection test", collection.testScript, {
        request: reqResolved,
        response: responseObj,
        variables: localVars,
        tests,
        console: consoleLogs,
      });
    if (request.testScript)
      runScript("request test", request.testScript, {
        request: reqResolved,
        response: responseObj,
        variables: localVars,
        tests,
        console: consoleLogs,
      });

    // Persist history
    const elapsed = performance.now();
    const history: HistoryEntry[] = JSON.parse(
      await fs.readFile(HISTORY_FILE, "utf-8")
    );
    history.unshift({
      id: genId(),
      request: {
        method: reqResolved.method,
        url: reqResolved.url,
        headers: headersWithAuth,
        body: reqResolved.body,
      },
      response: responseObj || {
        status: 0,
        statusText: "ABORTED",
        headers: {},
        body: null,
      },
      startedAt: new Date().toISOString(),
      durationMs: Math.round(elapsed),
      tests,
      console: consoleLogs,
    });
    while (history.length > 200) history.pop();
    await fs.writeFile(HISTORY_FILE, JSON.stringify(history, null, 2), "utf-8");

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(
            {
              response: responseObj,
              tests,
              console: consoleLogs,
              resolvedUrl: reqResolved.url,
            },
            null,
            2
          ),
        },
      ],
    };
  }
);

// Tool: history (extended)
server.tool(
  "history",
  "List recent request history",
  {
    limit: z.object({
      limit: z.number().int().positive().max(100).default(20),
    }),
  },
  async ({ limit: { limit } }) => {
    await ensureDataFiles();
    const history: HistoryEntry[] = JSON.parse(
      await fs.readFile(HISTORY_FILE, "utf-8")
    );
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(history.slice(0, limit), null, 2),
        },
      ],
    };
  }
);

// Tool: export_collection (Postman v2.1 subset)
server.tool(
  "export_collection",
  "Export a collection to Postman v2.1 JSON (subset)",
  { data: z.object({ collectionId: z.string() }) },
  async ({ data: { collectionId } }) => {
    await ensureDataFiles();
    const collections: Collection[] = JSON.parse(
      await fs.readFile(COLLECTIONS_FILE, "utf-8")
    );
    const col = collections.find((c) => c.id === collectionId);
    if (!col) throw new Error("Collection not found");

    const mapRequest = (r: StoredRequest) => ({
      name: r.name,
      request: {
        method: r.method,
        header: Object.entries(r.headers).map(([key, value]) => ({
          key,
          value,
        })),
        url: r.url,
        body: r.body
          ? {
              mode: "raw",
              raw:
                typeof r.body === "string"
                  ? r.body
                  : JSON.stringify(r.body, null, 2),
            }
          : undefined,
      },
      _mcp: {
        id: r.id,
        variables: r.variables,
        auth: r.auth,
        preRequestScript: r.preRequestScript,
        testScript: r.testScript,
      },
    });

    const mapFolder = (f: Folder): any => ({
      name: f.name,
      item: [...f.requests.map(mapRequest), ...f.folders.map(mapFolder)],
    });

    const exported = {
      info: {
        name: col.name,
        schema:
          "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
      },
      item: [
        ...col.requests.map(mapRequest),
        ...(col.folders || []).map(mapFolder),
      ],
      variable: col.variables
        ? Object.entries(col.variables).map(([key, value]) => ({ key, value }))
        : undefined,
      _mcp: {
        id: col.id,
        auth: col.auth,
        preRequestScript: col.preRequestScript,
        testScript: col.testScript,
      },
    };

    return {
      content: [{ type: "text", text: JSON.stringify(exported, null, 2) }],
    };
  }
);

// Tool: import_postman_collection (subset)
server.tool(
  "import_postman_collection",
  "Import a Postman collection v2.1 JSON (subset supported)",
  { data: z.object({ json: z.string() }) },
  async ({ data: { json } }) => {
    await ensureDataFiles();
    let parsed: any;
    try {
      parsed = JSON.parse(json);
    } catch {
      throw new Error("Invalid JSON");
    }
    if (!parsed || !parsed.item || !Array.isArray(parsed.item))
      throw new Error("Unsupported collection format");
    const collections: Collection[] = JSON.parse(
      await fs.readFile(COLLECTIONS_FILE, "utf-8")
    );

    const toRequest = (it: any): StoredRequest => ({
      id: genId(),
      name: it.name || "request",
      method: (it.request?.method || "GET").toUpperCase(),
      url:
        typeof it.request?.url === "string"
          ? it.request.url
          : it.request?.url?.raw || "",
      headers: (it.request?.header || []).reduce((acc: any, h: any) => {
        if (h && h.key) acc[h.key] = h.value || "";
        return acc;
      }, {}),
      body: it.request?.body?.raw ? it.request.body.raw : undefined,
      createdAt: new Date().toISOString(),
      variables: it._mcp?.variables,
      auth: it._mcp?.auth,
      preRequestScript: it._mcp?.preRequestScript,
      testScript: it._mcp?.testScript,
    });

    const toFolder = (item: any): Folder => ({
      id: genId(),
      name: item.name || "folder",
      requests: (item.item || []).filter((x: any) => x.request).map(toRequest),
      folders: (item.item || [])
        .filter((x: any) => x.item && !x.request)
        .map(toFolder),
      createdAt: new Date().toISOString(),
    });

    const collection: Collection = {
      id: genId(),
      name: parsed.info?.name || "Imported",
      requests: parsed.item.filter((x: any) => x.request).map(toRequest),
      folders: parsed.item
        .filter((x: any) => x.item && !x.request)
        .map(toFolder),
      createdAt: new Date().toISOString(),
      variables: (parsed.variable || []).reduce((acc: any, v: any) => {
        if (v.key) acc[v.key] = v.value || "";
        return acc;
      }, {}),
      auth: parsed._mcp?.auth,
      preRequestScript: parsed._mcp?.preRequestScript,
      testScript: parsed._mcp?.testScript,
    };

    collections.push(collection);
    await fs.writeFile(
      COLLECTIONS_FILE,
      JSON.stringify(collections, null, 2),
      "utf-8"
    );
    return {
      content: [{ type: "text", text: JSON.stringify(collection, null, 2) }],
    };
  }
);

const jwtSecret: any = process.env.JWT_SECRET || "";
if (!jwtSecret) {
  console.error(
    "JWT_SECRET environment variable is not set, bearer token validation will not work"
  );
}

server.tool(
  "validate",
  "Validate bearer token and return user's phone number in {country_code}{number} format",
  {
    data: z.object({
      token: z.string().min(1, "Bearer token required"),
    }),
  },
  async ({ data: { token } }) => {
    let decoded: any;
    try {
      decoded = jwt.decode(token, jwtSecret);
      if (!decoded || !decoded.phone_number)
        throw new Error("phone_number not found in token");
    } catch (e: any) {
      throw new Error("Invalid token: " + (e?.message || e));
    }

    // Extract phone number in format +91-9876543210 or +919876543210
    let raw = decoded.phone_number as string;
    let match = raw.match(/^\+?(\d{1,3})[-\s]?(\d{6,})$/);
    if (!match) throw new Error("Invalid phone number format in token");
    const phone = `${match[1]}${match[2]}`;

    return { content: [{ type: "text", text: phone }] };
  }
);

// Start the MCP server
async function main() {
  await ensureDataFiles();
  const transport = new StdioServerTransport();

  // Prevent premature exit if stdin closes in Azure environment
  if (process.stdin) {
    process.stdin.on("end", () => {
      console.error("[lifecycle] stdin ended (ignoring to keep server alive)");
    });
    process.stdin.on("close", () => {
      console.error(
        "[lifecycle] stdin closed (ignoring to keep server running)"
      );
    });
  }

  await server.connect(transport);
  console.error("MCP server started on stdin/stdout transport");

  const rawPort = process.env.PORT || process.env.WEBSITE_PORT || "3000";
  const port = parseInt(rawPort, 10);
  if (Number.isNaN(port)) {
    console.error(`Invalid port value "${rawPort}", defaulting to 3000`);
  }

  app.get('/health', (_req, res) => {
    res.json({ status: "ok", time: new Date().toISOString() });
  });

  const serverHttp = http.createServer(app);
  serverHttp.listen(port, () => console.error(`HTTP server (health+SSE) on :${port}`));

  // Global error handlers
  process.on("uncaughtException", (err) => {
    console.error("[fatal] uncaughtException", err);
  });
  process.on("unhandledRejection", (reason) => {
    console.error("[fatal] unhandledRejection", reason);
  });

  // Graceful shutdown
  const shutdown = (signal: string) => {
    console.error(
      `[lifecycle] Received ${signal}, shutting down gracefully...`
    );
    serverHttp.close(() => {
      console.error("[lifecycle] HTTP server closed");
      // Delay a bit to flush logs
      setTimeout(() => process.exit(0), 200);
    });
    // Fallback force exit
    setTimeout(() => {
      console.error("[lifecycle] Force exit after timeout");
      process.exit(1);
    }, 5000).unref();
  };
  ["SIGTERM", "SIGINT"].forEach((sig) => process.on(sig, () => shutdown(sig)));

  // Keep-alive heartbeat (covers edge case where event loop empties)
  const heartbeat = setInterval(() => {
    console.error(`[heartbeat] ${new Date().toISOString()}`);
  }, 60_000);
  heartbeat.unref();
}

app.get("/sse", (req, res) => {
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  // Optional: disable proxy buffering
  res.flushHeaders?.();

  const heartbeat = setInterval(() => {
    res.write(":\n\n"); // comment heartbeat
  }, 15000);

  // Example initial event (adjust to MCP protocol your client expects)
  res.write(`event: ready\ndata: {"status":"ok"}\n\n`);

  req.on("close", () => {
    clearInterval(heartbeat);
  });
});

app.get("/", (_, res) => res.send("MCP SSE server running"));

main().catch((err) => {
  console.error("Fatal startup error:", err);
  process.exit(1);
});
