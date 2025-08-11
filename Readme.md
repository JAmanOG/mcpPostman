# MCP ReqForge Server

[Wanna try it out? Click Now on Directly integrated in your WhatsApp](https://puch.ai/mcp/WoFsL1UMUc)

List of all tool documentation is available at [https://mcppostman-1.onrender.com](https://mcppostman-1.onrender.com).

## What is MCP (Model Context Protocol)?

**MCP (Model Context Protocol)** is an open protocol and API specification designed to enable secure, context-aware, and extensible interactions between clients (such as AI agents, automation tools, or user interfaces) and backend services. MCP provides a standardized way to expose, discover, and invoke "tools" (API endpoints or actions) with rich metadata, permissions, and context propagation. It is especially suited for environments where user isolation, RBAC (Role-Based Access Control), and extensibility are critical.

Key features of MCP include:
- **Tool Discovery:** Clients can enumerate available tools, their parameters, and usage descriptions.
- **Context Propagation:** Each request carries user/session context, enabling per-user data isolation and permission enforcement.
- **Rich Metadata:** Every tool/action is described with machine-readable metadata (parameters, descriptions, side effects, etc.), supporting dynamic UIs and agent integration.
- **Secure Authentication:** Supports modern authentication schemes (e.g., Bearer tokens, JWT) for secure access.
- **Extensibility:** Easily add new tools or extend existing ones without breaking clients.
- **Streaming & Async:** Supports streaming responses and asynchronous execution for long-running or interactive tasks.

## Project Overview: MCP ReqForge Server

This project is a **full-featured, Postman-like API testing and automation server** built on top of MCP. It provides a robust backend for managing API collections, requests, environments, variables, and execution history, all with per-user isolation and RBAC. The backend is implemented in Python, using Redis for fast, persistent storage, and exposes a modern MCP-compatible API.

### Core Features

- **User-based RBAC:** Each user has isolated data (collections, environments, history, globals) and a role (admin, editor, reader, tester) controlling permissions.
- **Bearer Token Authentication:** Secure access using Bearer tokens, with easy integration for automation and agent clients.
- **Redis Backend:** All user data is stored in Redis, ensuring high performance and scalability.
- **API Collections & Requests:** Organize API requests into collections and folders, with support for variables, scripts, and authentication at every level.
- **Environment Management:** Define and switch between multiple environments (dev, staging, prod) with variable substitution.
- **Global Variables:** Store and retrieve variables that can be used across all requests and collections.
- **Pre-request & Test Scripts:** Attach JavaScript snippets to run before or after requests for dynamic logic and assertions.
- **History Tracking:** Every request/response is logged with metadata, test results, and console output for auditing and debugging.
- **Import/Export:** Full compatibility with Postman collection format (import/export), including preservation of custom MCP metadata.
- **Tooling & Extensibility:** All actions (CRUD, execution, metadata, etc.) are exposed as MCP tools with rich metadata for agent and UI integration.

### Technical Stack

- **Python 3.10+**
- **FastMCP** (MCP server framework)
- **Redis** (data storage)
- **httpx** (HTTP client for request execution)
- **pydantic** (data validation and modeling)
- **dotenv** (environment variable management)
- **Frontend:** Vite + React (for documentation and UI, if present)

### Directory Structure

```
PythonImplementation/
  main.py           # Main MCP server implementation
  oldmain.py        # Legacy/alternate implementation
  requirements.txt  # Python dependencies
  .env              # Environment variables (tokens, Redis config)
  data/
    collections.json
    environments.json
    globals.json
    history.json
frontend/
  ...               # React/Vite frontend (optional)
```

### Example MCP Tools

- `create_collection`, `update_collection`, `delete_collection`, `list_collections`
- `add_request`, `update_request`, `delete_request`, `list_requests`
- `add_folder`, `move_folder`, `list_folders`
- `create_environment`, `update_environment`, `delete_environment`, `list_environments`
- `set_globals`, `get_globals`
- `send_request` (execute API requests, with variable/environment/script support)
- `import_postman_collection`, `export_collection`
- `history` (per-user request/response log)
- `set_user_metadata`, `get_my_metadata` (RBAC management)

### Security & Permissions

- **RBAC:** Each user is assigned a role (`admin`, `editor`, `reader`, `tester`) with fine-grained permissions.
- **Per-user Namespacing:** All collections, environments, globals, and history are isolated per user in Redis.
- **Bearer Token Auth:** Only authenticated users can access tools; tokens are validated on every request.

### Usage

1. **Start the MCP server:**  
   ```sh
   python PythonImplementation/main.py
   ```
2. **Authenticate:**  
   Use your Bearer token (from `.env`) in the `Authorization` header.
3. **Interact via MCP client, agent, or UI:**  
   Discover and invoke tools, manage collections, run requests, etc.

### Extending

- Add new tools by defining async functions with `@mcp.tool` decorator.
- Update or add data models using Pydantic.
- Integrate with additional backends or authentication providers as needed.

---

## Frontend: Modern React + Vite UI for MCP ReqForge

The frontend of this project is a modern, responsive web application built with **React** and **Vite**. It serves as a documentation and demonstration portal for the MCP ReqForge server, providing users with an interactive overview of all available features, tools, and usage instructions.

### Key Features

- **Instant Documentation:**  
  The UI presents all MCP tools, categorized by functionality (collections, folders, requests, environments, variables, history, user management, etc.), with clear descriptions and usage hints.

- **Role-Based UI Elements:**  
  Visualizes RBAC (Role-Based Access Control) roles and permissions, helping users understand access levels (admin, editor, reader, tester).

- **Capabilities Showcase:**  
  Highlights the server’s core capabilities, such as Redis-backed storage, user isolation, variable management, scripting, and ReqForge compatibility.

- **Step-by-Step Usage Guide:**  
  Provides a clear, multi-step guide for connecting to the MCP server, including integration with external platforms (e.g., Puch.ai, WhatsApp).

- **Modern Design:**  
  Uses a clean, mobile-friendly layout with custom CSS and Tailwind integration for rapid styling and responsive behavior.

- **Extensible Structure:**  
  Easily adaptable for future enhancements, such as live API testing, authentication flows, or team collaboration features.

### Technical Stack

- **React 18+**  
- **Vite** (for fast development and HMR)
- **Tailwind CSS** (via plugin, for utility-first styling)
- **Custom CSS** (for advanced layout and animation)
- **ESLint** (with React and hooks support)

### Directory Structure

```
frontend/
  src/
    App.jsx         # Main documentation and UI logic
    App.css         # Custom styles for all UI sections
    index.css       # Tailwind base import
    main.jsx        # Entry point
    assets/         # Static assets (SVGs, images)
  public/
    vite.svg        # Favicon/logo
  index.html        # HTML template
  package.json      # Dependencies and scripts
  vite.config.js    # Vite + Tailwind config
  eslint.config.js  # Linting rules
  README.md         # Frontend-specific notes
```

### UI Sections

- **Hero Section:**  
  Project title, subtitle, and quick server info badges (user isolation, auth, storage).

- **Features Section:**  
  Categorized list of all MCP tools, each with a name and description, grouped by feature (collections, folders, requests, environments, data/history, user management).

- **Capabilities Section:**  
  Grid of cards highlighting unique backend features (RBAC, Redis, ReqForge compatibility, variable management, scripting, hierarchical organization).

- **Usage Section:**  
  Step-by-step instructions for accessing and using the MCP server, including platform links and integration notes.

- **Footer:**  
  Credits and stack information.

### Styling & Responsiveness

- **Custom CSS** in `src/App.css` provides a polished, animated, and responsive layout.
- **Tailwind CSS** is imported via `src/index.css` and configured in `vite.config.js`.
- **Mobile Friendly:**  
  All sections adapt to smaller screens, with grid-to-column transitions and touch-friendly controls.

### How to Run

1. **Install dependencies:**
   ```sh
   cd frontend
   npm install
   ```
2. **Start the development server:**
   ```sh
   npm run dev
   ```
3. **Open in browser:**  
   Visit [http://localhost:5173](http://localhost:5173) (or the port shown in your terminal).

### Customization & Extension

- **Add new tools or features:**  
  Update `src/App.jsx` to add new tool descriptions or UI sections.
- **Change styles:**  
  Edit `src/App.css` or use Tailwind utility classes.
- **Integrate live API calls:**  
  Extend the React components to connect to your MCP backend for interactive testing or authentication.

---

## First Approach: TypeScript FastMCP Server

This project’s initial implementation was a robust, fully functional MCP-compatible backend written in **TypeScript** using the [FastMCP](https://www.npmjs.com/package/fastmcp) library. The goal was to provide a Postman-like API automation and testing server, with all core features implemented in a single, modular TypeScript file.

### Architecture & Design

- **Framework:**  
  Built on FastMCP, a modern, lightweight MCP server framework for Node.js.
- **Persistence:**  
  Uses the Node.js `fs` module for simple, file-based JSON storage (collections, environments, globals, history) in a local `data/` directory.
- **Authentication:**  
  Implements Bearer token and API key authentication, with session context passed to all tools.
- **Schema Validation:**  
  All tool parameters are validated using [Zod](https://zod.dev/), ensuring strict type safety and clear error messages.
- **Extensible Tooling:**  
  Tools are registered via a reusable `adaptTool` helper, making it easy to add new endpoints with rich metadata and validation.

### Core Features

- **Collections, Folders, and Requests:**  
  - Create, update, delete, and list collections.
  - Support for nested folders and requests, mirroring Postman’s hierarchy.
  - Each request supports variables, authentication, pre-request and test scripts.
- **Environment & Global Variables:**  
  - Create, update, delete, and list environments.
  - Set and get global variables, with variable resolution across all scopes.
- **Request Execution:**  
  - Send ad-hoc or stored requests, with full variable substitution, authentication, and script execution.
  - Pre-request and test scripts are executed in a secure VM context, supporting dynamic logic and assertions.
- **History Tracking:**  
  - Every request/response is logged with metadata, test results, and console output.
  - History is capped for performance and can be queried via the MCP API.
- **Import/Export:**  
  - Import and export collections in Postman v2.1 format (subset), preserving MCP-specific metadata.
- **RBAC Ready:**  
  - Session context is available for future RBAC or multi-user extensions.

### Technical Stack

- **TypeScript** (strict mode)
- **Node.js** (ESM modules)
- **FastMCP** (MCP server)
- **Zod** (schema validation)
- **Node.js fs/promises** (file storage)
- **crypto** (ID generation)
- **vm** (secure script execution)
- **dotenv** (environment variables)

### File Structure

```
firstApproach.ts      # Main TypeScript MCP server (single file)
data/
  collections.json
  environments.json
  globals.json
  history.json
.env                  # Auth tokens, config
```

### Usage

1. **Install dependencies:**
   ```sh
   npm install fastmcp zod dotenv
   ```
2. **Run the server:**
   ```sh
   node firstApproach.ts
   ```
3. **Access the MCP endpoint:**  
   The server runs on `/mcp` (default port 5000). Authenticate using a Bearer token or API key.

### Strengths

- **Self-contained:**  
  All logic is in a single, readable TypeScript file—easy to audit and extend.
- **Rich Feature Set:**  
  Implements nearly all Postman-like features, including scripting and variable resolution.
- **MCP Native:**  
  All actions are exposed as MCP tools with strict schemas and metadata.

### Limitations

- **Single-user, file-based:**  
  No built-in user isolation or RBAC; all data is shared and persisted locally.
- **Not optimized for scale:**  
  File-based storage is simple but not suitable for concurrent or multi-user environments.
- **No Redis or advanced backend:**  
  Lacks the high-performance, per-user isolation, and RBAC features of the Python/Redis implementation.

### Why Python MCP Was Chosen for Puch.ai

While the TypeScript FastMCP server worked flawlessly for local and single-user scenarios, the **Python MCP implementation** was ultimately chosen for integration with Puch.ai due to:

- **Better Redis Integration:**  
  Python version uses Redis for fast, scalable, per-user data storage.
- **RBAC and User Isolation:**  
  Python MCP supports multi-user environments with role-based access control, critical for Puch.ai’s requirements.
- **Easier Extensibility:**  
  Python’s ecosystem and the MCP server’s design made it easier to add new features and integrate with Puch.ai’s agent workflows.
- **Production Readiness:**  
  The Python stack is more suitable for deployment, scaling, and integration with external platforms.

---

**Summary:**  
The TypeScript FastMCP server demonstrates a clean, feature-rich MCP backend, ideal for prototyping and single-user use. For production and Puch.ai integration, the Python MCP server with Redis and RBAC is the preferred solution. Both implementations are included for reference and comparison.