import React from 'react'
import './App.css'

const MCPPostmanDocs = () => {
  return (
    <div className="docs-container">
      <header className="hero-section">
        <div className="hero-content">
          <h1 className="hero-title">🚀 MCP Postman Server</h1>
          <p className="hero-subtitle">
            A comprehensive Postman-like MCP (Model Context Protocol) server with user-based RBAC, 
            Redis backend, and full API testing capabilities.
          </p>
          <div className="server-info">
            <span className="info-badge">🛡️ Id: Each user unique and isolated data</span>
            <span className="info-badge">🔐 Auth: Bearer Token</span>
            <span className="info-badge">📊 Storage: Redis Backend</span>
          </div>
        </div>
      </header>

      <section className="features-section">
        <div className="container">
          <h2 className="section-title">✨ What We Provide Through MCP</h2>
          
          <div className="features-grid">

            <div className="feature-category">
              <div className="category-header">
                <h3>📁 Collection Management</h3>
                <p>Organize and manage your API request collections</p>
              </div>
              <div className="tools-list">
                <div className="tool-item">
                  <span className="tool-name">create_collection</span>
                  <span className="tool-desc">Build new collections with variables, auth, and scripting support</span>
                </div>
                <div className="tool-item">
                  <span className="tool-name">list_collections</span>
                  <span className="tool-desc">Browse all your organized collections with metadata</span>
                </div>
                <div className="tool-item">
                  <span className="tool-name">update_collection</span>
                  <span className="tool-desc">Modify collection properties, variables, and authentication</span>
                </div>
                <div className="tool-item">
                  <span className="tool-name">delete_collection</span>
                  <span className="tool-desc">Remove entire collections and all contained requests</span>
                </div>
                <div className="tool-item">
                  <span className="tool-name">get_collection_id</span>
                  <span className="tool-desc">Resolve collection names to unique identifiers</span>
                </div>
                <div className="tool-item">
                  <span className="tool-name">get_collection_name</span>
                  <span className="tool-desc">Retrieve collection names from system identifiers</span>
                </div>
              </div>
            </div>

            <div className="feature-category">
              <div className="category-header">
                <h3>📂 Folder Organization</h3>
                <p>Create hierarchical structures within collections</p>
              </div>
              <div className="tools-list">
                <div className="tool-item">
                  <span className="tool-name">add_folder</span>
                  <span className="tool-desc">Create nested folder structures for better organization</span>
                </div>
                <div className="tool-item">
                  <span className="tool-name">list_folders</span>
                  <span className="tool-desc">Display complete folder hierarchy with nested visualization</span>
                </div>
                <div className="tool-item">
                  <span className="tool-name">move_folder</span>
                  <span className="tool-desc">Reorganize folder structures across collections</span>
                </div>
                <div className="tool-item">
                  <span className="tool-name">get_folder_id</span>
                  <span className="tool-desc">Resolve folder names to unique identifiers</span>
                </div>
                <div className="tool-item">
                  <span className="tool-name">get_folder_name</span>
                  <span className="tool-desc">Retrieve folder names from system identifiers</span>
                </div>
              </div>
            </div>

            <div className="feature-category">
              <div className="category-header">
                <h3>🌐 Request Management</h3>
                <p>Create, execute, and manage HTTP requests with full customization</p>
              </div>
              <div className="tools-list">
                <div className="tool-item">
                  <span className="tool-name">add_request</span>
                  <span className="tool-desc">Create comprehensive API requests with headers, auth, and scripts</span>
                </div>
                <div className="tool-item">
                  <span className="tool-name">list_requests</span>
                  <span className="tool-desc">Browse and filter requests within collections or folders</span>
                </div>
                <div className="tool-item">
                  <span className="tool-name">update_request</span>
                  <span className="tool-desc">Modify existing requests with fine-grained control</span>
                </div>
                <div className="tool-item">
                  <span className="tool-name">delete_request</span>
                  <span className="tool-desc">Remove requests from collections with safety validations</span>
                </div>
              </div>
            </div>

            <div className="feature-category">
              <div className="category-header">
                <h3>⚙️ Environment & Variables</h3>
                <p>Manage different environments and global variables</p>
              </div>
              <div className="tools-list">
                <div className="tool-item">
                  <span className="tool-name">create_environment</span>
                  <span className="tool-desc">Configure environment-specific variables for different stages</span>
                </div>
                <div className="tool-item">
                  <span className="tool-name">list_environments</span>
                  <span className="tool-desc">View all configured environments with their variable sets</span>
                </div>
                <div className="tool-item">
                  <span className="tool-name">update_environment</span>
                  <span className="tool-desc">Modify environment variables with merge capabilities</span>
                </div>
                <div className="tool-item">
                  <span className="tool-name">delete_environment</span>
                  <span className="tool-desc">Remove environment configurations safely</span>
                </div>
                <div className="tool-item">
                  <span className="tool-name">set_globals</span>
                  <span className="tool-desc">Configure cross-request global variables</span>
                </div>
                <div className="tool-item">
                  <span className="tool-name">get_globals</span>
                  <span className="tool-desc">Retrieve all configured global variables</span>
                </div>
              </div>
            </div>

            <div className="feature-category">
              <div className="category-header">
                <h3>📊 Data & History</h3>
                <p>Track execution history and manage data import/export</p>
              </div>
              <div className="tools-list">
                <div className="tool-item">
                  <span className="tool-name">history</span>
                  <span className="tool-desc">Access detailed execution history with performance metrics</span>
                </div>
                <div className="tool-item">
                  <span className="tool-name">export_collection</span>
                  <span className="tool-desc">Generate Postman-compatible JSON exports for sharing</span>
                </div>
                <div className="tool-item">
                  <span className="tool-name">import_postman_collection</span>
                  <span className="tool-desc">Import existing Postman collections with full fidelity</span>
                </div>
                <div className="tool-item">
                  <span className="tool-name">validate</span>
                  <span className="tool-desc">Verify server connectivity and system status</span>
                </div>
              </div>
            </div>

            <div className="feature-category">
              <div className="category-header">
                <h3>👤 User Management & Security (implemented but no used until team collaboration not implemented)</h3>
                <p>Role-based access control with fine-grained permissions</p>
              </div>
              <div className="tools-list">
                <div className="tool-item">
                  <span className="tool-name">set_user_metadata</span>
                  <span className="tool-desc">Configure user roles and data classification (admin only)</span>
                </div>
                <div className="tool-item">
                  <span className="tool-name">get_my_metadata</span>
                  <span className="tool-desc">Retrieve your current permissions and role information</span>
                </div>
              </div>
              <div className="permissions-info">
                <h4>🔑 Role Permissions</h4>
                <div className="roles">
                  <span className="role admin">Admin: Full Access</span>
                  <span className="role editor">Editor: Create, Update, Delete, Read, Execute, Export</span>
                  <span className="role reader">Reader: Read, Export</span>
                  <span className="role tester">Tester: Read, Execute</span>
                </div>
              </div>
            </div>

          </div>
        </div>
      </section>

      <section className="capabilities-section">
        <div className="container">
          <h2 className="section-title">🎯 Key Capabilities</h2>
          <div className="capabilities-grid">
            <div className="capability-card">
              <div className="capability-icon">🔐</div>
              <h3>User-Based RBAC</h3>
              <p>Complete role-based access control with user namespacing and permission management</p>
            </div>
            <div className="capability-card">
              <div className="capability-icon">📊</div>
              <h3>Redis Backend</h3>
              <p>Scalable Redis storage with user-isolated data namespaces and real-time access</p>
            </div>
            <div className="capability-card">
              <div className="capability-icon">🔄</div>
              <h3>Postman Compatibility</h3>
              <p>Full import/export support for Postman collections with script preservation</p>
            </div>
            <div className="capability-card">
              <div className="capability-icon">🌍</div>
              <h3>Variable Management</h3>
              <p>Environment-specific and global variables with template resolution</p>
            </div>
            <div className="capability-card">
              <div className="capability-icon">📝</div>
              <h3>Script Support</h3>
              <p>Pre-request and test scripts for advanced request automation</p>
            </div>
            <div className="capability-card">
              <div className="capability-icon">🗂️</div>
              <h3>Hierarchical Organization</h3>
              <p>Nested folders and collections for structured API testing workflows</p>
            </div>
          </div>
        </div>
      </section>

      <section className="usage-section">
        <div className="container">
          <h2 className="section-title">🚀 How to Use</h2>
          <div className="usage-steps">
            <div className="step">
              <div className="step-number">1</div>
              <div className="step-content">
                <h3>Visit Our Platform</h3>
                <div className="link-section">
                  <a href="https://puch.ai/mcp/WoFsL1UMUc" target="_blank" rel="noopener noreferrer" className="platform-link">
                    🌐 Visit Puch.ai Platform
                  </a>
                </div>
                <p>Access our MCP server through the Puch.ai platform</p>
              </div>
            </div>
            <div className="step">
              <div className="step-number">2</div>
              <div className="step-content">
                <h3>Navigated to WhatsApp</h3>
                <div className="whatsapp-info">
                  <span className="whatsapp-icon">💬</span>
                  <p>Once on the platform, navigate to WhatsApp integration</p>
                </div>
              </div>
            </div>
            <div className="step">
              <div className="step-number">3</div>
              <div className="step-content">
                <h3>Chat with Our MCP Server</h3>
                <p>Start chatting and access all MCP tools directly through WhatsApp interface</p>
                <div className="features-highlight">
                  <span>✨ All 27 MCP tools available</span>
                  <span>🔐 Secure RBAC authentication</span>
                  <span>📊 Real-time Redis backend</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      <footer className="footer">
        <div className="container">
          <p>Built with FastMCP • Redis • Python • Bearer Token Authentication</p>
        </div>
      </footer>
    </div>
  )
}

function App() {
  return <MCPPostmanDocs />
}

export default App
