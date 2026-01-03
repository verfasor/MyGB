# Getting Started for Developers

This guide is designed for developers who want to run MyGB locally, or understand how the codebase works.

## Prerequisites

- **Node.js**: v24.x or later
- **npm**: v11.x or later
- **Cloudflare Account**: Required for D1 database and Workers deployment
- **Wrangler CLI**: Install globally via `npm install -g wrangler`

## Local Development Setup

### 1. Installation

Clone the repository and install dependencies (if any - currently the project is zero-dependency, but you might need `wrangler` locally):

```bash
npm install
```

### 2. Local Database Setup

This project uses Cloudflare D1. For local development, Wrangler simulates D1 using SQLite.

1.  **Create a local D1 database:**
    You don't strictly need to "create" it for local dev as Wrangler handles it, but ensuring the binding exists in `wrangler.toml` is key.

    Check `wrangler.toml`:
    ```toml
    [[d1_databases]]
    binding = "DB"
    database_name = "guestbook-db"
    database_id = "xxxx" # This ID is for production, local dev ignores it
    ```

2.  **Initialize Schema (Optional but recommended):**
    The application automatically creates tables (`entries` and `settings`) if they don't exist. However, you can manually apply the schema to start fresh:

    ```bash
    wrangler d1 execute guestbook-db --local --file=schema.sql
    ```

### 3. Running Locally

Start the local development server:

```bash
wrangler dev
```

- The app will be available at `http://localhost:8787`.
- Press `b` to open in browser.
- Press `d` to open the local D1 inspector.

## Architecture Overview

The entire application is contained in a single file: `worker.js`. This "monolithic worker" approach reduces complexity and deployment overhead.

### Key Components in `worker.js`

1.  **Request Handling (`fetch` event)**:
    - The `fetch` handler routes requests based on URL paths (`/api/submit`, `/admin`, `/`, etc.).
    - It handles CORS preflight requests automatically.

2.  **Database Interaction**:
    - Uses `env.DB` (D1 binding) for all SQL operations.
    - **Auto-Initialization**: The `getAppConfig` function checks for the `settings` table. If missing, it calls `initializeDatabase()` to create all necessary tables.

3.  **HTML Rendering**:
    - Functions like `getIndexHTML`, `getAdminHTML`, and `getLoginHTML` return Server-Side Rendered (SSR) HTML strings.
    - Template literals are used for lightweight templating.
    - **Security**: All user input is escaped using `escapeHtml()` before rendering to prevent XSS.

4.  **Authentication & Sessions**:
    - **Admin Auth**: Simple password check against `ADMIN_PASSWORD` env var.
    - **Sessions**: Uses HMAC-signed cookies (`gb_session`). The `sign` and `verify` functions use the Web Crypto API.
    - **CSRF Protection**: Checks `Origin` header on state-changing requests.

5.  **Client-Side Script (`getClientScript`)**:
    - Serves a dynamic JS file (`/client.js`) that handles the embed widget logic.
    - It is injected into the embed iframe or host page to render the guestbook form and entries.

### Database Schema

- **`entries`**: Stores guestbook messages.
    - `id`: Primary Key
    - `name`, `message`, `site`, `email`: User content
    - `approved`: Boolean (0 or 1) for moderation status
    - `created_at`: Timestamp
- **`settings`**: Key-value store for runtime configuration (Site name, Turnstile keys, etc.).

## Deployment

### 1. Create Production Database

If you haven't already:

```bash
wrangler d1 create guestbook-db
```

Copy the `database_id` output and paste it into `wrangler.toml`.

### 2. Configure Secrets

Set the required secrets for the production worker:

```bash
# Admin Password (Required)
wrangler secret put ADMIN_PASSWORD

# Session Secret
wrangler secret put SESSION_SECRET
```

### 3. Deploy

```bash
wrangler deploy
```

The application will automatically create the database tables on the first visit.

## CLI Command Reference

| Command | Description |
|---------|-------------|
| `wrangler dev` | Run locally with hot reload |
| `wrangler deploy` | Deploy to Cloudflare Workers |
| `wrangler d1 execute guestbook-db --local --file=schema.sql` | Reset/Apply schema locally |
| `wrangler d1 execute guestbook-db --remote --file=schema.sql` | Reset/Apply schema in production |
| `wrangler tail` | View real-time logs from production |
| `wrangler secret put <NAME>` | Set an encrypted environment variable |

## Customization

### Modifying CSS
You don't need to edit code to change basic styles. Go to `/admin/settings` and use the **Custom CSS** field.

### Modifying Logic
Edit `worker.js` directly.
- **New Routes**: Add `if (path === '/new-route')` blocks in the `fetch` handler.
- **New DB Tables**: Update `schema.sql` AND the `initializeDatabase` function in `worker.js`.
