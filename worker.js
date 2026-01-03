// Guestbook Service for Cloudflare Workers
// Single file implementation with D1 database

// Session management
const SESSION_COOKIE_NAME = 'gb_session';
const SESSION_DURATION = 7 * 24 * 60 * 60 * 1000; // 7 days

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Access-Control-Max-Age': '86400'
};

const CLIENT_COMMON_JS = `
  function escapeHtml(text) {
    if (!text) return '';
    return String(text)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  function formatDateString(dateStr) {
    if (!dateStr) return '';
    const isoDate = dateStr.replace(' ', 'T') + (dateStr.includes('Z') ? '' : 'Z');
    const date = new Date(isoDate);
    if (isNaN(date.getTime())) return dateStr;
    return date.toLocaleString('en-US', { 
      month: 'short', day: 'numeric', year: 'numeric', 
      hour: 'numeric', minute: '2-digit' 
    });
  }

  function formatClientDates() {
    document.querySelectorAll('.client-date').forEach(el => {
      const dateStr = el.getAttribute('datetime');
      if (dateStr) el.textContent = formatDateString(dateStr);
      el.classList.remove('client-date');
    });
  }
  
  document.addEventListener('DOMContentLoaded', formatClientDates);
`;

async function sign(data, secret) {
  const encoder = new TextEncoder();
  const keyData = encoder.encode(secret);
  const key = await crypto.subtle.importKey(
    'raw', keyData, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const signature = await crypto.subtle.sign(
    'HMAC', key, encoder.encode(data)
  );
  // Use URL-safe base64 to avoid cookie issues
  return data + '.' + btoa(String.fromCharCode(...new Uint8Array(signature))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function verify(token, secret) {
  if (!token || !token.includes('.')) return null;
  const [data, signature] = token.split('.');
  // Re-sign the data to check if signature matches
  const expectedToken = await sign(data, secret);
  return expectedToken === token ? data : null;
}

async function createSessionToken(env) {
  const random = crypto.randomUUID();
  // Use SESSION_SECRET if available, otherwise fallback to ADMIN_PASSWORD
  const secret = env.SESSION_SECRET || env.ADMIN_PASSWORD || 'default-insecure-secret-god';
  return await sign(random, secret);
}

async function verifySession(request, env) {
  const cookie = request.headers.get('Cookie');
  if (!cookie) return null;
  
  const cookies = Object.fromEntries(
    cookie.split(';').map(c => c.trim().split('='))
  );
  const sessionToken = cookies[SESSION_COOKIE_NAME];
  if (!sessionToken) return null;
  
  const secret = env.SESSION_SECRET || env.ADMIN_PASSWORD || 'default-insecure-secret';
  return await verify(sessionToken, secret);
}

async function checkPassword(input, expected) {
  if (!input || !expected) return false;
  const encoder = new TextEncoder();
  // Hash both to ensure constant time comparison of hashes
  const inputHash = await crypto.subtle.digest('SHA-256', encoder.encode(input));
  const expectedHash = await crypto.subtle.digest('SHA-256', encoder.encode(expected));
  
  const inputArr = new Uint8Array(inputHash);
  const expectedArr = new Uint8Array(expectedHash);
  
  if (inputArr.length !== expectedArr.length) return false;
  
  let result = 0;
  for (let i = 0; i < inputArr.length; i++) {
    result |= inputArr[i] ^ expectedArr[i];
  }
  return result === 0;
}

function setSessionCookie(sessionToken) {
  const expires = new Date(Date.now() + SESSION_DURATION).toUTCString();
  return `${SESSION_COOKIE_NAME}=${sessionToken}; Path=/; HttpOnly; Secure; SameSite=Lax; Expires=${expires}`;
}

function clearSessionCookie() {
  return `${SESSION_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Expires=Thu, 01 Jan 1970 00:00:00 GMT`;
}

// Turnstile verification
async function verifyTurnstile(token, env) {
  if (!env.TURNSTILE_ENABLED) return true;
  
  const response = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      secret: env.TURNSTILE_SECRET_KEY,
      response: token,
    }),
  });
  
  const result = await response.json();
  return result.success === true;
}

const COMMON_CSS = `
    :root {
      --primary: #2563eb;
      --primary-hover: #1d4ed8;
      --bg: #f8fafc;
      --card-bg: #ffffff;
      --text: #1e293b;
      --text-muted: #64748b;
      --text-content: #334155;
      --border: #e2e8f0;
      --shadow: 0 1px 3px 0 rgb(0 0 0 / 0.1), 0 1px 2px -1px rgb(0 0 0 / 0.1);
      --success: #10b981;
      --warning: #f59e0b;
      --danger: #ef4444;
      --active-nav-bg: #eff6ff;
      --active-nav-color: var(--primary);
    }

    @media (prefers-color-scheme: dark) {
      :root {
        --primary: #60a5fa;
        --primary-hover: #93c5fd;
        --bg: #0f172a;
        --card-bg: #1e293b;
        --text: #f1f5f9;
        --text-muted: #94a3b8;
        --text-content: #e2e8f0;
        --border: #334155;
        --shadow: 0 4px 6px -1px rgb(0 0 0 / 0.5), 0 2px 4px -2px rgb(0 0 0 / 0.5);
        --active-nav-bg: #1e40af;
        --active-nav-color: #e0f2fe;
      }
      
      input, textarea {
        background-color: var(--card-bg) !important;
        color: var(--text) !important;
        border-color: var(--border) !important;
      }
      
      .entries-table th {
        background-color: #1e293b !important;
        color: var(--text-muted) !important;
        border-bottom-color: var(--border) !important;
      }
      
      .row-pending {
        background-color: #121b2b !important;
      }
      
      .badge-warning {
        background-color: #451a03 !important;
        color: #fcd34d !important;
      }
      
      .message-content {
        color: #e2e8f0 !important;
      }
      
      pre {
        background-color: #020617 !important;
        color: #e2e8f0 !important;
        border-color: var(--border) !important;
      }
      
      .entry-site:hover {
        background-color: #1e3a8a !important;
      }

      /* Dark mode overrides for mobile menu */
      @media (max-width: 768px) {
        .nav-links {
          background-color: var(--card-bg) !important;
          border-color: var(--border) !important;
        }
        .nav-links a:hover {
          background-color: var(--border) !important;
        }
      }
    }
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
      line-height: 1.5;
      color: var(--text);
      background: var(--bg);
      padding: 2rem 1rem;
    }
    .container {
      max-width: var(--container-width, 1000px);
      margin: 0 auto;
    }
    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 2rem;
      padding-bottom: 1rem;
      border-bottom: 1px solid var(--border);
    }
    h1 {
       font-size: 1.25rem;
       font-weight: 700;
       color: var(--text);
     }
    .nav-links a {
      color: var(--text-muted);
      text-decoration: none;
      font-size: 0.875rem;
      font-weight: 500;
      padding: 0.5rem 1rem;
      border-radius: 0.375rem;
      transition: all 0.2s;
      margin-left: 0.5rem;
    }
    .nav-links a:hover {
      background: var(--border);
      color: var(--text);
    }
    .nav-links a.active {
      background: var(--active-nav-bg);
      color: var(--active-nav-color);
    }
    .card {
      background: var(--card-bg);
      border-radius: 0.75rem;
      box-shadow: var(--shadow);
      border: 1px solid var(--border);
      overflow: hidden;
      margin-bottom: 2rem;
    }
    .form-group {
      margin-bottom: 1.5rem;
    }
    label {
      display: block;
      margin-bottom: 0.5rem;
      font-weight: 500;
      color: var(--text);
      font-size: 0.9375rem;
    }
    input[type="text"],
    input[type="email"],
    input[type="url"],
    input[type="password"],
    textarea {
      width: 100%;
      padding: 0.75rem 1rem;
      border: 1px solid var(--border);
      border-radius: 0.5rem;
      font-size: 1rem;
      transition: border-color 0.15s;
      background: #fff;
    }
    input:focus, textarea:focus {
      outline: none;
      border-color: var(--primary);
      box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.1);
    }
    button {
      background: var(--primary);
      color: white;
      border: none;
      padding: 0.75rem 1.5rem;
      border-radius: 0.5rem;
      cursor: pointer;
      font-size: 1rem;
      font-weight: 600;
      transition: background-color 0.15s;
    }
    button:hover {
      background: var(--primary-hover);
    }
    button:disabled {
      background: var(--text-muted);
      cursor: not-allowed;
      opacity: 0.7;
    }
    .message {
      padding: 1rem;
      border-radius: 0.5rem;
      margin-bottom: 1.5rem;
      font-size: 0.9375rem;
    }
    .message.success {
      background: #ecfdf5;
      color: #065f46;
      border: 1px solid #a7f3d0;
    }
    .message.error {
      background: #fef2f2;
      color: #991b1b;
      border: 1px solid #fecaca;
    }
    .text-muted { color: var(--text-muted); }
    .text-sm { font-size: 0.75rem; }

    .logout { 
      color: #ef4444 !important; 
    }
    .logout:hover { 
      background: #fef2f2 !important; 
    }
    /* Mobile Menu */
    .hamburger { display: none; background: none; border: none; font-size: 1.5rem; padding: 0.5rem; color: var(--text); cursor: pointer; }
    @media (max-width: 768px) {
      .hamburger { display: block; }
      .nav-links {
        display: none;
        position: absolute;
        top: 100%;
        left: 0;
        right: 0;
        background: var(--card-bg);
        border-bottom: 1px solid var(--border);
        flex-direction: column;
        padding: 1rem;
        box-shadow: var(--shadow);
        z-index: 50;
      }
      .nav-links.active { display: flex; }
      .nav-links a { margin: 0 0 0.5rem 0; display: block; text-align: center; padding: 0.75rem; }
      header { position: relative; }
    }
`;

function getHead(title, siteIcon, extraStyles = '', extraHead = '', noIndex = false) {
  let metaTags = '';
  if (noIndex) {
    metaTags += '<meta name="robots" content="noindex, nofollow">\n';
  }
  return `
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  ${metaTags}
  <title>${escapeHtml(title)}</title>
  <link rel="icon" href="${escapeHtml(siteIcon)}">
  <link rel="apple-touch-icon" href="${escapeHtml(siteIcon)}">
  <style>
    ${COMMON_CSS}
    ${extraStyles}
  </style>
  ${extraHead}
</head>`;
}

function getAdminHeader(activePage) {
  return `
    <header>
      <h1>Admin Panel</h1>
      <button class="hamburger" onclick="document.querySelector('.nav-links').classList.toggle('active')" aria-label="Toggle menu">☰</button>
      <div class="nav-links">
        <a href="/admin" class="${activePage === 'entries' ? 'active' : ''}">Entries</a>
        <a href="/admin/embed" class="${activePage === 'embed' ? 'active' : ''}">Embed</a>
        <a href="/admin/settings" class="${activePage === 'settings' ? 'active' : ''}">Settings</a>
        <a href="/" target="_blank">View Site</a>
        <a href="#" onclick="logout(); return false;" class="logout">Logout</a>
      </div>
    </header>`;
}

// Configuration Helpers
async function initializeDatabase(env) {
  try {
    const batch = [
      env.DB.prepare(`CREATE TABLE IF NOT EXISTS entries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        message TEXT NOT NULL,
        site TEXT,
        email TEXT,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        approved INTEGER NOT NULL DEFAULT 0
      )`),
      env.DB.prepare(`CREATE INDEX IF NOT EXISTS idx_approved ON entries(approved)`),
      env.DB.prepare(`CREATE INDEX IF NOT EXISTS idx_created_at ON entries(created_at)`),
      env.DB.prepare(`CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT
      )`)
    ];
    await env.DB.batch(batch);
    console.log('Database initialized');
  } catch (e) {
    console.error('Failed to initialize database', e);
  }
}

async function getAppConfig(env) {
  // Initialize defaults from env
  const config = {
    SITENAME: env.SITENAME || 'Guestbook',
    SITE_INTRO: env.SITE_INTRO || 'A simple guestbook powered by Cloudflare Workers. You can edit this in /admin/settings.',
    SITE_DESCRIPTION: env.SITE_DESCRIPTION || 'A simple guestbook powered by Cloudflare Workers.',
    SITE_ICON_URL: env.SITE_ICON_URL || 'https://static.mighil.com/images/2026/gb.webp',
    SITE_COVER_IMAGE_URL: env.SITE_COVER_IMAGE_URL || '',
    NAV_LINKS: env.NAV_LINKS || '[]',
    CANONICAL_URL: env.CANONICAL_URL || '',
    ALLOW_INDEXING: env.ALLOW_INDEXING !== 'false',
    TURNSTILE_ENABLED: env.TURNSTILE_ENABLED !== 'false',
    TURNSTILE_SITE_KEY: env.TURNSTILE_SITE_KEY || '',
    TURNSTILE_SECRET_KEY: env.TURNSTILE_SECRET_KEY || '',
    ENTRY_MODERATION: env.ENTRY_MODERATION !== 'false',
    CUSTOM_CSS: env.CUSTOM_CSS || '',
    // These remain cloudflare-main-env-only
    ADMIN_PASSWORD: env.ADMIN_PASSWORD,
    SESSION_SECRET: env.SESSION_SECRET,
    DB: env.DB,
    API_URL: env.API_URL
  };

  try {
    // Try to fetch settings from DB
    const settings = await env.DB.prepare('SELECT key, value FROM settings').all();
    if (settings.results) {
      settings.results.forEach(row => {
        if (row.key === 'TURNSTILE_ENABLED' || row.key === 'ENTRY_MODERATION' || row.key === 'ALLOW_INDEXING') {
           config[row.key] = row.value === 'true';
        } else {
           config[row.key] = row.value;
        }
      });
    }
  } catch (e) {
    // Table might not exist yet, try to initialize
    await initializeDatabase(env);
  }

  return config;
}

async function saveAppSettings(env, settings) {
  // Ensure table exists (lazy init)
  try {
    await env.DB.prepare('CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)').run();
  } catch (e) {
    console.error('Failed to create settings table', e);
  }

  const stmt = env.DB.prepare('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)');
  const batch = [];
  
  for (const [key, value] of Object.entries(settings)) {
    batch.push(stmt.bind(key, String(value)));
  }
  
  await env.DB.batch(batch);
}

function getSettingsHTML(config) {
  const sitename = config.SITENAME || 'Guestbook';
  const siteIcon = config.SITE_ICON_URL || 'https://static.mighil.com/images/2026/gb.webp';
  
  const extraStyles = `
    .help-text { font-size: 0.875rem; color: var(--text-muted); margin-top: 0.25rem; }
    .checkbox-group { display: flex; align-items: center; gap: 0.75rem; }
    .checkbox-group input { width: 1rem; height: 1rem; margin: 0; cursor: pointer; }
    .checkbox-group label { margin-bottom: 0; cursor: pointer; font-weight: 400; }
    .btn-export {
      text-decoration: none;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      padding: 0.5rem 1rem;
      border: 1px solid var(--border);
      border-radius: 0.375rem;
      color: var(--text);
      background: var(--card-bg);
      font-size: 0.875rem;
      font-weight: 500;
      transition: background 0.15s;
    }
    .btn-export:hover {
      background: var(--border);
    }
    .card-header {
      padding: 1.25rem 1.5rem;
      border-bottom: 1px solid var(--border);
    }
    .card-header h3 {
      margin: 0;
      font-size: 1.125rem;
      font-weight: 600;
    }
    .card-body {
      padding: 1.5rem;
    }
  `;

  return `<!DOCTYPE html>
<html lang="en">
${getHead('Settings - ' + sitename, siteIcon, extraStyles + (config.CUSTOM_CSS || ''), '', true)}
<body>
  <div class="container">
    ${getAdminHeader('settings')}
    
    <div id="message-container"></div>
    
    <form id="settings-form">
      <!-- General Settings -->
      <div class="card">
        <div class="card-header">
          <h3>General</h3>
        </div>
        <div class="card-body">
          <div class="form-group">
            <label for="SITENAME">Site Name</label>
            <input type="text" id="SITENAME" name="SITENAME" value="${escapeHtml(config.SITENAME)}">
            <div class="help-text">Used as the page title.</div>
          </div>
          <div class="form-group">
            <label for="SITE_INTRO">Site Intro</label>
            <textarea id="SITE_INTRO" name="SITE_INTRO" rows="3" style="width: 100%; box-sizing: border-box;">${escapeHtml(config.SITE_INTRO || '')}</textarea>
            <div class="help-text">Displayed on the home page above the form. Supports basic HTML.</div>
          </div>
          <div class="form-group">
            <label for="SITE_DESCRIPTION">Site Description</label>
            <textarea id="SITE_DESCRIPTION" name="SITE_DESCRIPTION" rows="2" style="width: 100%; box-sizing: border-box;">${escapeHtml(config.SITE_DESCRIPTION || '')}</textarea>
            <div class="help-text">Used for meta description and social media cards.</div>
          </div>
          <div class="form-group">
            <label for="SITE_ICON_URL">Site Icon URL</label>
            <input type="url" id="SITE_ICON_URL" name="SITE_ICON_URL" value="${escapeHtml(config.SITE_ICON_URL)}">
            <div class="help-text">URL to your site's favicon or logo (square recommended).</div>
          </div>
          <div class="form-group">
            <label for="SITE_COVER_IMAGE_URL">Site Cover Image URL</label>
            <input type="url" id="SITE_COVER_IMAGE_URL" name="SITE_COVER_IMAGE_URL" value="${escapeHtml(config.SITE_COVER_IMAGE_URL || '')}">
            <div class="help-text">URL to an image used for social media sharing (Open Graph / Twitter). Recommended size: 1200x630.</div>
          </div>
          <div class="form-group">
            <label for="CANONICAL_URL">Canonical URL</label>
            <input type="url" id="CANONICAL_URL" name="CANONICAL_URL" value="${escapeHtml(config.CANONICAL_URL || '')}">
            <div class="help-text">The authoritative URL for your guestbook. Useful if you embed the guestbook on another site.</div>
          </div>
          <div class="checkbox-group" style="margin-top: 1rem;">
            <input type="checkbox" id="ALLOW_INDEXING" name="ALLOW_INDEXING" ${config.ALLOW_INDEXING ? 'checked' : ''}>
            <label for="ALLOW_INDEXING">Allow Search Engine Indexing</label>
          </div>
          <div class="help-text">If unchecked, adds <code>noindex, nofollow</code> to prevent search engines from indexing this page.</div>
        </div>
      </div>
      
      <!-- Navigation Settings -->
      <div class="card">
        <div class="card-header">
          <h3>Navigation</h3>
        </div>
        <div class="card-body">
          <p class="text-muted" style="margin-bottom: 1rem; font-size: 0.875rem;">Add links to your main website or other pages. These will appear in the header.</p>
          <div id="nav-links-container"></div>
          <button type="button" id="add-link-btn" style="margin-top: 1rem; background: var(--card-bg); color: var(--text); border: 1px dashed var(--border); width: auto;">+ Add Link</button>
          <input type="hidden" id="NAV_LINKS" name="NAV_LINKS" value="${escapeHtml(config.NAV_LINKS || '[]')}">
        </div>
      </div>
      
      <!-- Moderation Settings -->
      <div class="card">
        <div class="card-header">
          <h3>Moderation</h3>
        </div>
        <div class="card-body">
          <div class="checkbox-group">
            <input type="checkbox" id="ENTRY_MODERATION" name="ENTRY_MODERATION" ${config.ENTRY_MODERATION ? 'checked' : ''}>
            <label for="ENTRY_MODERATION">Require approval for new entries</label>
          </div>
          <div class="help-text">If checked, entries will not appear publicly until you approve them.</div>
        </div>
      </div>
      
      <!-- Security Settings -->
      <div class="card">
        <div class="card-header">
          <h3>Security (Cloudflare Turnstile)</h3>
        </div>
        <div class="card-body">
          <div class="checkbox-group" style="margin-bottom: 1rem;">
            <input type="checkbox" id="TURNSTILE_ENABLED" name="TURNSTILE_ENABLED" ${config.TURNSTILE_ENABLED ? 'checked' : ''}>
            <label for="TURNSTILE_ENABLED">Enable Turnstile CAPTCHA</label>
          </div>
          
          <div class="form-group">
            <label for="TURNSTILE_SITE_KEY">Site Key</label>
            <input type="text" id="TURNSTILE_SITE_KEY" name="TURNSTILE_SITE_KEY" value="${escapeHtml(config.TURNSTILE_SITE_KEY)}">
          </div>
          <div class="form-group">
            <label for="TURNSTILE_SECRET_KEY">Secret Key</label>
            <input type="password" id="TURNSTILE_SECRET_KEY" name="TURNSTILE_SECRET_KEY" value="${escapeHtml(config.TURNSTILE_SECRET_KEY)}">
            <div class="help-text">Keep this secret! It's used to verify tokens.</div>
          </div>
        </div>
      </div>

      <!-- Appearance Settings -->
      <div class="card">
        <div class="card-header">
          <h3>Appearance</h3>
        </div>
        <div class="card-body">
          <div class="form-group">
            <label for="CUSTOM_CSS">Custom CSS</label>
            <textarea id="CUSTOM_CSS" name="CUSTOM_CSS" placeholder=".container { max-width: 800px; } /* Target classes like .entry, .card, .btn */" style="font-family: monospace; min-height: 150px; width: 100%; box-sizing: border-box;">${escapeHtml(config.CUSTOM_CSS || '')}</textarea>
            <div class="help-text">
              Add custom CSS to style both the guestbook and admin UI. 
              <br><strong>Common targets:</strong> <code>.container</code>, <code>.card</code>, <code>.entry</code>, <code>.entry-header</code>, <code>.entry-content</code>, <code>button</code>.
            </div>
          </div>
        </div>
      </div>

      <!-- Export Data -->
      <div class="card">
        <div class="card-header">
          <h3>Export Data</h3>
        </div>
        <div class="card-body">
          <p class="text-muted" style="margin-bottom: 1rem; font-size: 0.875rem;">Download your guestbook data. Email addresses are excluded from these public exports.</p>
          <div style="display: flex; gap: 1rem;">
            <a href="/data.json" target="_blank" class="btn-export">Download JSON</a>
            <a href="/data.csv" target="_blank" class="btn-export">Download CSV</a>
          </div>
        </div>
      </div>
      
      <div style="position: sticky; bottom: 1rem; z-index: 10;">
        <button type="submit" style="width: 100%; padding: 0.75rem 1.5rem; box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1), 0 2px 4px -2px rgb(0 0 0 / 0.1);">Save Settings</button>
      </div>
    </form>
  </div>
  
  <script>
    // Navigation Links Management
    const navLinksInput = document.getElementById('NAV_LINKS');
    const navLinksContainer = document.getElementById('nav-links-container');
    const addLinkBtn = document.getElementById('add-link-btn');
    
    let navLinks = [];
    try {
      navLinks = JSON.parse(navLinksInput.value || '[]');
    } catch (e) {
      navLinks = [];
    }

    function renderNavLinks() {
      navLinksContainer.innerHTML = '';
      if (navLinks.length === 0) {
        navLinksContainer.innerHTML = '<p class="text-muted" style="font-style: italic; font-size: 0.875rem;">No links added yet.</p>';
      }
      navLinks.forEach((link, index) => {
        const row = document.createElement('div');
        row.style.cssText = 'display: flex; gap: 0.5rem; margin-bottom: 0.5rem; align-items: center;';
        // Simple escape for attribute values
        const safeLabel = (link.label || '').replace(/"/g, '&quot;');
        const safeUrl = (link.url || '').replace(/"/g, '&quot;');
        
        row.innerHTML = 
          '<input type="text" placeholder="Label" value="' + safeLabel + '" data-index="' + index + '" data-key="label" class="nav-link-input" style="flex: 1;">' +
          '<input type="url" placeholder="URL" value="' + safeUrl + '" data-index="' + index + '" data-key="url" class="nav-link-input" style="flex: 2;">' +
          '<button type="button" data-index="' + index + '" class="remove-link-btn" style="padding: 0.5rem 0.75rem; background: #fee2e2; color: #dc2626; border: 1px solid #fecaca; border-radius: 0.375rem; cursor: pointer; width: auto; font-weight: bold;">&times;</button>';
        navLinksContainer.appendChild(row);
      });
    }

    function updateHiddenInput() {
      navLinksInput.value = JSON.stringify(navLinks);
    }

    // Event delegation for inputs
    navLinksContainer.addEventListener('input', (e) => {
      if (e.target.classList.contains('nav-link-input')) {
        const index = parseInt(e.target.dataset.index);
        const key = e.target.dataset.key;
        navLinks[index][key] = e.target.value;
        updateHiddenInput();
      }
    });

    // Event delegation for remove buttons
    navLinksContainer.addEventListener('click', (e) => {
      if (e.target.classList.contains('remove-link-btn')) {
        const index = parseInt(e.target.dataset.index);
        navLinks.splice(index, 1);
        renderNavLinks();
        updateHiddenInput();
      }
    });

    addLinkBtn.addEventListener('click', () => {
      navLinks.push({ label: '', url: '' });
      renderNavLinks();
      updateHiddenInput();
    });

    renderNavLinks();

    document.getElementById('settings-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const form = e.target;
      const button = form.querySelector('button[type="submit"]');
      const messageContainer = document.getElementById('message-container');
      const formData = new FormData(form);
      
      button.disabled = true;
      button.textContent = 'Saving...';
      
      try {
        const response = await fetch('/api/settings', {
          method: 'POST',
          body: formData
        });
        
        const result = await response.json();
        
        if (result.success) {
          messageContainer.innerHTML = '<div class="message success">Settings saved successfully. Reloading...</div>';
          setTimeout(() => location.reload(), 1000);
        } else {
          messageContainer.innerHTML = '<div class="message error">' + (result.error || 'Failed to save settings') + '</div>';
        }
      } catch (error) {
        messageContainer.innerHTML = '<div class="message error">An error occurred. Please try again.</div>';
      } finally {
        button.disabled = false;
        button.textContent = 'Save Settings';
      }
    });
    
    async function logout() {
      try {
        await fetch('/logout', { method: 'POST' });
        window.location.href = '/login';
      } catch (error) {
        window.location.href = '/login';
      }
    }
  </script>
</body>
</html>`;
}

// HTML templates
function getIndexHTML(entries, env, currentHostname) {
  const sitename = env.SITENAME || 'Guestbook';
  // Ensure turnstileSiteKey is always a primitive string (not String object)
  let turnstileSiteKey = env.TURNSTILE_SITE_KEY;
  if (typeof turnstileSiteKey !== 'string') {
    turnstileSiteKey = String(turnstileSiteKey || '');
  }
  // Ensure it's a primitive string, not a String object
  turnstileSiteKey = '' + turnstileSiteKey;
  
  const entriesHTML = entries.length === 0 
    ? `<div class="empty-state"><img src="${escapeHtml(env.SITE_ICON_URL || 'https://static.mighil.com/images/2026/gb.webp')}" alt="Guestbook" class="empty-icon-img" width="64" height="64"><p>No entries yet. Be the first to sign!</p></div>`
    : entries.map(entry => `
      <div class="entry">
        <div class="entry-header">
          <div class="entry-avatar">${escapeHtml(entry.name).charAt(0).toUpperCase()}</div>
          <div class="entry-meta">
            <strong class="entry-name">
              ${entry.site 
                ? `<a href="${escapeHtml(entry.site)}${entry.site.includes('?') ? '&' : '?'}via=${escapeHtml(currentHostname || '')}" target="_blank" rel="nofollow" class="name-link">${escapeHtml(entry.name)}</a>` 
                : escapeHtml(entry.name)
              }
            </strong>
            <span class="entry-date client-date" datetime="${entry.created_at}">${formatDate(entry.created_at)}</span>
          </div>
        </div>
        <div class="entry-content">${escapeHtml(entry.message).replace(/\n/g, '<br>')}</div>
      </div>
    `).join('');
  
  const siteIcon = env.SITE_ICON_URL || 'https://static.mighil.com/images/2026/gb.webp';
  
  // Meta tags
   const siteDescription = env.SITE_DESCRIPTION || 'A simple guestbook powered by Cloudflare Workers.';
   const siteCoverImage = env.SITE_COVER_IMAGE_URL || '';
   const canonicalUrl = env.CANONICAL_URL || '';
   const allowIndexing = env.ALLOW_INDEXING !== false; // Default to true
   
   let extraHead = '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit" async defer></script><script>' + CLIENT_COMMON_JS + '</script>';
   
   if (!allowIndexing) {
     extraHead += `
   <meta name="robots" content="noindex, nofollow">`;
   }
   
   if (canonicalUrl) {
     extraHead += `
   <link rel="canonical" href="${escapeHtml(canonicalUrl)}">`;
   }
   
   if (siteDescription) {
     extraHead += `
   <meta name="description" content="${escapeHtml(siteDescription)}">`;
   }
  
  extraHead += `
  <meta property="og:title" content="${escapeHtml(sitename)}">`;

  if (siteDescription) {
    extraHead += `
  <meta property="og:description" content="${escapeHtml(siteDescription)}">`;
  }

  if (siteCoverImage) {
    extraHead += `
  <meta property="og:image" content="${escapeHtml(siteCoverImage)}">`;
  }

  extraHead += `
  <meta name="twitter:title" content="${escapeHtml(sitename)}">`;

  if (siteDescription) {
    extraHead += `
  <meta name="twitter:description" content="${escapeHtml(siteDescription)}">`;
  }
  
  if (siteCoverImage) {
    extraHead += `
  <meta name="twitter:image" content="${escapeHtml(siteCoverImage)}">
  <meta name="twitter:card" content="summary_large_image">`;
  } else {
    extraHead += `
  <meta name="twitter:card" content="summary">`;
  }
  
  let navLinks = [];
  try {
    navLinks = JSON.parse(env.NAV_LINKS || '[]');
  } catch (e) {
    navLinks = [];
  }
  
  const navLinksHTML = navLinks.length > 0 ? `
    <nav class="header-nav">
      ${navLinks.map(link => `<a href="${escapeHtml(link.url)}" class="nav-link">${escapeHtml(link.label)}</a>`).join('')}
    </nav>` : '';
  
  const extraStyles = `
    .container { max-width: 700px; }
    h1 { font-size: 1.5rem; letter-spacing: -0.025em; }
    .header-nav { display: flex; gap: 1rem; align-items: center; }
    .nav-link { color: var(--text-muted); text-decoration: none; font-size: 0.9375rem; font-weight: 500; transition: color 0.2s; }
    .nav-link:hover { color: var(--primary); }
    .card { padding: 2rem; }
    .turnstile-container { margin: 1.5rem 0; min-height: 65px; }
    button { width: 100%; }
    textarea { min-height: 120px; resize: vertical; }
    h2 {
      font-size: 1.5rem;
      font-weight: 600;
      margin-bottom: 1.5rem;
      color: var(--text);
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }
    .entry {
      background: var(--card-bg);
      border-radius: 0.75rem;
      padding: 1.5rem;
      margin-bottom: 1rem;
      border: 1px solid var(--border);
      box-shadow: var(--shadow);
    }
    .entry-header {
      display: flex;
      align-items: center;
      gap: 1rem;
      margin-bottom: 1rem;
    }
    .entry-avatar {
      width: 40px;
      height: 40px;
      background: linear-gradient(135deg, var(--primary), #60a5fa);
      color: white;
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: 600;
      font-size: 1.125rem;
      flex-shrink: 0;
    }
    .entry-meta { flex: 1; display: flex; flex-direction: column; }
    .entry-name { color: var(--text); font-size: 1rem; }
    .name-link { color: var(--text); text-decoration: none; transition: color 0.2s; }
    .name-link:hover { color: var(--primary); text-decoration: underline; }
    .entry-date { color: var(--text-muted); font-size: 0.75rem; }
    .entry-site {
      color: var(--text-muted);
      text-decoration: none;
      font-size: 1.25rem;
      padding: 0.25rem;
      border-radius: 0.25rem;
      transition: all 0.2s;
    }
    .entry-site:hover { color: var(--primary); background: #eff6ff; }
    .entry-content {
      color: var(--text-content);
      line-height: 1.625;
      font-size: 0.9375rem;
      padding-left: 3.5rem;
    }
    .empty-state { text-align: center; padding: 4rem 2rem; color: var(--text-muted); }
    .empty-icon { font-size: 3rem; margin-bottom: 1rem; }
    @media (max-width: 640px) {
      .entry-content { padding-left: 0; margin-top: 1rem; }
    }
  `;

  return `<!DOCTYPE html>
<html lang="en">
${getHead(sitename, siteIcon, extraStyles + (env.CUSTOM_CSS || ''), extraHead)}
<body>
  <div class="container">
    <header>
      <h1 class="site-name">${escapeHtml(sitename)}</h1>
      ${navLinksHTML}
    </header>
    
    <div class="card">
      ${env.SITE_INTRO ? `<div style="margin-bottom: 1.5rem; color: var(--text); line-height: 1.6;">${env.SITE_INTRO}</div>` : ''}
      <form id="guestbook-form">
        <div class="form-group">
          <label for="name">Name</label>
          <input type="text" id="name" name="name" required placeholder="Your name">
        </div>
        <div class="form-group">
          <label for="email">Email <span style="color:var(--text-muted);font-weight:400">(optional, private)</span></label>
          <input type="email" id="email" name="email" placeholder="you@example.com">
        </div>
        <div class="form-group">
          <label for="site">Website <span style="color:var(--text-muted);font-weight:400">(optional)</span></label>
          <input type="url" id="site" name="site" placeholder="https://example.com">
        </div>
        <div class="form-group">
          <label for="message">Message</label>
          <textarea id="message" name="message" required placeholder="Leave a message..."></textarea>
        </div>
        ${env.TURNSTILE_ENABLED ? `<div class="turnstile-container">
          <div class="cf-turnstile"></div>
        </div>` : ''}
        <button type="button" id="submit-btn">Post Message</button>
      </form>
      <div id="message-container" style="margin-top: 1rem"></div>
    </div>
    
    <div class="entries-section">
      <h2 style="font-size: 1.25rem; color: var(--text-muted); margin-bottom: 1rem; display: flex; align-items: center; gap: 0.5rem;">
        <span>Guestbook Entries</span>
      </h2>
      <div id="entries-container">
        ${entriesHTML}
      </div>
      <div id="load-more-container" style="text-align: center; margin-top: 2rem; display: ${entries.length >= 20 ? 'block' : 'none'};">
        <button id="load-more-btn" style="background: var(--card-bg); color: var(--text); border: 1px solid var(--border); padding: 0.5rem 1rem; border-radius: 0.5rem; cursor: pointer; font-size: 0.875rem;" data-cursor="${entries.length > 0 ? entries[entries.length - 1].id : ''}">Load More</button>
      </div>
    </div>

    <footer style="text-align: center; margin-top: 3rem; padding-top: 1.5rem; border-top: 1px solid var(--border); color: var(--text-muted); font-size: 0.875rem;">
      <p style="margin-bottom: 0.5rem;">Powered by <a href="https://mighil.com/mygb" target="_blank" rel="noopener noreferrer" style="color: inherit; text-decoration: underline;">MyGB</a></p>
      <p style="margin: 0;"><a href="https://github.com/verfasor/mygb" target="_blank" rel="noopener noreferrer" style="color: inherit; text-decoration: underline;">Source</a> available under GNU AGPL v3</p>
    </footer>
  </div>
  
  <script>
    let turnstileWidgetId = null;
    let turnstileReady = false;
    let isSubmitting = false;
    const TURNSTILE_SITE_KEY = ${turnstileSiteKey ? JSON.stringify(String(turnstileSiteKey)) : '""'};
    const TURNSTILE_ENABLED = ${env.TURNSTILE_ENABLED};
    
    // Load More functionality
    const loadMoreBtn = document.getElementById('load-more-btn');
    const entriesContainer = document.getElementById('entries-container');
    
    if (loadMoreBtn) {
      loadMoreBtn.addEventListener('click', async () => {
        const cursor = loadMoreBtn.getAttribute('data-cursor');
        loadMoreBtn.disabled = true;
        loadMoreBtn.textContent = 'Loading...';
        
        try {
          const response = await fetch('/api/entries?cursor=' + cursor);
          const data = await response.json();
          
          if (data.success && data.entries.length > 0) {
            data.entries.forEach(entry => {
              const entryHtml = \`
                <div class="entry">
                  <div class="entry-header">
                    <div class="entry-avatar">\${escapeHtml(entry.name).charAt(0).toUpperCase()}</div>
                    <div class="entry-meta">
                      <strong class="entry-name">
                        \${entry.site 
                          ? '<a href="' + escapeHtml(entry.site) + (entry.site.includes('?') ? '&' : '?') + 'via=' + escapeHtml(window.location.hostname) + '" target="_blank" rel="nofollow" class="name-link">' + escapeHtml(entry.name) + '</a>' 
                          : escapeHtml(entry.name)
                        }
                      </strong>
                      <span class="entry-date client-date" datetime="\${entry.created_at}">\${formatDateString(entry.created_at)}</span>
                    </div>
                  </div>
                  <div class="entry-content">\${escapeHtml(entry.message).replace(/\\n/g, '<br>')}</div>
                </div>
              \`;
              entriesContainer.insertAdjacentHTML('beforeend', entryHtml);
            });
            
            if (data.nextCursor) {
              loadMoreBtn.setAttribute('data-cursor', data.nextCursor);
              loadMoreBtn.disabled = false;
              loadMoreBtn.textContent = 'Load More';
            } else {
              loadMoreBtn.style.display = 'none';
            }
          } else {
            loadMoreBtn.style.display = 'none';
          }
        } catch (error) {
          console.error('Error loading more entries:', error);
          loadMoreBtn.disabled = false;
          loadMoreBtn.textContent = 'Load More';
        }
      });
    }


    
    // Render Turnstile automatically
    function renderTurnstile() {
      if (!TURNSTILE_ENABLED) return null;
      
      if (turnstileWidgetId !== null || !window.turnstile) {
        return turnstileWidgetId;
      }
      
      // Ensure sitekey is a valid non-empty string
      if (!TURNSTILE_SITE_KEY || typeof TURNSTILE_SITE_KEY !== 'string' || TURNSTILE_SITE_KEY === '') {
        console.error('Turnstile site key is missing or invalid. Type:', typeof TURNSTILE_SITE_KEY, 'Value:', TURNSTILE_SITE_KEY);
        return null;
      }
      
      const container = document.querySelector('.cf-turnstile');
      if (container) {
        try {
          // Ensure it's definitely a string
          const siteKeyStr = String(TURNSTILE_SITE_KEY);
          turnstileWidgetId = window.turnstile.render(container, {
            sitekey: siteKeyStr,
            theme: 'auto',
            callback: function(token) {
              // Store token but don't auto-submit
              // We'll submit when user clicks the button
            }
          });
          return turnstileWidgetId;
        } catch (error) {
          console.error('Turnstile render error:', error);
          return null;
        }
      }
      return null;
    }
    
    // Wait for Turnstile script to load and then render
    function waitForTurnstile() {
      if (window.turnstile) {
        turnstileReady = true;
        renderTurnstile();
        return;
      }
      
      window.addEventListener('load', () => {
        const checkTurnstile = setInterval(() => {
          if (window.turnstile) {
            clearInterval(checkTurnstile);
            turnstileReady = true;
            renderTurnstile();
          }
        }, 100);
        // Timeout after 5 seconds
        setTimeout(() => clearInterval(checkTurnstile), 5000);
      });
    }
    
    waitForTurnstile();
    
    async function submitForm(token) {
      // Prevent multiple simultaneous submissions
      if (isSubmitting) {
        return;
      }
      
      isSubmitting = true;
      const form = document.getElementById('guestbook-form');
      const button = document.getElementById('submit-btn');
      const messageContainer = document.getElementById('message-container');
      
      if (!button) {
        console.error('Submit button not found');
        isSubmitting = false;
        return;
      }
      
      button.disabled = true;
      button.textContent = 'Submitting...';
      
      const formData = new FormData(form);
      formData.append('cf-turnstile-response', token);
      
      try {
        const response = await fetch('/api/submit', {
          method: 'POST',
          body: formData
        });
        
        const result = await response.json();
        
        if (result.success) {
          const successMsg = result.approved 
            ? 'Thank you! Your entry has been submitted.' 
            : 'Thank you! Your entry will be visible after moderation.';
          messageContainer.innerHTML = '<div class="message success">' + successMsg + '</div>';
          form.reset();
          // Don't reset turnstile if we're reloading - just reload immediately
          setTimeout(() => location.reload(), 4000);
          // Don't reset isSubmitting since we're reloading
          return;
        } else {
          messageContainer.innerHTML = '<div class="message error">' + (result.error || 'Failed to submit entry. Please try again.') + '</div>';
          if (window.turnstile && turnstileWidgetId !== null) {
            window.turnstile.reset(turnstileWidgetId);
          }
        }
      } catch (error) {
        messageContainer.innerHTML = '<div class="message error">An error occurred. Please try again.</div>';
        if (window.turnstile && turnstileWidgetId !== null) {
          window.turnstile.reset(turnstileWidgetId);
        }
      } finally {
        isSubmitting = false;
        button.disabled = false;
        button.textContent = 'Submit';
      }
    }
    
    // Handle button click instead of form submit to prevent Enter key from triggering
    document.getElementById('submit-btn').addEventListener('click', async () => {
      // Prevent multiple clicks
      if (isSubmitting) {
        return;
      }
      
      const form = document.getElementById('guestbook-form');
      
      // Validate form
      if (!form.checkValidity()) {
        form.reportValidity();
        return;
      }

      if (!TURNSTILE_ENABLED) {
        submitForm('disabled');
        return;
      }
      
      // Get Turnstile response
      const token = window.turnstile ? window.turnstile.getResponse(turnstileWidgetId) : null;
      
      if (!token) {
        const messageContainer = document.getElementById('message-container');
        messageContainer.innerHTML = '<div class="message error">Please verify you are human.</div>';
        return;
      }
      
      submitForm(token);
    });
    
    // Prevent form submission on Enter key
    document.getElementById('guestbook-form').addEventListener('submit', (e) => {
      e.preventDefault();
    });
    
    // Format dates to client timezone
    function formatClientDates() {
      document.querySelectorAll('.client-date').forEach(el => {
        const dateStr = el.getAttribute('datetime');
        if (!dateStr) return;
        
        // Fix for SQLite date format (YYYY-MM-DD HH:MM:SS) to ISO (YYYY-MM-DDTHH:MM:SSZ)
        // Assume UTC if no timezone specified
        const isoDate = dateStr.replace(' ', 'T') + (dateStr.includes('Z') ? '' : 'Z');
        
        const date = new Date(isoDate);
        if (isNaN(date.getTime())) return;
        
        el.textContent = date.toLocaleString('en-US', { 
          month: 'short', 
          day: 'numeric', 
          year: 'numeric', 
          hour: 'numeric', 
          minute: '2-digit' 
        });
      });
    }
    formatClientDates();
  </script>
</body>
</html>`;
}

function getLoginHTML(env) {
  const sitename = env.SITENAME || 'Guestbook';
  const siteIcon = env.SITE_ICON_URL || 'https://static.mighil.com/images/2026/gb.webp';
  
  const extraStyles = `
    body { display: flex; justify-content: center; align-items: center; min-height: 100vh; padding: 1rem; }
    .login-container {
      background: var(--card-bg);
      padding: 2.5rem;
      border-radius: 1rem;
      box-shadow: var(--shadow);
      width: 100%;
      max-width: 400px;
      border: 1px solid var(--border);
    }
    .brand { text-align: center; margin-bottom: 2rem; }
    .brand-icon { font-size: 3rem; margin-bottom: 0.5rem; display: inline-block; }
    h1 { margin-bottom: 0.5rem; font-size: 1.5rem; }
    .subtitle { color: var(--text-muted); font-size: 0.875rem; }
    button { width: 100%; padding: 0.75rem; }
    .message { text-align: center; padding: 0.75rem; }
    .back-link {
      display: block;
      text-align: center;
      margin-top: 1.5rem;
      color: var(--text-muted);
      text-decoration: none;
      font-size: 0.875rem;
      transition: color 0.2s;
    }
    .back-link:hover { color: var(--primary); }
  `;
  
  return `<!DOCTYPE html>
<html lang="en">
${getHead('Login - ' + sitename, siteIcon, extraStyles + (env.CUSTOM_CSS || ''), '', true)}
<body>
  <div class="login-container">
    <div class="brand">
      <img src="${escapeHtml(siteIcon)}" alt="Logo" width="64" height="64" style="margin-bottom: 1rem; border-radius: 8px;">
      <h1>Admin Login</h1>
      <p class="subtitle">Enter your password to manage entries</p>
    </div>
    
    <div id="message-container"></div>
    
    <form id="login-form">
      <div class="form-group">
        <label for="password">Password</label>
        <input type="password" id="password" name="password" required autofocus>
      </div>
      <button type="submit">Sign In</button>
    </form>
    <a href="/" class="back-link">Back to Guestbook</a>
  </div>
  
  <script>
    document.getElementById('login-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const form = e.target;
      const button = form.querySelector('button[type="submit"]');
      const messageContainer = document.getElementById('message-container');
      const formData = new FormData(form);
      
      button.disabled = true;
      button.textContent = 'Logging in...';
      
      try {
        const response = await fetch('/login', {
          method: 'POST',
          body: formData
        });
        
        const result = await response.json();
        
        if (result.success) {
          window.location.href = '/admin';
        } else {
          messageContainer.innerHTML = '<div class="message error">Invalid password</div>';
          form.reset();
        }
      } catch (error) {
        messageContainer.innerHTML = '<div class="message error">An error occurred. Please try again.</div>';
      } finally {
        button.disabled = false;
        button.textContent = 'Login';
      }
    });
  </script>
</body>
</html>`;
}

function getEmbedHTML(env, origin) {
  const sitename = env.SITENAME || 'Guestbook';
  const siteIcon = env.SITE_ICON_URL || 'https://static.mighil.com/images/2026/gb.webp';
  const turnstileKey = env.TURNSTILE_SITE_KEY || 'YOUR_TURNSTILE_SITE_KEY';
  
  const embedCode = `<!-- Guestbook Widget Container -->
<div 
  data-gb 
  data-gb-api-url="${origin}"
  data-gb-turnstile-key="${turnstileKey}"
  data-gb-form="true"
></div>

<!-- Load the guestbook client script -->
<script src="${origin}/client.js"></script>`;

  const extraStyles = `
    pre {
      background: #f1f5f9;
      padding: 1rem;
      border-radius: 0.5rem;
      overflow-x: auto;
      border: 1px solid var(--border);
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
      font-size: 0.875rem;
      margin-bottom: 1rem;
      color: #334155;
    }
    .copy-btn {
      background: var(--primary);
      color: white;
      border: none;
      padding: 0.5rem 1rem;
      border-radius: 0.375rem;
      font-size: 0.875rem;
      font-weight: 500;
      cursor: pointer;
      transition: background 0.15s;
    }
    .copy-btn:hover { background: var(--primary-hover); }
  `;

  return `<!DOCTYPE html>
<html lang="en">
${getHead('Embed - ' + sitename, siteIcon, extraStyles + (env.CUSTOM_CSS || ''), '', true)}
<body>
  <div class="container">
    ${getAdminHeader('embed')}
    
    <div class="card">
      <div style="padding: 1.5rem; border-bottom: 1px solid var(--border);">
        <h2 style="font-size: 1.125rem; font-weight: 600; margin: 0;">Embed Code</h2>
      </div>
      <div style="padding: 1.5rem;">
        <p style="margin-bottom: 1rem; color: var(--text-muted);">Copy the code below and paste it into your website where you want the guestbook to appear.</p>
        <div style="position: relative;">
          <pre><code id="embed-code">${escapeHtml(embedCode)}</code></pre>
          <button class="copy-btn" onclick="copyCode()">Copy Code</button>
          <span id="copy-success" style="margin-left: 0.5rem; color: var(--success); opacity: 0; transition: opacity 0.2s;">Copied!</span>
        </div>
      </div>
    </div>
  </div>
  
  <script>
    function copyCode() {
      const code = document.getElementById('embed-code').innerText;
      navigator.clipboard.writeText(code).then(() => {
        const successMsg = document.getElementById('copy-success');
        successMsg.style.opacity = '1';
        setTimeout(() => {
          successMsg.style.opacity = '0';
        }, 2000);
      });
    }
    
    async function logout() {
      try {
        await fetch('/logout', { method: 'POST' });
        window.location.href = '/login';
      } catch (error) {
        alert('Failed to logout');
      }
    }
  </script>
</body>
</html>`;
}

function getAdminHTML(entries, env) {
  const sitename = env.SITENAME || 'Guestbook';
  const siteIcon = env.SITE_ICON_URL || 'https://static.mighil.com/images/2026/gb.webp';
  
  const entriesHTML = entries.length === 0
    ? '<div class="empty-state">No entries found.</div>'
    : `
      <div class="table-responsive">
        <table class="entries-table">
          <thead>
            <tr>
              <th>Status</th>
              <th>Name</th>
              <th>Message</th>
              <th>Date</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            ${entries.map(entry => `
              <tr class="${entry.approved ? '' : 'row-pending'}">
                <td>
                  <span class="badge ${entry.approved ? 'badge-success' : 'badge-warning'}">
                    ${entry.approved ? 'Approved' : 'Pending'}
                  </span>
                </td>
                <td>
                  <div class="font-medium">${escapeHtml(entry.name)}</div>
                  ${entry.email ? `<div class="text-sm"><a href="mailto:${escapeHtml(entry.email)}" class="site-link">${escapeHtml(entry.email)}</a></div>` : ''}
                  ${entry.site ? `<a href="${escapeHtml(entry.site)}" target="_blank" rel="nofollow" class="site-link">${escapeHtml(entry.site)}</a>` : ''}
                </td>
                <td><div class="message-content">${escapeHtml(entry.message).replace(/\n/g, '<br>')}</div></td>
                <td class="text-muted text-sm client-date" datetime="${entry.created_at}">${formatDate(entry.created_at)}</td>
                <td>
                  <div class="action-buttons">
                    ${!entry.approved ? `<button onclick="approveEntry(${entry.id})" class="btn-icon btn-approve" title="Approve">Approve</button>` : ''}
                    <button onclick="deleteEntry(${entry.id})" class="btn-icon btn-delete" title="Delete">Delete</button>
                  </div>
                </td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    `;

  const extraStyles = `
    .logout { color: #ef4444 !important; }
    .logout:hover { background: #fef2f2 !important; }
    .table-responsive { overflow-x: auto; }
    .entries-table { width: 100%; border-collapse: collapse; font-size: 0.875rem; }
    .entries-table th {
      text-align: left;
      padding: 1rem;
      background: #f1f5f9;
      color: var(--text-muted);
      font-weight: 600;
      border-bottom: 1px solid var(--border);
    }
    .entries-table td {
      padding: 1rem;
      border-bottom: 1px solid var(--border);
      vertical-align: top;
    }
    .entries-table tr:last-child td { border-bottom: none; }
    .row-pending { background-color: #fffbeb; }
    .badge {
      display: inline-flex;
      align-items: center;
      padding: 0.25rem 0.625rem;
      border-radius: 9999px;
      font-size: 0.75rem;
      font-weight: 600;
    }
    .badge-success { background: #ecfdf5; color: #065f46; }
    .badge-warning { background: #fffbeb; color: #92400e; }
    .font-medium { font-weight: 600; color: var(--text); }
    .site-link {
      display: block;
      color: var(--primary);
      text-decoration: none;
      font-size: 0.75rem;
      margin-top: 0.25rem;
    }
    .site-link:hover { text-decoration: underline; }
    .message-content { max-width: 400px; color: var(--text-content); }
    .action-buttons { display: flex; flex-direction: column; gap: 0.2rem; }
    .btn-icon {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 100%;
      padding: 0.15rem 0.4rem;
      border-radius: 0.2rem;
      border: 1px solid transparent;
      cursor: pointer;
      font-size: 0.625rem;
      font-weight: 600;
      transition: all 0.2s;
      text-transform: uppercase;
      letter-spacing: 0.025em;
    }
    .btn-approve { background: #ecfdf5; color: #059669; border-color: #a7f3d0; }
    .btn-approve:hover { background: #d1fae5; }
    .btn-delete { background: #fef2f2; color: #dc2626; border-color: #fecaca; }
    .btn-delete:hover { background: #fee2e2; }
    .empty-state { padding: 4rem 2rem; text-align: center; color: var(--text-muted); font-style: italic; }
  `;

  return `<!DOCTYPE html>
<html lang="en">
${getHead('Admin - ' + sitename, siteIcon, extraStyles + (env.CUSTOM_CSS || ''), '', true)}
<body>
  <div class="container">
    ${getAdminHeader('entries')}
    
    <div id="message-container"></div>
    
    <div class="card">
      <div style="padding: 1.5rem; border-bottom: 1px solid var(--border);">
        <h2 style="font-size: 1.125rem; font-weight: 600; margin: 0;">All Entries</h2>
      </div>
      ${entriesHTML}
    </div>
  </div>
  
  <script>
    async function approveEntry(id) {
      try {
        const response = await fetch('/api/approve/' + id, { method: 'POST' });
        const result = await response.json();
        if (result.success) {
          location.reload();
        } else {
          alert('Failed to approve entry: ' + (result.error || 'Unknown error'));
        }
      } catch (error) {
        alert('An error occurred: ' + error.message);
      }
    }
    
    async function deleteEntry(id) {
      if (!confirm('Are you sure you want to delete this entry?')) return;
      
      try {
        const response = await fetch('/api/delete/' + id, { method: 'POST' });
        const result = await response.json();
        if (result.success) {
          location.reload();
        } else {
          alert('Failed to delete entry: ' + (result.error || 'Unknown error'));
        }
      } catch (error) {
        alert('An error occurred: ' + error.message);
      }
    }
    
    async function logout() {
      try {
        await fetch('/logout', { method: 'POST' });
        window.location.href = '/login';
      } catch (error) {
        window.location.href = '/login';
      }
    }
    
    ${CLIENT_COMMON_JS}
  </script>
</body>
</html>`;
}

function getClientScript(env, requestUrl) {
  // Use API_URL from env, or derive from request URL
  const apiUrl = env.API_URL || (requestUrl ? new URL(requestUrl).origin : '');
  // Ensure turnstileSiteKey is always a primitive string (not String object)
  let turnstileSiteKey = env.TURNSTILE_SITE_KEY;
  if (typeof turnstileSiteKey !== 'string') {
    turnstileSiteKey = String(turnstileSiteKey || '');
  }
  // Ensure it's a primitive string, not a String object
  turnstileSiteKey = '' + turnstileSiteKey;
  
  // Check for turnstile=false query param
  let forceDisabled = false;
  if (requestUrl) {
    try {
      const url = new URL(requestUrl);
      if (url.searchParams.get('turnstile') === 'false') {
        forceDisabled = true;
      }
    } catch (e) {
      // Ignore URL parse errors
    }
  }
  
  const turnstileEnabled = !forceDisabled && env.TURNSTILE_ENABLED;
  
  return `(function() {
  const GB_API_URL = ${JSON.stringify(String(apiUrl))};
  const GB_TURNSTILE_SITE_KEY = ${JSON.stringify(turnstileSiteKey)};
  const GB_TURNSTILE_ENABLED = ${turnstileEnabled};
  
  // Load Turnstile script
  if (GB_TURNSTILE_ENABLED && !document.querySelector('script[src*="turnstile"]')) {
    const script = document.createElement('script');
    script.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
    script.async = true;
    script.defer = true;
    document.head.appendChild(script);
  }
  
  // Guestbook widget
  function GuestbookWidget(config) {
    this.container = typeof config.container === 'string' 
      ? document.querySelector(config.container) 
      : config.container;
    this.apiUrl = config.apiUrl || GB_API_URL;
    // Ensure turnstileSiteKey is always a string
    const providedKey = config.turnstileSiteKey || GB_TURNSTILE_SITE_KEY;
    this.turnstileSiteKey = String(providedKey || '');
    this.turnstileEnabled = config.turnstileEnabled !== undefined ? config.turnstileEnabled : GB_TURNSTILE_ENABLED;
    this.showForm = config.showForm !== false;
    this.isSubmitting = false;
    this.turnstileWidgetId = null;
    this.init();
  }
  
  GuestbookWidget.prototype.init = function() {
    if (!this.container) {
      console.error('Guestbook: Container not found');
      return;
    }
    
    this.render();
    this.loadEntries();
  };
  
  GuestbookWidget.prototype.render = function() {
    let html = '<div class="gb-widget">';
    
    if (this.showForm) {
      html += \`
        <div class="gb-form">
          <form id="gb-form-\${Date.now()}">
            <div class="gb-form-group">
              <input type="text" name="name" required placeholder="Name">
            </div>
            <div class="gb-form-group">
              <input type="email" name="email" placeholder="Email (optional)">
            </div>
            <div class="gb-form-group">
              <input type="url" name="site" placeholder="Website (optional)">
            </div>
            <div class="gb-form-group">
              <textarea name="message" required placeholder="Message in plain text"></textarea>
            </div>
            \${this.turnstileEnabled ? '<div class="gb-turnstile"></div>' : ''}
            <button type="button" class="gb-submit-btn">Submit</button>
          </form>
          <div class="gb-message"></div>
        </div>
      \`;
    }
    
    html += '<div class="gb-entries"><div class="gb-entries-list"></div></div>';
    html += '</div>';
    
    this.container.innerHTML = html;
    
    if (this.showForm) {
      const form = this.container.querySelector('form');
      const submitBtn = this.container.querySelector('.gb-submit-btn');
      const turnstileContainer = this.container.querySelector('.gb-turnstile');
      const self = this;
      
      // Render Turnstile automatically
      function renderTurnstileWidget() {
        if (!self.turnstileEnabled) return null;
        
        if (self.turnstileWidgetId !== null || !window.turnstile) {
          return self.turnstileWidgetId;
        }
        
        try {
          if (!self.turnstileSiteKey || typeof self.turnstileSiteKey !== 'string' || self.turnstileSiteKey === '') {
            console.error('Turnstile site key is invalid:', self.turnstileSiteKey, typeof self.turnstileSiteKey);
            return null;
          }
          // Explicitly ensure it's a string
          const siteKeyValue = String(self.turnstileSiteKey);
          self.turnstileWidgetId = window.turnstile.render(turnstileContainer, {
            sitekey: siteKeyValue,
            theme: 'auto',
            callback: function(token) {
              // Store token but don't auto-submit
              // We'll submit when user clicks the button
            }
          });
          turnstileContainer.setAttribute('data-turnstile-rendered', 'true');
          return self.turnstileWidgetId;
        } catch (error) {
          console.error('Turnstile render error:', error);
          return null;
        }
      }
      
      // Auto-render if Turnstile is ready
      if (window.turnstile) {
        renderTurnstileWidget();
      } else {
        // Poll for Turnstile
        const checkTurnstile = setInterval(() => {
          if (window.turnstile) {
            clearInterval(checkTurnstile);
            renderTurnstileWidget();
          }
        }, 100);
        setTimeout(() => clearInterval(checkTurnstile), 5000);
      }
      
      // Handle button click instead of form submit to prevent Enter key from triggering
      submitBtn.addEventListener('click', async () => {
        // Prevent multiple clicks
        if (this.isSubmitting) {
          return;
        }
        
        // Validate form
        if (!form.checkValidity()) {
          form.reportValidity();
          return;
        }

        if (!this.turnstileEnabled) {
          this.handleSubmit('disabled');
          return;
        }
        
        // Get Turnstile response
        const token = window.turnstile ? window.turnstile.getResponse(this.turnstileWidgetId) : null;
        
        if (!token) {
          const messageDiv = this.container.querySelector('.gb-message');
          messageDiv.innerHTML = '<div class="gb-error">Please verify you are human.</div>';
          return;
        }
        
        this.handleSubmit(token);
      });
      
      // Prevent form submission on Enter key
      form.addEventListener('submit', (e) => {
        e.preventDefault();
      });
    }
  };
  
  GuestbookWidget.prototype.handleSubmit = async function(token) {
    // Prevent multiple simultaneous submissions
    if (this.isSubmitting) {
      return;
    }
    
    this.isSubmitting = true;
    const form = this.container.querySelector('form');
    const button = this.container.querySelector('.gb-submit-btn');
    const messageDiv = this.container.querySelector('.gb-message');
    
    if (!button) {
      console.error('Submit button not found');
      this.isSubmitting = false;
      return;
    }
    
    button.disabled = true;
    button.textContent = 'Submitting...';
    
    const formData = new FormData(form);
    formData.append('cf-turnstile-response', token);
    
    try {
      const response = await fetch(this.apiUrl + '/api/submit', {
        method: 'POST',
        body: formData
      });
      
      const result = await response.json();
      
      if (result.success) {
        const successMsg = result.approved 
          ? 'Thank you! Your entry has been submitted.' 
          : 'Thank you! Your entry will be visible after moderation.';
        messageDiv.innerHTML = '<div class="gb-success">' + successMsg + '</div>';
        form.reset();
        if (window.turnstile && this.turnstileWidgetId !== null) {
          window.turnstile.reset(this.turnstileWidgetId);
        }
        this.loadEntries();
      } else {
        messageDiv.innerHTML = '<div class="gb-error">' + (result.error || 'Failed to submit entry.') + '</div>';
        if (window.turnstile && this.turnstileWidgetId !== null) {
          window.turnstile.reset(this.turnstileWidgetId);
        }
      }
    } catch (error) {
      messageDiv.innerHTML = '<div class="gb-error">An error occurred. Please try again.</div>';
      if (window.turnstile && this.turnstileWidgetId !== null) {
        window.turnstile.reset(this.turnstileWidgetId);
      }
    } finally {
      this.isSubmitting = false;
      button.disabled = false;
      button.textContent = 'Submit';
    }
  };
  
  GuestbookWidget.prototype.loadEntries = async function() {
    const entriesList = this.container.querySelector('.gb-entries-list');
    if (!entriesList) return;
    
    entriesList.innerHTML = '<div class="gb-loading">Loading entries...</div>';
    
    try {
      const response = await fetch(this.apiUrl + '/api/entries');
      const result = await response.json();
      
      if (result.success && result.entries) {
        if (result.entries.length === 0) {
          entriesList.innerHTML = '<div class="gb-no-entries">No entries yet.</div>';
        } else {
          entriesList.innerHTML = result.entries.map(entry => \`
            <div class="gb-entry">
              <div class="gb-entry-header">
                <strong class="gb-entry-name">
                  \${entry.site 
                    ? '<a href="' + this.escapeHtml(this.addViaParam(entry.site)) + '" target="_blank" rel="nofollow" class="gb-entry-name-link">' + this.escapeHtml(entry.name) + '</a>' 
                    : this.escapeHtml(entry.name)
                  }
                </strong>
                <span class="gb-entry-date">\${this.formatDate(entry.created_at)}</span>
              </div>
              <div class="gb-entry-message">\${this.escapeHtml(entry.message).replace(/\\n/g, '<br>')}</div>
            </div>
          \`).join('');
        }
      } else {
        entriesList.innerHTML = '<div class="gb-error">Failed to load entries.</div>';
      }
    } catch (error) {
      entriesList.innerHTML = '<div class="gb-error">Failed to load entries.</div>';
    }
  };
  
  GuestbookWidget.prototype.escapeHtml = function(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  };
  
  GuestbookWidget.prototype.addViaParam = function(urlStr) {
    if (!urlStr) return '';
    try {
      const url = new URL(urlStr);
      url.searchParams.set('via', window.location.hostname);
      return url.toString();
    } catch (e) {
      return urlStr;
    }
  };

  GuestbookWidget.prototype.formatDate = function(dateString) {
    if (!dateString) return '';
    // Fix for SQLite date format
    const isoDate = dateString.replace(' ', 'T') + (dateString.includes('Z') ? '' : 'Z');
    const date = new Date(isoDate);
    if (isNaN(date.getTime())) return dateString;
    // To include time, use:
    // return date.toLocaleString('en-US', { month: 'short', day: 'numeric', year: 'numeric', hour: 'numeric', minute: '2-digit' });
    return date.toLocaleString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
  };
  
  // CSS Styles
  const style = document.createElement('style');
  style.textContent = \`
    .gb-widget { 
      font-family: inherit; 
      color: inherit;
      --gb-base: currentColor;
      --gb-primary: #3498db;
      --gb-bg: transparent;
      --gb-border: #ddd;
      --gb-input-bg: #fff;
      --gb-input-text: inherit;
      --gb-error-bg: #f8d7da;
      --gb-error-text: #721c24;
      --gb-success-bg: #d4edda;
      --gb-success-text: #155724;
    }
    .gb-form { 
      margin-bottom: 20px; 
    }
    .gb-form-group { margin-bottom: 15px; }
    .gb-form-group input,
    .gb-form-group textarea { 
      width: 100%;
      padding: 8px;
      border: 1px solid color-mix(in srgb,var(--gb-base)10%,transparent);
      border-radius: 10px;
      font-family: inherit;
      color: inherit;
      box-sizing: border-box;
      font-size: 16px;
      background: transparent;
    }
    .gb-form-group textarea { min-height: 80px; resize: vertical; }
    .gb-turnstile { margin: 15px 0; }
    .gb-form button { 
      border: 1px solid;
      padding: 10px 20px;
      border-radius: 10px;
      cursor: pointer;
      font-weight: 500;
      background: transparent;
      text-transform: uppercase;
    }
    .gb-form button:hover { opacity: 0.9; }
    .gb-form button:disabled { opacity: 0.6; cursor: not-allowed; }
    .gb-message { margin-top: 15px; }
    .gb-success { padding: 10px; background: var(--gb-success-bg); color: var(--gb-success-text); border-radius: 4px; }
    .gb-error { padding: 10px; background: var(--gb-error-bg); color: var(--gb-error-text); border-radius: 4px; }
    .gb-entries h3 { margin-bottom: 15px; }
    .gb-entry { 
      margin-bottom: 20px;
      padding: 15px;
      border: 1px solid color-mix(in srgb,var(--gb-base)10%,transparent);
      border-radius: 10px;
    }
    .gb-entry-header { display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 8px; align-items: center; }
    .gb-entry-name { font-weight: bold; color: inherit; }
    .gb-entry-date { opacity: 0.7; font-size: 0.85em; margin-left: auto; }
    .gb-entry-message { line-height: 1.6; }
    .gb-loading, .gb-no-entries { text-align: center; opacity: 0.7; padding: 20px; }
  \`;
  document.head.appendChild(style);
  
  // Export
  window.GuestbookWidget = GuestbookWidget;
  
    // Auto-initialize if data-gb attribute is present
    document.addEventListener('DOMContentLoaded', function() {
      const containers = document.querySelectorAll('[data-gb]');
      containers.forEach(container => {
        const config = {
          container: container,
          apiUrl: container.getAttribute('data-gb-api-url') || GB_API_URL,
          turnstileSiteKey: container.getAttribute('data-gb-turnstile-key') || GB_TURNSTILE_SITE_KEY,
          showForm: container.getAttribute('data-gb-form') !== 'false'
        };
        new GuestbookWidget(config);
      });
    });
  })();`;
}

// Utility functions
function escapeHtml(text) {
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function formatDate(dateString) {
  if (!dateString) return '';
  // Fix for SQLite date format
  const isoDate = dateString.replace(' ', 'T') + (dateString.includes('Z') ? '' : 'Z');
  const date = new Date(isoDate);
  if (isNaN(date.getTime())) return dateString;
  
  return date.toLocaleString('en-US', { 
    month: 'short', 
    day: 'numeric', 
    year: 'numeric', 
    hour: 'numeric', 
    minute: '2-digit' 
  });
}

// Main handler
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    
    // Load configuration
    const config = await getAppConfig(env);
    
    try {
      // Handle CORS preflight
      if (request.method === 'OPTIONS') {
        return new Response(null, {
          headers: {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type',
            'Access-Control-Max-Age': '86400'
          }
        });
      }

      // Favicon
      if (path === '/favicon.ico') {
        return Response.redirect(config.SITE_ICON_URL, 301);
      }
      
      // API Routes
      if (path === '/api/submit') {
        if (request.method !== 'POST') {
          return new Response(JSON.stringify({ success: false, error: 'Method not allowed' }), {
            status: 405,
            headers: { 
              'Content-Type': 'application/json',
              'Access-Control-Allow-Origin': '*'
            }
          });
        }
        
        const formData = await request.formData();
        const name = formData.get('name')?.trim();
        const message = formData.get('message')?.trim();
        let site = formData.get('site')?.trim() || null;
        const email = formData.get('email')?.trim() || null;
        const turnstileToken = formData.get('cf-turnstile-response');

        // Input length validation
        if (name && name.length > 100) {
          return new Response(JSON.stringify({ success: false, error: 'Name too long (max 300 chars)' }), {
            status: 400,
            headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
          });
        }
        if (message && message.length > 2000) {
          return new Response(JSON.stringify({ success: false, error: 'Message too long (max 5000 chars)' }), {
            status: 400,
            headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
          });
        }
        if (site && site.length > 255) {
          return new Response(JSON.stringify({ success: false, error: 'URL too long (max 500 chars)' }), {
            status: 400,
            headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
          });
        }
        if (email && email.length > 255) {
          return new Response(JSON.stringify({ success: false, error: 'Email too long (max 500 chars)' }), {
            status: 400,
            headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
          });
        }
        
        // Validate URL protocol to prevent XSS (javascript: links)
        if (site) {
          try {
            const url = new URL(site);
            if (!['http:', 'https:'].includes(url.protocol)) {
              return new Response(JSON.stringify({ success: false, error: 'Invalid website URL. Must start with http:// or https://' }), {
                status: 400,
                headers: { 
                  'Content-Type': 'application/json',
                  'Access-Control-Allow-Origin': '*'
                }
              });
            }
          } catch (e) {
            return new Response(JSON.stringify({ success: false, error: 'Invalid website URL' }), {
              status: 400,
              headers: { 
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
              }
            });
          }
        }
        
        if (!name || !message) {
          return new Response(JSON.stringify({ success: false, error: 'Name and message are required' }), {
            status: 400,
            headers: { 
              'Content-Type': 'application/json',
              'Access-Control-Allow-Origin': '*'
            }
          });
        }
        
        if (config.TURNSTILE_ENABLED && !turnstileToken) {
          return new Response(JSON.stringify({ success: false, error: 'Turnstile verification required' }), {
            status: 400,
            headers: { 
              'Content-Type': 'application/json',
              'Access-Control-Allow-Origin': '*'
            }
          });
        }
        
        // Verify Turnstile
        if (config.TURNSTILE_ENABLED) {
          const turnstileValid = await verifyTurnstile(turnstileToken, config);
          if (!turnstileValid) {
            return new Response(JSON.stringify({ success: false, error: 'Verification failed' }), {
              status: 400,
              headers: { 
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
              }
            });
          }
        }
        
        // Determine approval status based on ENTRY_MODERATION config
        const approved = config.ENTRY_MODERATION ? 0 : 1;
        
        // Insert into database
        const result = await env.DB.prepare(
          'INSERT INTO entries (name, message, site, email, created_at, approved) VALUES (?, ?, ?, ?, datetime("now"), ?)'
        ).bind(name, message, site, email, approved).run();
        
        return new Response(JSON.stringify({ success: true, id: result.meta.last_row_id, approved: approved === 1 }), {
          headers: { 
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
          }
        });
      }
      
      if (path === '/api/entries') {
        const url = new URL(request.url);
        const limit = 20;
        const cursor = url.searchParams.get('cursor');
        
        let query = 'SELECT id, name, message, site, created_at FROM entries WHERE approved = 1';
        const params = [];
        
        if (cursor) {
          query += ' AND id < ?';
          params.push(parseInt(cursor));
        }
        
        query += ' ORDER BY id DESC LIMIT ?';
        params.push(limit);
        
        const entries = await env.DB.prepare(query).bind(...params).all();
        
        const results = entries.results || [];
        const nextCursor = results.length === limit ? results[results.length - 1].id : null;
        
        return new Response(JSON.stringify({ 
          success: true, 
          entries: results,
          nextCursor 
        }), {
          headers: { 
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Cache-Control': 'public, max-age=60, s-maxage=60'
          }
        });
      }
      
      // Admin API routes (protected)
      if (path.startsWith('/api/')) {
        const username = await verifySession(request, env);
        if (!username) {
          return new Response(JSON.stringify({ success: false, error: 'Unauthorized' }), {
            status: 401,
            headers: { 'Content-Type': 'application/json' }
          });
        }

        // CSRF Check
        const origin = request.headers.get('Origin');
        const urlObj = new URL(request.url);
        if (origin && origin !== urlObj.origin) {
          // Relaxed check: allow protocol mismatch (http vs https) if host matches
          try {
            const originUrl = new URL(origin);
            if (originUrl.host !== urlObj.host) {
              return new Response(JSON.stringify({ 
                success: false, 
                error: `CSRF Forbidden: Origin '${origin}' does not match '${urlObj.origin}'` 
              }), {
                status: 403,
                headers: { 'Content-Type': 'application/json' }
              });
            }
          } catch (e) {
             return new Response(JSON.stringify({ success: false, error: 'CSRF Forbidden: Invalid Origin' }), {
              status: 403,
              headers: { 'Content-Type': 'application/json' }
            });
          }
        }

        if (path === '/api/settings' && request.method === 'POST') {
          const formData = await request.formData();
          const settings = {
            SITENAME: formData.get('SITENAME') || 'Guestbook',
            SITE_INTRO: formData.get('SITE_INTRO') || '',
            SITE_DESCRIPTION: formData.get('SITE_DESCRIPTION') || '',
            SITE_ICON_URL: formData.get('SITE_ICON_URL') || '',
            SITE_COVER_IMAGE_URL: formData.get('SITE_COVER_IMAGE_URL') || '',
            NAV_LINKS: formData.get('NAV_LINKS') || '[]',
            CANONICAL_URL: formData.get('CANONICAL_URL') || '',
            ALLOW_INDEXING: formData.get('ALLOW_INDEXING') === 'on',
            ENTRY_MODERATION: formData.get('ENTRY_MODERATION') === 'on',
            TURNSTILE_ENABLED: formData.get('TURNSTILE_ENABLED') === 'on',
            TURNSTILE_SITE_KEY: formData.get('TURNSTILE_SITE_KEY') || '',
            TURNSTILE_SECRET_KEY: formData.get('TURNSTILE_SECRET_KEY') || '',
            CUSTOM_CSS: formData.get('CUSTOM_CSS') || ''
          };
          
          await saveAppSettings(env, settings);
          
          return new Response(JSON.stringify({ success: true }), {
            headers: { 'Content-Type': 'application/json' }
          });
        }
        
        if (path.startsWith('/api/approve/')) {
          const id = parseInt(path.split('/').pop());
          await env.DB.prepare('UPDATE entries SET approved = 1 WHERE id = ?').bind(id).run();
          return new Response(JSON.stringify({ success: true }), {
            headers: { 'Content-Type': 'application/json' }
          });
        }
        
        if (path.startsWith('/api/delete/')) {
          const id = parseInt(path.split('/').pop());
          await env.DB.prepare('DELETE FROM entries WHERE id = ?').bind(id).run();
          return new Response(JSON.stringify({ success: true }), {
            headers: { 'Content-Type': 'application/json' }
          });
        }
      }
      
      // Login routes
      if (path === '/login') {
        if (request.method === 'POST') {
          const formData = await request.formData();
          const password = formData.get('password');
          
          if (!password || !config.ADMIN_PASSWORD) {
            return new Response(JSON.stringify({ success: false }), {
              status: 401,
              headers: { 'Content-Type': 'application/json' }
            });
          }
          
          if (await checkPassword(password, config.ADMIN_PASSWORD)) {
            const sessionToken = await createSessionToken(env);
            return new Response(JSON.stringify({ success: true }), {
              headers: {
                'Content-Type': 'application/json',
                'Set-Cookie': setSessionCookie(sessionToken)
              }
            });
          }
          
          return new Response(JSON.stringify({ success: false }), {
            status: 401,
            headers: { 'Content-Type': 'application/json' }
          });
        }
        
        // If already logged in, redirect to admin
        const username = await verifySession(request, env);
        if (username) {
          return Response.redirect(url.origin + '/admin', 302);
        }
        
        return new Response(getLoginHTML(config), {
          headers: { 'Content-Type': 'text/html' }
        });
      }
      
      if (path === '/logout') {
        if (request.method === 'POST') {
          const origin = request.headers.get('Origin');
          const urlObj = new URL(request.url);
          if (origin && origin !== urlObj.origin) {
            // Relaxed check for logout too
            try {
              const originUrl = new URL(origin);
              if (originUrl.host !== urlObj.host) {
                return new Response(JSON.stringify({ success: false, error: 'CSRF Forbidden' }), {
                  status: 403,
                  headers: { 'Content-Type': 'application/json' }
                });
              }
            } catch (e) {
               return new Response(JSON.stringify({ success: false, error: 'CSRF Forbidden' }), {
                status: 403,
                headers: { 'Content-Type': 'application/json' }
              });
            }
          }
        }

        return new Response(JSON.stringify({ success: true }), {
          headers: {
            'Content-Type': 'application/json',
            'Set-Cookie': clearSessionCookie()
          }
        });
      }
      
      // Admin Pages
      if (path.startsWith('/admin')) {
        const username = await verifySession(request, env);
        if (!username) {
          return Response.redirect(new URL('/login', request.url), 302);
        }
        
        if (path === '/admin/embed') {
          // Use configured API_URL or fallback to current origin
          const apiUrl = config.API_URL ? config.API_URL.replace(/\/$/, '') : url.origin;
          return new Response(getEmbedHTML(config, apiUrl), {
            headers: { 'Content-Type': 'text/html' }
          });
        }

        if (path === '/admin/settings') {
          return new Response(getSettingsHTML(config), {
            headers: { 'Content-Type': 'text/html' }
          });
        }

        // Default admin page (entries)
        const entries = await env.DB.prepare(
          'SELECT * FROM entries ORDER BY created_at DESC LIMIT 100'
        ).all();
        
        return new Response(getAdminHTML(entries.results || [], config), {
          headers: { 'Content-Type': 'text/html' }
        });
      }
      
      // Client script
      if (path === '/client.js') {
        return new Response(getClientScript(config, request.url), {
          headers: {
            'Content-Type': 'application/javascript',
            'Access-Control-Allow-Origin': '*'
          }
        });
      }

      // Public Data Export (JSON)
      if (path === '/data.json') {
        const entries = await env.DB.prepare(
          'SELECT name, message, site, created_at FROM entries WHERE approved = 1 ORDER BY created_at DESC'
        ).all();
        
        const results = (entries.results || []).map(entry => ({
          ...entry,
          created_at: entry.created_at ? entry.created_at.replace(' ', 'T') + 'Z' : null
        }));
        
        return new Response(JSON.stringify(results, null, 2), {
          headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Cache-Control': 'public, max-age=60'
          }
        });
      }

      // Public Data Export (CSV)
      if (path === '/data.csv') {
        const entries = await env.DB.prepare(
          'SELECT name, message, site, created_at FROM entries WHERE approved = 1 ORDER BY created_at DESC'
        ).all();
        
        const results = entries.results || [];
        
        // CSV Header
        let csv = 'Name,Message,Website,Date\n';
        
        // CSV Rows
        for (const entry of results) {
          const name = (entry.name || '').replace(/"/g, '""');
          const message = (entry.message || '').replace(/"/g, '""');
          const site = (entry.site || '').replace(/"/g, '""');
          let date = (entry.created_at || '').replace(/"/g, '""');
          
          // Convert to ISO 8601 UTC format (YYYY-MM-DDTHH:MM:SSZ)
          if (date && /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(date)) {
            date = date.replace(' ', 'T') + 'Z';
          }
          
          csv += `"${name}","${message}","${site}","${date}"\n`;
        }
        
        return new Response(csv, {
          headers: {
            'Content-Type': 'text/csv; charset=utf-8',
            'Content-Disposition': 'attachment; filename="guestbook-data.csv"',
            'Access-Control-Allow-Origin': '*',
            'Cache-Control': 'public, max-age=60'
          }
        });
      }
      
      // Index page
      if (path === '/') {
        const entries = await env.DB.prepare(
          'SELECT id, name, message, site, created_at FROM entries WHERE approved = 1 ORDER BY id DESC LIMIT 20'
        ).all();
        
        return new Response(getIndexHTML(entries.results || [], config, url.hostname), {
          headers: { 
            'Content-Type': 'text/html',
            'Cache-Control': 'public, max-age=60, s-maxage=60'
          }
        });
      }
      
      return new Response('Not Found', { status: 404 });
    } catch (error) {
      console.error('Error:', error);
      return new Response(JSON.stringify({ success: false, error: error.message }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  }
};