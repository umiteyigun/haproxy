const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const { Pool } = require('pg');
const fs = require('fs');
const fsPromises = require('fs').promises;
const path = require('path');
const yaml = require('js-yaml');
const cron = require('node-cron');
const axios = require('axios');
let SSLManager;
try {
  SSLManager = require('./ssl-manager');
} catch (e) {
  console.error('SSLManager module failed to load, using stub. Error:', e && e.message);
  SSLManager = class SSLManagerStub {
    async listCertificates() { return []; }
    async requestCertificate() { return { success: false, error: 'SSL manager unavailable' }; }
    async renewCertificates() { return { success: false, error: 'SSL manager unavailable' }; }
    async executeInCertbotContainer() { return { stdout: '', stderr: 'ssl-manager unavailable', exitCode: 1 }; }
  };
}
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const http = require('http');
const WebSocket = require('ws');
const HEDNSManager = require('./he-dns-manager');
const CRSManager = require('./crs-manager');
const app = express();

const PORT = process.env.PORT || 3000;
const server = http.createServer(app);

// Enhanced CORS configuration
const corsOptions = {
  origin: (origin, callback) => {
    if (!origin) return callback(null, true);
    const allowAll = (process.env.CORS_ALLOW_ALL || 'true').toLowerCase() === 'true';
    if (allowAll) return callback(null, true);
    const allowed = (process.env.CORS_ORIGINS || 'http://localhost,http://localhost:80,http://localhost:3000,http://127.0.0.1')
      .split(',')
      .map(s => s.trim());
    if (allowed.includes(origin)) return callback(null, true);
    return callback(new Error('CORS: Origin not allowed'));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Origin', 'X-Requested-With', 'Content-Type', 'Accept', 'Authorization'],
  optionsSuccessStatus: 204,
  preflightContinue: false
};
app.use(cors(corsOptions));
// Explicitly handle preflight for all routes
app.options('*', cors(corsOptions));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Database connection with better error handling
const pool = new Pool({
  host: process.env.DB_HOST || 'db',
  port: process.env.DB_PORT || 5432,
  database: process.env.DB_NAME || 'haproxy',
  user: process.env.DB_USER || 'haproxy',
  password: process.env.DB_PASSWORD || 'haproxy_password_change_me',
  connectionTimeoutMillis: 5000,
  idleTimeoutMillis: 30000,
  max: 10
});

// Database connection error handling
pool.on('error', (err, client) => {
  console.error('Unexpected error on idle client', err);
  // Do not exit; let the pool recover and our retry logic handle readiness
});

// SSL Manager
const sslManager = new SSLManager();
const crsManager = new CRSManager();

// Initialize database
async function initDatabase() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS rules (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL UNIQUE,
        type VARCHAR(50) NOT NULL,
        domain VARCHAR(255),
        path VARCHAR(255),
        frontend_port INTEGER,
        backend_host VARCHAR(255),
        backend_port INTEGER,
        ssl_enabled BOOLEAN DEFAULT false,
        ssl_cert VARCHAR(255),
        ssl_type VARCHAR(20) DEFAULT 'none',
        dns_provider VARCHAR(50),
        lb_mode VARCHAR(20) DEFAULT 'roundrobin',
        redirect_to_https BOOLEAN DEFAULT false,
        active BOOLEAN DEFAULT true,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS certificates (
        id SERIAL PRIMARY KEY,
        domain VARCHAR(255) NOT NULL UNIQUE,
        email VARCHAR(255),
        provider VARCHAR(50),
        auto_renew BOOLEAN DEFAULT true,
        expires_at TIMESTAMP,
        last_check TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS settings (
        key VARCHAR(255) PRIMARY KEY,
        value TEXT,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // Migration: Add new columns if they don't exist
    try {
      await pool.query('ALTER TABLE rules ADD COLUMN IF NOT EXISTS ssl_type VARCHAR(20) DEFAULT \'none\'');
      await pool.query('ALTER TABLE rules ADD COLUMN IF NOT EXISTS dns_provider VARCHAR(50)');
      await pool.query('ALTER TABLE rules ADD COLUMN IF NOT EXISTS lb_mode VARCHAR(20) DEFAULT \'roundrobin\'');
      await pool.query('ALTER TABLE rules ADD COLUMN IF NOT EXISTS redirect_to_https BOOLEAN DEFAULT false');
      await pool.query('ALTER TABLE rules ADD COLUMN IF NOT EXISTS backend_protocol VARCHAR(10) DEFAULT \'http\'');
    } catch (e) {
      // Columns might already exist, ignore
      console.log('Migration check:', e.message);
    }

    await pool.query(`
      CREATE TABLE IF NOT EXISTS rule_backends (
        id SERIAL PRIMARY KEY,
        rule_id INTEGER NOT NULL REFERENCES rules(id) ON DELETE CASCADE,
        host VARCHAR(255) NOT NULL,
        port INTEGER NOT NULL,
        weight INTEGER DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS port_forwarding (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL UNIQUE,
        frontend_port INTEGER NOT NULL,
        backend_host VARCHAR(255) NOT NULL,
        backend_port INTEGER NOT NULL,
        protocol VARCHAR(10) DEFAULT 'tcp',
        active BOOLEAN DEFAULT true,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS members (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        role VARCHAR(50) DEFAULT 'admin',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // SSL Certificates table (central certificate pool)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS certificates (
        id SERIAL PRIMARY KEY,
        domain VARCHAR(255) NOT NULL,
        cert_domain VARCHAR(255) NOT NULL,
        cert_path VARCHAR(255) NOT NULL,
        ssl_type VARCHAR(20) NOT NULL,
        dns_provider VARCHAR(50),
        email VARCHAR(255),
        expires_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(cert_domain)
      )
    `);

    // Seed admin if not exists and env provided
    const adminEmail = process.env.ADMIN_EMAIL;
    const adminPassword = process.env.ADMIN_PASSWORD;
    if (adminEmail && adminPassword) {
      const exists = await pool.query('SELECT 1 FROM members WHERE email = $1', [adminEmail]);
      if (exists.rowCount === 0) {
        const hash = await bcrypt.hash(adminPassword, 10);
        await pool.query('INSERT INTO members (email, password_hash, role) VALUES ($1, $2, $3)', [adminEmail, hash, 'admin']);
        console.log('Seeded admin user');
      }
    }

    console.log('Database initialized');
  } catch (error) {
    console.error('Database initialization error:', error);
  }
}

// Wait for database to be ready with retry/backoff
async function waitForDatabase(maxAttempts = 30, delayMs = 2000) {
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      await pool.query('SELECT 1');
      console.log('Database is reachable');
      return;
    } catch (err) {
      console.log(`Database not ready (attempt ${attempt}/${maxAttempts}): ${err.message}`);
      await new Promise(r => setTimeout(r, delayMs));
    }
  }
  console.warn('Database did not become ready in time; continuing and relying on pool retries');
}

// Generate HAProxy config from database
async function generateHAProxyConfig() {
  try {
    const configDir = '/app/config/haproxy';

    // Ensure directory exists
    if (!fs.existsSync(configDir)) {
      fs.mkdirSync(configDir, { recursive: true });
    }

    // Get all active ingress rules
    const ingressRules = await pool.query(`
      SELECT * FROM rules 
      WHERE type = 'ingress' AND active = true
      ORDER BY created_at
    `);

    await hydrateRuleBackends(ingressRules.rows);

    // Get all active port forwarding rules
    const portForwardingRules = await pool.query(`
      SELECT * FROM port_forwarding 
      WHERE active = true
      ORDER BY frontend_port
    `);

    // Generate backends only (routing via host map in frontend)
    let ingressConfig = '';
    ingressRules.rows.forEach((rule) => {
      const servers = (rule.backends && rule.backends.length)
        ? rule.backends
        : (rule.backend_host && rule.backend_port ? [{ host: rule.backend_host, port: rule.backend_port }] : []);

      if (!servers.length) {
        return;
      }

      ingressConfig += `backend backend_${rule.id}\n`;
      if (servers.length > 1 && (rule.lb_mode || 'roundrobin') === 'roundrobin') {
        ingressConfig += '    balance roundrobin\n';
      }

      servers.forEach((server, index) => {
        const safeName = `${rule.name}_${index + 1}`.replace(/[^a-zA-Z0-9_-]/g, '_');
        const backupFlag = (rule.lb_mode === 'failover' && index > 0) ? ' backup' : '';
        ingressConfig += `    server ${safeName} ${server.host}:${server.port} check inter 3s fall 3 rise 2${backupFlag}\n`;
      });

      ingressConfig += '\n';
    });

    // Write backends to a dedicated file included by haproxy.cfg
    const ingressBackendsFile = path.join(configDir, 'ingress_backends.cfg');
    fs.writeFileSync(ingressBackendsFile, ingressConfig || '# No ingress backends\n');

    // No frontend additions needed; using host map

    // Generate host map for frontend routing
    const mapsDir = '/usr/local/etc/haproxy/maps';
    const localMapsDir = '/app/config/haproxy_maps';
    if (!fs.existsSync(localMapsDir)) fs.mkdirSync(localMapsDir, { recursive: true });
    const hostsMapPath = path.join(localMapsDir, 'hosts.map');
    const hostLines = ingressRules.rows
      .filter(r => r.domain)
      .map(r => `${r.domain.toLowerCase()} backend_${r.id}`)
      .join('\n');
    fs.writeFileSync(hostsMapPath, hostLines + (hostLines ? '\n' : ''));

    // Generate dynamic HAProxy config with all domains and backends
    await generateDynamicHAProxyConfig(ingressRules.rows, portForwardingRules.rows);

    // Port forwarding configs are now included in the main file via generateDynamicHAProxyConfig

    // Reload HAProxy
    await reloadHAProxy();

    console.log('HAProxy config regenerated');
  } catch (error) {
    console.error('Error generating HAProxy config:', error);
  }
}

// Get base HAProxy template with placeholders
function getBaseTemplate() {
  return `global
    log host.docker.internal:514 local0
    maxconn 4096
    user haproxy
    group haproxy
    daemon
    stats socket /app/sockets/haproxy.sock mode 666 level admin expose-fd listeners
    stats timeout 2m
    ssl-default-bind-ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384

defaults
    log global
    mode http
    option httplog
    option dontlognull
    option forwardfor
    option http-server-close
    timeout connect 5000ms
    timeout client 50000ms
    timeout server 50000ms
    timeout http-request 10s
    timeout http-keep-alive 10s

# Frontend for HTTP (port 80)
frontend http_frontend
    bind *:80
    # Allow Let's Encrypt validation
    acl letsencrypt-acl path_beg /.well-known/acme-challenge/

    filter spoe engine modsecurity config /usr/local/etc/haproxy/modsecurity.conf

    # --- WAF: IP blacklist, rate limiting, and bad user-agent filtering ---
    stick-table type ip size 100k expire 10m store http_req_rate(10s)
    acl waf_blacklisted_ip src -f /usr/local/etc/haproxy/config.d/ip_blacklist.lst
    acl waf_whitelist src -f /usr/local/etc/haproxy/config.d/whitelist.lst
    
    http-request track-sc0 src if !letsencrypt-acl
    acl waf_rate_abuse sc_http_req_rate(0) gt 100
    acl waf_bad_user_agent hdr_sub(User-Agent) -f /usr/local/etc/haproxy/maps/bad_useragents.lst
    
    http-request deny deny_status 403 if waf_blacklisted_ip !letsencrypt-acl !waf_whitelist
    http-request deny deny_status 429 if waf_rate_abuse !letsencrypt-acl !waf_whitelist
    http-request deny deny_status 403 if waf_bad_user_agent !letsencrypt-acl !waf_whitelist

    # Dynamic host-based routing (generated by API)
#DYNAMIC_ACLS#
#DYNAMIC_HTTP_REDIRECTS#
#DYNAMIC_RULES#
    # API Routing
    acl path_api path_beg /api /auth
    use_backend api_backend if path_api

    use_backend web_backend if letsencrypt-acl
    default_backend web_backend

# Frontend for HTTPS (port 443)
frontend https_frontend
#DYNAMIC_SSL_BINDS#
    option forwardfor
    http-request set-header X-Forwarded-Proto https
    acl letsencrypt-acl path_beg /.well-known/acme-challenge/

    filter spoe engine modsecurity config /usr/local/etc/haproxy/modsecurity.conf

    stick-table type ip size 100k expire 10m store http_req_rate(10s)
    
    acl waf_blacklisted_ip src -f /usr/local/etc/haproxy/config.d/ip_blacklist.lst
    acl waf_whitelist src -f /usr/local/etc/haproxy/config.d/whitelist.lst
    
    http-request track-sc0 src
    acl waf_rate_abuse sc_http_req_rate(0) gt 100
    acl waf_bad_user_agent hdr_sub(User-Agent) -f /usr/local/etc/haproxy/maps/bad_useragents.lst
    
    http-request deny deny_status 403 if waf_blacklisted_ip !waf_whitelist
    http-request deny deny_status 429 if waf_rate_abuse !waf_whitelist
    http-request deny deny_status 403 if waf_bad_user_agent !waf_whitelist

    # Dynamic host-based routing (generated by API)
#DYNAMIC_ACLS#
#DYNAMIC_RULES#
    # API Routing
    acl path_api path_beg /api /auth
    use_backend api_backend if path_api

    use_backend web_backend if letsencrypt-acl
    default_backend web_backend

# Backend for Web UI and Let's Encrypt validation (exposed locally on port 8088)
backend web_backend
    server web 127.0.0.1:8088

# Backend for API (exposed locally on port 3000)
backend api_backend
    mode http
    server api 127.0.0.1:3000

# Dynamic backends (generated by API)
#DYNAMIC_BACKENDS#

# SPOE backend for ModSecurity agent (exposed locally on port 12345)
backend spoa
    mode tcp
    timeout connect 5s
    timeout server 5m
    server modsecurity-agent 127.0.0.1:12345

# HAProxy Stats
frontend stats
    bind *:8404
    stats enable
    stats uri /stats
    stats refresh 30s
    stats admin if TRUE

# TCP Port Forwarding (generated by API)
#DYNAMIC_TCP_LISTENERS#
`;
}

// Generate dynamic HAProxy config with all domains
async function generateDynamicHAProxyConfig(rules, tcpRules = []) {
  try {
    // Always read from template file (not from generated config)
    // Template should have placeholders: #DYNAMIC_ACLS#, #DYNAMIC_RULES#, #DYNAMIC_BACKENDS#
    const templatePath = path.join(__dirname, '../haproxy/haproxy.cfg');
    let baseConfig;

    if (fs.existsSync(templatePath)) {
      baseConfig = fs.readFileSync(templatePath, 'utf8');
      // If template has been replaced (has backends), we need a clean template
      // Check if it has placeholder markers
      if (!baseConfig.includes('#DYNAMIC_ACLS#') && !baseConfig.includes('#DYNAMIC_BACKENDS#')) {
        // Template has been replaced, read from a backup or use hardcoded template
        console.log('Template appears to be already processed, using hardcoded template');
        baseConfig = getBaseTemplate();
      }
    } else {
      // Fallback to hardcoded template
      console.log('Template file not found, using hardcoded template');
      baseConfig = getBaseTemplate();
    }

    await hydrateRuleBackends(rules);

    // Collect SSL certificates for HTTPS frontend bind
    const sslCertificates = new Set();
    rules.forEach(rule => {
      if (rule.ssl_enabled && rule.ssl_cert) {
        sslCertificates.add(rule.ssl_cert);
      }
    });

    // Generate SSL bind statements for HTTPS frontend
    let sslBinds = '';
    if (sslCertificates.size > 0) {
      // Use SNI (Server Name Indication) for multiple certificates
      const certPaths = Array.from(sslCertificates).map(cert =>
        `crt /etc/ssl/certs/haproxy/${cert}`
      ).join(' ');
      sslBinds = `    bind *:443 ssl ${certPaths}\n`;
    } else {
      // Fallback: use default self-signed cert if no SSL certs (for testing)
      // Check if default cert exists, if not create a generic one
      const defaultCertPath = '/etc/ssl/certs/haproxy/default.pem';
      sslBinds = `    bind *:443 ssl crt ${defaultCertPath}\n`;
      sslBinds += `    # Using default self-signed certificate (for testing)\n`;
    }

    // Generate ACLs and use_backend rules for frontend
    let frontendACLs = '';
    let frontendRules = '';
    let httpRedirects = '';
    const processedRedirects = new Set();
    console.log('Generating dynamic config for', rules.length, 'rules');
    rules.forEach(rule => {
      if (!rule.domain) {
        return;
      }

      const domainLower = rule.domain.toLowerCase();
      frontendACLs += `    acl host_${rule.id} hdr(host) -i ${domainLower}\n`;
      if (rule.path && rule.path !== '/') {
        // Path specified and not root - use path matching
        frontendACLs += `    acl path_${rule.id} path_beg ${rule.path}\n`;
        frontendRules += `    use_backend backend_${rule.id} if host_${rule.id} path_${rule.id}\n`;
      } else {
        // No path or root path - match all paths for this domain
        frontendRules += `    use_backend backend_${rule.id} if host_${rule.id}\n`;
      }

      if (rule.redirect_to_https && rule.ssl_enabled && !processedRedirects.has(rule.id)) {
        processedRedirects.add(rule.id);
        httpRedirects += `    http-request redirect scheme https code 301 if host_${rule.id}\n`;
      }
    });
    console.log('Generated ACLs:', frontendACLs.length, 'chars, Rules:', frontendRules.length, 'chars');

    // Generate backends
    let backends = '';
    rules.forEach(rule => {
      const servers = (rule.backends && rule.backends.length)
        ? rule.backends
        : (rule.backend_host && rule.backend_port ? [{ host: rule.backend_host, port: rule.backend_port }] : []);

      if (!servers.length) {
        return;
      }

      backends += `backend backend_${rule.id}\n`;
      const lbMode = (rule.lb_mode || 'roundrobin').toLowerCase();

      if (servers.length > 1 && lbMode === 'roundrobin') {
        backends += '    balance roundrobin\n';
      }

      servers.forEach((server, index) => {
        const serverName = `${rule.name}_${index + 1}`.replace(/[^a-zA-Z0-9_-]/g, '_');
        const backupFlag = lbMode === 'failover' && index > 0 ? ' backup' : '';

        let serverLine = `    server ${serverName} ${server.host}:${server.port}`;

        // Add SSL options if backend protocol is https
        if (rule.backend_protocol === 'https') {
          // Disable health checks for HTTPS temporarily to bypass handshake issues
          // Traffic will still be SSL/TLS encrypted with SNI
          serverLine += ` ssl verify none sni str(${rule.domain})`;
        } else {
          // Standard HTTP check
          serverLine += ` check inter 3s fall 3 rise 2`;
        }

        if (backupFlag) serverLine += backupFlag;

        backends += `${serverLine}\n`;
      });

      backends += '\n';
    });

    // Replace placeholders in base config
    console.log('Replacing placeholders in base config...');

    // Generate TCP Listeners (Port Forwarding)
    let tcpListeners = '';
    let tcpPortsToOpen = '';

    if (tcpRules && tcpRules.length > 0) {
      console.log('Generating TCP listener config for', tcpRules.length, 'rules');
      tcpRules.forEach(rule => {
        const serverName = rule.name.replace(/[^a-zA-Z0-9_-]/g, '_');
        tcpListeners += `listen tcp_${rule.id}_port_${rule.frontend_port}\n`;
        tcpListeners += `    bind *:${rule.frontend_port}\n`;
        tcpListeners += `    mode ${rule.protocol || 'tcp'}\n`;
        tcpListeners += `    server ${serverName} ${rule.backend_host}:${rule.backend_port} check\n`;
        tcpListeners += `\n`;

        tcpPortsToOpen += `${rule.frontend_port}/${rule.protocol || 'tcp'}\n`;

        // Special handling for FTP (Port 21): Enable Passive Mode ports
        if (parseInt(rule.frontend_port) === 21) {
          tcpListeners += `listen tcp_${rule.id}_passive\n`;
          tcpListeners += `    bind *:30000-30100\n`;
          tcpListeners += `    mode tcp\n`;
          // No port specified on server to preserve client destination port (1-to-1 mapping)
          tcpListeners += `    server ${serverName}_passive ${rule.backend_host} check port 21\n`;
          tcpListeners += `\n`;
          tcpPortsToOpen += `30000-30100/tcp\n`;
        }
      });
    }

    // Write TCP ports to file for Guard Port Manager to pick up
    try {
      const portsDir = '/app/config/haproxy/ports';
      if (!fs.existsSync(portsDir)) fs.mkdirSync(portsDir, { recursive: true });

      // Add default ports
      tcpPortsToOpen += `21/tcp\n`;
      tcpPortsToOpen += `80/tcp\n`;
      tcpPortsToOpen += `443/tcp\n`;

      fs.writeFileSync(path.join(portsDir, 'tcp_ports.txt'), tcpPortsToOpen);
      console.log('Wrote TCP ports to file for Port Manager');
    } catch (err) {
      console.error('Failed to write ports file:', err);
    }

    // Replace placeholders in base config
    console.log('Replacing placeholders in base config...');
    let dynamicConfig = baseConfig
      .replace(/#DYNAMIC_SSL_BINDS#/g, sslBinds)
      .replace(/#DYNAMIC_ACLS#/g, frontendACLs)
      .replace(/#DYNAMIC_HTTP_REDIRECTS#/g, httpRedirects)
      .replace(/#DYNAMIC_RULES#/g, frontendRules)
      .replace(/#DYNAMIC_BACKENDS#/g, backends)
      .replace(/#DYNAMIC_TCP_LISTENERS#/g, tcpListeners);

    // Verify replacements
    const remainingPlaceholders = (dynamicConfig.match(/#DYNAMIC_/g) || []).length;
    console.log('Remaining placeholders after replace:', remainingPlaceholders);

    // Write to mounted haproxy config file (will be read by haproxy container)
    // This path is mounted from host ./haproxy/haproxy.cfg
    const hostConfigPath = '/app/config/haproxy/haproxy.cfg';
    fs.writeFileSync(hostConfigPath, dynamicConfig);
    console.log('Config written to:', hostConfigPath);

    // Also restart HAProxy to apply changes (since include doesn't work)
    console.log('HAProxy config updated, restart required');

    console.log('Dynamic HAProxy config generated with', rules.length, 'rules');
  } catch (error) {
    console.error('Error generating dynamic HAProxy config:', error);
  }
}

// Reload HAProxy configuration using socket API (zero-downtime)
async function reloadHAProxy() {
  try {
    const net = require('net');
    const socketPath = '/app/sockets/haproxy.sock';

    // Try socket API first (zero-downtime reload)
    return new Promise((resolve, reject) => {
      const client = net.createConnection(socketPath, () => {
        console.log('Connected to HAProxy socket, sending reload command...');
        // Send reload command to HAProxy socket
        client.write('reload\n');
        client.end();
        console.log('HAProxy reload command sent via socket (zero-downtime)');
        resolve();
      });

      client.on('error', (error) => {
        console.log('Socket connection failed, falling back to container restart...');
        console.error('Socket error:', error.message);
        // Fallback to container restart if socket unavailable
        fallbackRestart().then(resolve).catch(reject);
      });

      client.setTimeout(5000, () => {
        console.log('Socket timeout, falling back to container restart...');
        client.destroy();
        fallbackRestart().then(resolve).catch(reject);
      });
    });
  } catch (error) {
    console.error('Error in reloadHAProxy:', error);
    return fallbackRestart();
  }
}

// Fallback: Restart HAProxy container using Docker HTTP API
async function fallbackRestart() {
  try {
    console.log('Restarting HAProxy container via Docker API...');

    // Use Docker HTTP API via Unix socket
    const socketPath = '/var/run/docker.sock';

    return new Promise((resolve, reject) => {
      // Docker HTTP API: POST /containers/{id}/restart
      const postData = '';
      const options = {
        socketPath: socketPath,
        path: '/containers/haproxy/restart?t=5',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': postData.length
        }
      };

      const clientRequest = http.request(options, (res) => {
        let data = '';
        res.on('data', (chunk) => { data += chunk; });
        res.on('end', () => {
          if (res.statusCode === 204 || res.statusCode === 200) {
            console.log('HAProxy container restarted successfully via Docker API');
            resolve();
          } else {
            console.error(`Docker API returned status ${res.statusCode}: ${data}`);
            reject(new Error(`Docker API error: ${res.statusCode}`));
          }
        });
      });

      clientRequest.on('error', (error) => {
        console.error('Error calling Docker API:', error.message);
        // Last resort: try exec
        tryExecRestart().then(resolve).catch(reject);
      });

      clientRequest.write(postData);
      clientRequest.end();
    });
  } catch (error) {
    console.error('Error in fallback restart:', error);
    return tryExecRestart();
  }
}

// Last resort: Try exec method
async function tryExecRestart() {
  try {
    const { exec } = require('child_process');
    const util = require('util');
    const execPromise = util.promisify(exec);

    console.log('Trying exec method as last resort...');
    // Try using docker command directly (if available in PATH)
    try {
      await execPromise('docker restart haproxy', { timeout: 10000 });
      console.log('HAProxy restarted via docker command');
      return;
    } catch (e) {
      console.log('Docker command not available, config is updated but HAProxy needs manual restart');
      console.log('Please run: docker-compose restart haproxy');
      // Don't throw - config is updated, just needs manual restart
      return;
    }
  } catch (error) {
    console.error('Error in tryExecRestart:', error);
    // Don't throw - config is updated
  }
}

// Sync certificates from disk to DB
async function syncCertificates() {
  try {
    const diskCerts = await sslManager.listCertificates();
    for (const cert of diskCerts) {
      // Upsert into DB
      const result = await pool.query('SELECT * FROM certificates WHERE domain = $1', [cert.domain]);
      if (result.rows.length === 0) {
        // New cert found on disk
        await pool.query(
          'INSERT INTO certificates (domain, expires_at) VALUES ($1, $2)',
          [cert.domain, cert.expires]
        );
      } else {
        // Update expiry
        await pool.query(
          'UPDATE certificates SET expires_at = $1, updated_at = NOW() WHERE domain = $2',
          [cert.expires, cert.domain]
        );
      }
    }
  } catch (e) {
    console.error('Certificate sync error:', e);
  }
}

// Daily Cron Job for Certificate Renewal
cron.schedule('0 3 * * *', async () => {
  console.log('Running daily certificate renewal check...');
  try {
    const result = await pool.query('SELECT * FROM certificates WHERE auto_renew = true');
    const certs = result.rows;

    for (const cert of certs) {
      // Check expiry (< 30 days)
      if (cert.expires_at) {
        const daysUntilExpiry = (new Date(cert.expires_at) - new Date()) / (1000 * 60 * 60 * 24);
        if (daysUntilExpiry < 30) {
          console.log(`Certificate for ${cert.domain} excludes in ${daysUntilExpiry.toFixed(1)} days. Attempting renewal...`);

          if (cert.provider === 'manual' || cert.provider === 'he-net') {
            console.log(`Skipping auto-renewal for ${cert.domain} (Provider: ${cert.provider}) - Manual action required.`);
            // TODO: Send notification if implementation exists
          } else {
            // Attempt auto-renew via certbot
            // Note: sslManager.renewCertificates() renews ALL efficiently, but we can call it here.
            // It relies on certbot's internal logic which checks expiry.
          }
        }
      }
    }

    // Run standard certbot renew (covers all eligible certs)
    const renewResult = await sslManager.renewCertificates();
    console.log('Certbot renew result:', renewResult);

    // Re-sync after renewal attempt
    await syncCertificates();

  } catch (error) {
    console.error('Daily renewal cron failed:', error);
  }
});
function formatRetryAfterMessage(retryAfter) {
  if (typeof retryAfter === 'number') {
    if (retryAfter < 60) {
      return `${retryAfter} saniye`;
    } else {
      const minutes = Math.floor(retryAfter / 60);
      const seconds = retryAfter % 60;
      return `${minutes} dakika ${seconds} saniye`;
    }
  }
  return 'bir süre';
}

function normalizeBackendsPayload(rawBackends, fallbackHost = null, fallbackPort = null) {
  const list = [];

  if (Array.isArray(rawBackends)) {
    rawBackends.forEach((item) => {
      if (!item) return;
      if (typeof item === 'string') {
        const parts = item.split(':').map((part) => part.trim()).filter(Boolean);
        if (parts.length >= 2) {
          const port = Number(parts[1]);
          if (!Number.isNaN(port) && port > 0 && port < 65536) {
            list.push({ host: parts[0], port });
          }
        }
        return;
      }

      const host = (item.host || '').trim();
      const port = Number(item.port);
      if (host && !Number.isNaN(port) && port > 0 && port < 65536) {
        list.push({ host, port });
      }
    });
  }

  const fallbackHostTrimmed = fallbackHost ? String(fallbackHost).trim() : '';
  const fallbackPortNumber = Number(fallbackPort);
  if (!list.length && fallbackHostTrimmed && !Number.isNaN(fallbackPortNumber) && fallbackPortNumber > 0 && fallbackPortNumber < 65536) {
    list.push({ host: fallbackHostTrimmed, port: fallbackPortNumber });
  }

  const seen = new Set();
  const deduped = [];
  list.forEach((backend) => {
    const key = `${backend.host}:${backend.port}`;
    if (!seen.has(key)) {
      deduped.push(backend);
      seen.add(key);
    }
  });

  return deduped;
}

async function saveRuleBackends(ruleId, backends) {
  await pool.query('DELETE FROM rule_backends WHERE rule_id = $1', [ruleId]);
  if (!backends || !backends.length) {
    return;
  }

  const insertQueries = backends.map((backend) => pool.query(
    'INSERT INTO rule_backends (rule_id, host, port, weight) VALUES ($1, $2, $3, $4)',
    [ruleId, backend.host, backend.port, backend.weight || 1]
  ));

  await Promise.all(insertQueries);
}

async function hydrateRuleBackends(rules) {
  if (!Array.isArray(rules) || rules.length === 0) {
    return rules;
  }

  const ruleIds = rules.map((rule) => rule.id);
  const { rows } = await pool.query(
    'SELECT rule_id, host, port, weight FROM rule_backends WHERE rule_id = ANY($1::int[]) ORDER BY id',
    [ruleIds]
  );

  const backendMap = new Map();
  rows.forEach((row) => {
    if (!backendMap.has(row.rule_id)) {
      backendMap.set(row.rule_id, []);
    }
    backendMap.get(row.rule_id).push({ host: row.host, port: row.port, weight: row.weight });
  });

  rules.forEach((rule) => {
    const mapped = backendMap.get(rule.id) || [];
    if (!mapped.length && rule.backend_host && rule.backend_port) {
      mapped.push({ host: rule.backend_host, port: rule.backend_port });
    }
    rule.backends = mapped;
    rule.lb_mode = (rule.lb_mode || 'roundrobin').toLowerCase();
  });

  return rules;
}

// API Routes

const ALLOWED_MEMBER_ROLES = ['admin', 'operator'];

function requireAuth(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET || 'dev_secret');
    req.user = payload;
    return next();
  } catch (e) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
}

function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden' });
  }
  return next();
}

function isValidEmailAddress(email) {
  return typeof email === 'string' && /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email.trim());
}

function isValidPassword(password) {
  return typeof password === 'string' && password.length >= 8;
}

function sanitizeMember(row) {
  if (!row) return null;
  return {
    id: row.id,
    email: row.email,
    role: row.role,
    created_at: row.created_at
  };
}

// Auth routes
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }
  const r = await pool.query('SELECT * FROM members WHERE email = $1', [email]);
  if (r.rowCount === 0) {
    console.log(`Login failed for ${email}: user not found`);
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const user = r.rows[0];
  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) {
     const passwordHash = await bcrypt.hash(password, 10);
    console.log(`user.password_hash: ${user.password_hash}`);
    console.log(`passwordHash: ${passwordHash}`);
    console.log(`Login failed for ${email}: incorrect password`);
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, process.env.JWT_SECRET || 'dev_secret', { expiresIn: '12h' });
  res.json({ token });
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

// Get all rules
app.get('/api/rules', requireAuth, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM rules ORDER BY created_at DESC');
    const rules = await hydrateRuleBackends(result.rows);
    res.json(rules);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get rule by ID
app.get('/api/rules/:id', requireAuth, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM rules WHERE id = $1', [req.params.id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Rule not found' });
    }
    const rules = await hydrateRuleBackends(result.rows);
    res.json(rules[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Create ingress rule
app.post('/api/rules', requireAuth, async (req, res) => {
  try {
    let {
      name,
      domain,
      path,
      ssl_enabled,
      ssl_type,
      ssl_cert,
      dns_provider,
      redirect_to_https,
      lb_mode,
      backend_protocol,
      backends
    } = req.body;

    const lbModeRaw = (lb_mode || 'roundrobin').toString().toLowerCase();
    const lbMode = ['roundrobin', 'failover'].includes(lbModeRaw) ? lbModeRaw : 'roundrobin';

    const redirectFlag = typeof redirect_to_https === 'boolean'
      ? redirect_to_https
      : (typeof redirect_to_https === 'string' ? redirect_to_https.toLowerCase() === 'true' : false);

    const targets = normalizeBackendsPayload(backends, req.body.backend_host, req.body.backend_port);
    if (!targets.length) {
      return res.status(400).json({ error: 'En az bir backend hedefi belirtilmeli' });
    }

    const primary = targets[0];

    // Auto-create DNS record if domain is under HE.net managed zones
    let dnsCreated = false;
    if (domain && !domain.startsWith('*')) {
      try {
        // Get HE.net credentials from settings
        const heCredsResult = await pool.query('SELECT value FROM settings WHERE key = $1', ['he_credentials']);
        if (heCredsResult.rows.length > 0) {
          const heCreds = JSON.parse(heCredsResult.rows[0].value);
          const baseDomain = HEDNSManager.getBaseDomain(domain);

          // Check if base domain is managed by HE.net (has wildcard cert)
          const certCheck = await pool.query(
            'SELECT * FROM certificates WHERE domain = $1 AND dns_provider = $2',
            [`*.${baseDomain}`, 'he-net']
          );

          if (certCheck.rows.length > 0) {
            console.log(`Auto-creating DNS record for ${domain} on HE.net`);
            const heManager = new HEDNSManager(heCreds.username, heCreds.password);

            // Get HAProxy public IP (from environment or default)
            const publicIP = process.env.HAPROXY_PUBLIC_IP || primary.host;

            const dnsResult = await heManager.addARecord(domain, publicIP, baseDomain);
            dnsCreated = dnsResult.success;
            console.log(`DNS record created: ${domain} -> ${publicIP}`);

            // Auto-select wildcard SSL if available
            if (!ssl_enabled && certCheck.rows.length > 0) {
              ssl_enabled = true;
              ssl_type = 'wildcard';
              ssl_cert = certCheck.rows[0].cert_path;
              dns_provider = 'he-net';
              console.log(`Auto-selected wildcard SSL for ${domain}`);
            }
          }
        }
      } catch (dnsError) {
        console.error('DNS auto-creation failed (continuing anyway):', dnsError.message);
        // Continue with rule creation even if DNS fails
      }
    }

    const result = await pool.query(
      `INSERT INTO rules (name, type, domain, path, backend_host, backend_port, ssl_enabled, ssl_type, ssl_cert, dns_provider, lb_mode, redirect_to_https, backend_protocol)
       VALUES ($1, 'ingress', $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
       RETURNING *`,
      [
        name,
        domain,
        path || null,
        primary.host,
        primary.port,
        ssl_enabled || false,
        ssl_type || 'none',
        ssl_cert || null,
        dns_provider || null,
        lbMode,
        redirectFlag,
        backend_protocol || 'http'
      ]
    );

    const insertedRule = result.rows[0];
    await saveRuleBackends(insertedRule.id, targets);
    insertedRule.backends = targets;
    insertedRule.lb_mode = lbMode;
    insertedRule.dns_auto_created = dnsCreated;

    await generateHAProxyConfig();
    res.json(insertedRule);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update rule
app.put('/api/rules/:id', requireAuth, async (req, res) => {
  try {
    const {
      name,
      domain,
      path,
      ssl_enabled,
      active,
      ssl_type,
      ssl_cert,
      dns_provider,
      redirect_to_https,
      lb_mode,
      backend_protocol,
      backends
    } = req.body;

    const lbModeRaw = (lb_mode || 'roundrobin').toString().toLowerCase();
    const lbMode = ['roundrobin', 'failover'].includes(lbModeRaw) ? lbModeRaw : 'roundrobin';

    const redirectFlag = typeof redirect_to_https === 'boolean'
      ? redirect_to_https
      : (typeof redirect_to_https === 'string' ? redirect_to_https.toLowerCase() === 'true' : false);

    const targets = normalizeBackendsPayload(backends, req.body.backend_host, req.body.backend_port);
    if (!targets.length) {
      return res.status(400).json({ error: 'En az bir backend hedefi belirtilmeli' });
    }

    const primary = targets[0];

    const result = await pool.query(
      `UPDATE rules 
       SET name = $1, domain = $2, path = $3, backend_host = $4, backend_port = $5, 
           ssl_enabled = $6, active = $7, ssl_type = $8, ssl_cert = $9, dns_provider = $10, lb_mode = $11, redirect_to_https = $12, backend_protocol = $13, updated_at = CURRENT_TIMESTAMP
       WHERE id = $14
       RETURNING *`,
      [
        name,
        domain,
        path || null,
        primary.host,
        primary.port,
        ssl_enabled,
        active,
        ssl_type || 'none',
        ssl_cert || null,
        dns_provider || null,
        lbMode,
        redirectFlag,
        backend_protocol || 'http',
        req.params.id
      ]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Rule not found' });
    }

    const updatedRule = result.rows[0];
    await saveRuleBackends(updatedRule.id, targets);
    updatedRule.backends = targets;
    updatedRule.lb_mode = lbMode;

    await generateHAProxyConfig();
    res.json(updatedRule);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Delete rule
app.delete('/api/rules/:id', requireAuth, async (req, res) => {
  try {
    const result = await pool.query('DELETE FROM rules WHERE id = $1 RETURNING *', [req.params.id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Rule not found' });
    }

    const deletedRule = result.rows[0];

    // Auto-delete DNS record if it was auto-created
    if (deletedRule.domain && !deletedRule.domain.startsWith('*')) {
      try {
        // Get HE.net credentials from settings
        const heCredsResult = await pool.query('SELECT value FROM settings WHERE key = $1', ['he_credentials']);
        if (heCredsResult.rows.length > 0) {
          const heCreds = JSON.parse(heCredsResult.rows[0].value);
          const baseDomain = HEDNSManager.getBaseDomain(deletedRule.domain);

          // Check if base domain is managed by HE.net
          const certCheck = await pool.query(
            'SELECT * FROM certificates WHERE domain = $1 AND dns_provider = $2',
            [`*.${baseDomain}`, 'he-net']
          );

          if (certCheck.rows.length > 0) {
            console.log(`Auto-deleting DNS record for ${deletedRule.domain} from HE.net`);
            const heManager = new HEDNSManager(heCreds.username, heCreds.password);

            const dnsResult = await heManager.deleteARecord(deletedRule.domain, baseDomain);
            console.log(`DNS record deleted: ${deletedRule.domain}`);
          }
        }
      } catch (dnsError) {
        console.error('DNS auto-deletion failed (continuing anyway):', dnsError.message);
        // Continue with rule deletion even if DNS deletion fails
      }
    }

    // Delete config file
    const configFile = path.join('/app/config/haproxy', `ingress_${req.params.id}.cfg`);
    if (fs.existsSync(configFile)) {
      fs.unlinkSync(configFile);
    }

    await generateHAProxyConfig();
    res.json({ message: 'Rule deleted' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Port Forwarding Routes

// Get all port forwarding rules
app.get('/api/port-forwarding', requireAuth, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM port_forwarding ORDER BY frontend_port');
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get single port forwarding rule
app.get('/api/port-forwarding/:id', requireAuth, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM port_forwarding WHERE id = $1', [req.params.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Rule not found' });
    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Create port forwarding rule
app.post('/api/port-forwarding', requireAuth, async (req, res) => {
  try {
    const { name, frontend_port, backend_host, backend_port, protocol } = req.body;

    const result = await pool.query(
      `INSERT INTO port_forwarding (name, frontend_port, backend_host, backend_port, protocol)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING *`,
      [name, frontend_port, backend_host, backend_port, protocol || 'tcp']
    );

    await generateHAProxyConfig();
    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update port forwarding rule
app.put('/api/port-forwarding/:id', requireAuth, async (req, res) => {
  try {
    const { name, frontend_port, backend_host, backend_port, protocol, active } = req.body;

    const result = await pool.query(
      `UPDATE port_forwarding 
       SET name = $1, frontend_port = $2, backend_host = $3, backend_port = $4, 
           protocol = $5, active = $6, updated_at = CURRENT_TIMESTAMP
       WHERE id = $7
       RETURNING *`,
      [name, frontend_port, backend_host, backend_port, protocol, active, req.params.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Rule not found' });
    }

    await generateHAProxyConfig();
    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Delete port forwarding rule
app.delete('/api/port-forwarding/:id', requireAuth, async (req, res) => {
  try {
    const result = await pool.query('DELETE FROM port_forwarding WHERE id = $1 RETURNING *', [req.params.id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Rule not found' });
    }

    // Delete config file
    const configFile = path.join('/app/config/haproxy', `portforward_${req.params.id}.cfg`);
    if (fs.existsSync(configFile)) {
      fs.unlinkSync(configFile);
    }

    await generateHAProxyConfig();
    res.json({ message: 'Port forwarding rule deleted' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// SSL Certificate Management

// Get SSL certificates
app.get('/api/ssl/certificates', requireAuth, async (req, res) => {
  try {
    const dbResult = await pool.query('SELECT * FROM certificates ORDER BY created_at DESC');
    const fsCertificates = await sslManager.listCertificates();
    const fsMap = new Map(fsCertificates.map((cert) => [cert.domain, cert]));

    const combined = dbResult.rows.map((row) => {
      const fsInfo = fsMap.get(row.cert_domain) || null;
      return {
        id: row.id,
        domain: row.domain,
        cert_domain: row.cert_domain,
        ssl_type: row.ssl_type,
        dns_provider: row.dns_provider,
        email: row.email,
        expires_at: row.expires_at || fsInfo?.expires || null,
        created_at: row.created_at,
        updated_at: row.updated_at,
        cert_path: row.cert_path,
        haproxy_cert_path: path.join('/app/config/haproxy-certs', `${row.cert_domain}.pem`),
        filesystem: fsInfo
      };
    });

    // Include filesystem certificates that are not present in DB
    fsCertificates.forEach((fsCert) => {
      if (!combined.find((item) => item.cert_domain === fsCert.domain)) {
        combined.push({
          id: null,
          domain: fsCert.domain,
          cert_domain: fsCert.domain,
          ssl_type: 'unknown',
          dns_provider: null,
          email: null,
          expires_at: fsCert.expires || null,
          created_at: null,
          updated_at: null,
          cert_path: fsCert.path,
          haproxy_cert_path: path.join('/app/config/haproxy-certs', `${fsCert.domain}.pem`),
          filesystem: fsCert
        });
      }
    });

    res.json(combined);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get certificates available for a specific domain
app.get('/api/ssl/certificates/available/:domain', requireAuth, async (req, res) => {
  const requestedDomainRaw = req.params.domain || '';
  const requestedDomain = requestedDomainRaw.toLowerCase();
  const normalizedRequested = requestedDomain.replace(/^\*\./, '');

  try {
    const dbResult = await pool.query('SELECT * FROM certificates ORDER BY created_at DESC');
    const fsCertificates = await sslManager.listCertificates();
    const fsMap = new Map(fsCertificates.map((cert) => [cert.domain, cert]));

    const matchesDomain = (record) => {
      if (!record) return false;
      const certDomain = (record.cert_domain || '').toLowerCase();
      if (!certDomain) return false;

      if (record.ssl_type === 'wildcard') {
        if (normalizedRequested === certDomain) return true;
        return normalizedRequested === certDomain || normalizedRequested.endsWith(`.${certDomain}`);
      }

      return normalizedRequested === certDomain || requestedDomain === certDomain;
    };

    const payload = dbResult.rows
      .filter(matchesDomain)
      .map((row) => {
        const fsInfo = fsMap.get(row.cert_domain) || null;
        return {
          id: row.id,
          domain: row.domain,
          cert_domain: row.cert_domain,
          cert_path: row.cert_path,
          ssl_type: row.ssl_type,
          dns_provider: row.dns_provider,
          expires_at: row.expires_at || fsInfo?.expires || null
        };
      });

    // Include filesystem-only certificates if they match and are not already present
    fsCertificates.forEach((fsCert) => {
      const certDomain = (fsCert.domain || '').toLowerCase();
      const alreadyIncluded = payload.find((item) => item.cert_domain && item.cert_domain.toLowerCase() === certDomain);
      const wildcardMatch = normalizedRequested === certDomain || normalizedRequested.endsWith(`.${certDomain}`);
      if (!alreadyIncluded && wildcardMatch) {
        payload.push({
          id: null,
          domain: `*.${fsCert.domain}`,
          cert_domain: fsCert.domain,
          cert_path: `${fsCert.domain}.pem`,
          ssl_type: 'wildcard',
          dns_provider: null,
          expires_at: fsCert.expires || null
        });
      }
    });

    res.json(payload);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get SSL certificate details
app.get('/api/ssl/certificates/:certDomain', requireAuth, async (req, res) => {
  try {
    const { certDomain } = req.params;
    const recordResult = await pool.query(
      'SELECT * FROM certificates WHERE cert_domain = $1 OR domain = $1 LIMIT 1',
      [certDomain]
    );
    const record = recordResult.rows[0] || null;
    const targetDomain = record ? record.cert_domain : certDomain;

    const info = await sslManager.getCertificateInfo(targetDomain);
    if (!info && !record) {
      return res.status(404).json({ error: 'Certificate not found' });
    }

    if (record && !record.expires_at && info?.expiresAt) {
      await pool.query(
        'UPDATE certificates SET expires_at = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2',
        [info.expiresAt, record.id]
      );
      record.expires_at = info.expiresAt;
    }

    const response = {
      record: record ? { ...record, expires_at: record.expires_at || info?.expiresAt || null } : null,
      info
    };

    res.json(response);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Delete SSL certificate
app.delete('/api/ssl/certificates/:certDomain', requireAuth, async (req, res) => {
  const { certDomain } = req.params;

  try {
    const recordResult = await pool.query(
      'SELECT * FROM certificates WHERE cert_domain = $1 OR domain = $1 LIMIT 1',
      [certDomain]
    );
    const record = recordResult.rows[0];
    if (!record) {
      return res.status(404).json({ error: 'Certificate not found' });
    }

    await sslManager.deleteCertificate(record.cert_domain);

    await pool.query('DELETE FROM certificates WHERE cert_domain = $1', [record.cert_domain]);
    await pool.query(
      `UPDATE rules SET ssl_enabled = false, ssl_cert = NULL, ssl_type = 'none', dns_provider = NULL, updated_at = CURRENT_TIMESTAMP
       WHERE ssl_cert = $1`,
      [record.cert_path]
    );

    await generateHAProxyConfig();

    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Request SSL certificate (adds to certificate pool)
app.post('/api/ssl/request', requireAuth, async (req, res) => {
  try {
    const { domain, email, dnsProvider, he_username, he_password, assignToRuleId, retry } = req.body;

    if (!domain || !email) {
      return res.status(400).json({ error: 'Domain ve E-posta adresi zorunludur' });
    }

    // Check for saved credentials if not provided
    let finalHeUsername = he_username;
    let finalHePassword = he_password;

    if (dnsProvider === 'he-net') {
      if (!finalHeUsername || !finalHePassword) {
        // Try to fetch from settings
        const savedResult = await pool.query('SELECT value FROM settings WHERE key = \'he_credentials\'');
        if (savedResult.rows.length > 0) {
          try {
            const savedCreds = JSON.parse(savedResult.rows[0].value);
            if (!finalHeUsername) finalHeUsername = savedCreds.username;
            if (!finalHePassword) finalHePassword = savedCreds.password;
          } catch (e) {
            console.error('Failed to parse saved he_credentials');
          }
        }
      }

      if (!finalHeUsername || !finalHePassword) {
        return res.status(400).json({ error: 'HE.net için kullanıcı adı ve şifre gereklidir (Kaydedilmiş bilgi bulunamadı)' });
      }

      // Save credentials for future use
      try {
        await pool.query(
          `INSERT INTO settings (key, value, updated_at) VALUES ('he_credentials', $1, NOW())
                 ON CONFLICT (key) DO UPDATE SET value = $1, updated_at = NOW()`,
          [JSON.stringify({ username: finalHeUsername, password: finalHePassword })]
        );
      } catch (e) {
        console.error('Failed to save he_credentials', e);
      }
    }

    // If retry is true, check if DNS record exists first
    if (retry) {
      console.log('Retry requested for domain:', domain);
      const baseDomain = domain.startsWith('*.') ? domain.substring(2) : domain;
      const txtDomain = `_acme-challenge.${baseDomain}`;

      // Try to verify DNS TXT record exists (simple check)
      // For retry, we'll proceed with certificate request directly
      // Certbot will check DNS and proceed if TXT record is found
      console.log('Retry: Proceeding with certificate request for:', domain);
    }

    // Note: he-net doesn't have official API, will use manual DNS challenge or acme.sh
    // If retry is true, we'll use a longer timeout and try to continue
    const result = await sslManager.requestCertificate(domain, email, {
      dnsProvider,
      retry: retry || false,
      he_username: finalHeUsername,
      he_password: finalHePassword
    });

    // Log certbot output for debugging
    if (result.stdout || result.stderr) {
      console.log('Certbot output - stdout:', result.stdout);
      console.log('Certbot output - stderr:', result.stderr);
    }

    // Check if manual DNS challenge is required
    if (result.type === 'DNS_CHALLENGE') {
      const txtDomain = result.txtDomain || result.txt_domain || (domain.startsWith('*.') ? `_acme-challenge.${domain.substring(2)}` : `_acme-challenge.${domain}`);
      const txtValue = result.txtValue || result.txt_value || '';
      const sessionId = result.details?.sessionId;

      return res.status(202).json({
        requires_manual_dns: true,
        txt_domain: txtDomain,
        txt_record: txtValue,
        domain: domain,
        session_id: sessionId,
        dns_provider: dnsProvider,
        message: 'Manuel DNS challenge gerekli. Lütfen TXT kaydını ekleyin ve tekrar deneyin.',
        certbot_output: {
          stdout: result.stdout || '',
          stderr: result.stderr || ''
        }
      });
    }

    if (result.success) {
      // Determine certificate filename and type
      const isWildcard = domain.startsWith('*.');
      const certDomain = isWildcard ? domain.substring(2) : domain;
      const certFileName = certDomain;
      const certPath = `${certFileName}.pem`;
      const sslType = isWildcard ? 'wildcard' : 'normal';

      // Get certificate expiry
      const expiry = await sslManager.getCertificateExpiry(domain);

      // Add to certificate pool (database)
      const certResult = await pool.query(`
        INSERT INTO certificates (domain, cert_domain, cert_path, ssl_type, dns_provider, email, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        ON CONFLICT (cert_domain) DO UPDATE SET
          cert_path = EXCLUDED.cert_path,
          expires_at = EXCLUDED.expires_at,
          updated_at = CURRENT_TIMESTAMP
        RETURNING *
      `, [domain, certDomain, certPath, sslType, dnsProvider || null, email, expiry]);

      // If assignToRuleId is provided, assign certificate to that rule
      if (assignToRuleId) {
        await pool.query(
          `UPDATE rules SET ssl_enabled = true, ssl_cert = $1, ssl_type = $2, dns_provider = $3 WHERE id = $4`,
          [certPath, sslType, dnsProvider || null, assignToRuleId]
        );

        // Regenerate HAProxy config
        await generateHAProxyConfig();
      }

      res.json({
        ...result,
        certificate: certResult.rows[0],
        certbot_output: {
          stdout: result.stdout || '',
          stderr: result.stderr || ''
        }
      });
    } else {
      // Check for rate limit error
      if (result.type === 'CERTBOT_ERROR' && result.details && result.details.rateLimit) {
        const formattedMessage = formatRetryAfterMessage(result.details.retryAfter);
        return res.status(429).json({
          success: false,
          error: result.error || 'Let\'s Encrypt rate limit',
          type: 'RATE_LIMIT',
          message: result.error || `Let's Encrypt rate limit: Çok fazla başarısız deneme. ${formattedMessage}`,
          retryAfter: result.details.retryAfter,
          certbot_output: {
            stdout: result.stdout || '',
            stderr: result.stderr || ''
          }
        });
      }

      res.status(500).json({
        ...result,
        certbot_output: {
          stdout: result.stdout || '',
          stderr: result.stderr || '',
          fullOutput: result.fullOutput || ''
        }
      });
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Settings API
app.get('/api/settings/:key', requireAuth, async (req, res) => {
  try {
    const { key } = req.params;
    const result = await pool.query('SELECT value FROM settings WHERE key = $1', [key]);
    if (result.rows.length === 0) {
      return res.json({ value: null });
    }
    res.json({ value: result.rows[0].value });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/settings/:key', requireAuth, async (req, res) => {
  try {
    const { key } = req.params;
    const { value } = req.body;
    await pool.query(
      `INSERT INTO settings (key, value, updated_at) VALUES ($1, $2, NOW())
             ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = NOW()`,
      [key, value]
    );
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update/Change SSL certificate for a domain
app.put('/api/ssl/certificates/:domain', requireAuth, async (req, res) => {
  try {
    const { domain } = req.params;
    const { email, dnsProvider, force } = req.body;

    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }

    // Find rule for this domain
    const ruleResult = await pool.query('SELECT * FROM rules WHERE domain = $1 AND ssl_enabled = true', [domain]);
    if (ruleResult.rows.length === 0) {
      return res.status(404).json({ error: 'No SSL-enabled rule found for this domain' });
    }

    const rule = ruleResult.rows[0];
    const isWildcard = rule.ssl_type === 'wildcard';
    const sslDomain = isWildcard ? `*.${domain}` : domain;
    const dnsProviderToUse = dnsProvider || rule.dns_provider;

    // Request new certificate
    const result = await sslManager.requestCertificate(sslDomain, email, {
      dnsProvider: dnsProviderToUse,
      force: force || false
    });

    if (result.success) {
      const certFileName = isWildcard ? domain : domain;
      const certPath = `${certFileName}.pem`;

      // Update rule with new certificate
      await pool.query(
        `UPDATE rules SET ssl_cert = $1, updated_at = CURRENT_TIMESTAMP WHERE domain = $2`,
        [certPath, domain]
      );

      // Regenerate HAProxy config
      await generateHAProxyConfig();

      res.json({ ...result, message: 'SSL certificate updated successfully' });
    } else {
      res.status(500).json(result);
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Legacy verify endpoint - redirects to continue for backward compatibility
app.post('/api/ssl/verify', requireAuth, async (req, res) => {
  const { domain } = req.body;
  if (!domain) {
    return res.status(400).json({ error: 'Domain is required' });
  }

  try {
    const result = await sslManager.continueManualDNSSession(domain);
    const isWildcard = domain.startsWith('*.');

    if (result.challengeUpdated) {
      return res.status(202).json({
        success: false,
        message: 'Yeni bir DNS challenge üretildi. Lütfen TXT kaydını güncelleyin ve tekrar deneyin.',
        txt_domain: result.txtDomain,
        txt_record: result.txtValue,
        domain,
        running: true
      });
    }

    if (result.success) {
      const certPath = `${result.certDomain}.pem`;
      await pool.query(
        `UPDATE rules SET ssl_enabled = true, ssl_cert = $1, ssl_type = $2 WHERE domain = $3`,
        [certPath, isWildcard ? 'wildcard' : 'normal', result.certDomain]
      );
      await generateHAProxyConfig();

      return res.json({
        success: true,
        message: 'Sertifika başarıyla oluşturuldu',
        stdout: result.logOutput || '',
        stderr: '',
        certDomain: result.certDomain
      });
    }

    return res.status(500).json({
      success: false,
      error: result.message || 'Sertifika oluşturulamadı',
      stdout: result.logOutput || '',
      stderr: ''
    });
  } catch (error) {
    if (error.message && error.message.includes('Timeout waiting for result')) {
      return res.status(202).json({
        success: false,
        message: 'Process hala devam ediyor. DNS kaydının yayılması biraz zaman alabilir. Lütfen birkaç dakika sonra tekrar deneyin.',
        running: true
      });
    }

    res.status(500).json({ error: error.message });
  }
});

// Continue certbot process (send Enter after DNS record is added)
app.post('/api/ssl/continue', requireAuth, async (req, res) => {
  try {
    const { domain } = req.body;
    if (!domain) {
      return res.status(400).json({ error: 'Domain is required' });
    }

    try {
      const result = await sslManager.continueManualDNSSession(domain);
      const isWildcard = domain.startsWith('*.');

      if (result.challengeUpdated) {
        return res.status(202).json({
          success: false,
          message: 'Yeni bir DNS challenge üretildi. Lütfen TXT kaydını güncelleyin ve tekrar deneyin.',
          txt_domain: result.txtDomain,
          txt_record: result.txtValue,
          domain,
          running: true
        });
      }

      if (result.success) {
        const certPath = `${result.certDomain}.pem`;
        const sslTypeValue = isWildcard ? 'wildcard' : 'normal';
        let dnsProviderValue = result.dnsProvider || null;
        const emailValue = result.email || null;

        if (!dnsProviderValue) {
          const providerLookup = await pool.query('SELECT dns_provider FROM rules WHERE domain = $1 LIMIT 1', [result.certDomain]);
          dnsProviderValue = providerLookup.rows[0]?.dns_provider || null;
        }

        await pool.query(
          `UPDATE rules 
           SET ssl_enabled = true, 
               ssl_cert = $1, 
               ssl_type = $2, 
               dns_provider = COALESCE($4, dns_provider),
               updated_at = CURRENT_TIMESTAMP
           WHERE domain = $3`,
          [certPath, sslTypeValue, result.certDomain, dnsProviderValue]
        );

        const expiresAt = await sslManager.getCertificateExpiry(result.certDomain);

        const certResult = await pool.query(`
          INSERT INTO certificates (domain, cert_domain, cert_path, ssl_type, dns_provider, email, expires_at)
          VALUES ($1, $2, $3, $4, $5, $6, $7)
          ON CONFLICT (cert_domain) DO UPDATE SET
            cert_path = EXCLUDED.cert_path,
            ssl_type = EXCLUDED.ssl_type,
            dns_provider = EXCLUDED.dns_provider,
            email = EXCLUDED.email,
            expires_at = EXCLUDED.expires_at,
            updated_at = CURRENT_TIMESTAMP
          RETURNING *
        `, [domain, result.certDomain, certPath, sslTypeValue, dnsProviderValue, emailValue, expiresAt]);

        await generateHAProxyConfig();

        return res.json({
          success: true,
          message: 'Sertifika başarıyla oluşturuldu',
          stdout: result.logOutput || '',
          stderr: '',
          certDomain: result.certDomain,
          certificate: certResult.rows[0] || null
        });
      }

      return res.status(500).json({
        success: false,
        error: result.message || 'Sertifika oluşturulamadı',
        stdout: result.logOutput || '',
        stderr: ''
      });
    } catch (error) {
      if (error.message && error.message.includes('Timeout waiting for result')) {
        return res.status(202).json({
          success: false,
          message: 'Process hala devam ediyor. DNS kaydının yayılması biraz zaman alabilir. Lütfen birkaç dakika sonra tekrar deneyin.',
          running: true
        });
      }

      throw error;
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// SSL Certificates - List
app.get('/api/ssl/certificates', requireAuth, async (req, res) => {
  try {
    // 1. Get real certificates from disk
    const diskCerts = await sslManager.listCertificates();

    // 2. Get DB metadata
    const dbCerts = await pool.query('SELECT * FROM certificates');
    const dbMap = new Map(dbCerts.rows.map(c => [c.domain, c]));

    // 3. Merge
    const merged = diskCerts.map(d_cert => {
      const db_cert = dbMap.get(d_cert.domain) || {};
      return {
        ...d_cert,
        auto_renew: db_cert.auto_renew !== false, // default true
        provider: db_cert.provider || db_cert.dns_provider || 'manual',
        email: db_cert.email
      };
    });

    res.json(merged);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update SSL Certificate Settings (Auto Renew toggle)
app.put('/api/ssl/certificates/:domain', requireAuth, async (req, res) => {
  try {
    const { domain } = req.params;
    const { auto_renew } = req.body;

    // Upsert
    await pool.query(`
            INSERT INTO certificates (domain, auto_renew)
            VALUES ($1, $2)
            ON CONFLICT (domain) DO UPDATE SET
            auto_renew = $2,
            updated_at = NOW()
        `, [domain, auto_renew]);

    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/ssl/renew/:domain', requireAuth, async (req, res) => {
  try {
    const { domain } = req.params;
    // Trigger manual renewal attempt
    // Ideally reuse sslManager.renewCertificates logic but filtered for one domain
    // For now, running general renew is safe as it skips non-expiring certs
    const result = await sslManager.renewCertificates();
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});
app.post('/api/ssl/renew', requireAuth, async (req, res) => {
  try {
    const result = await sslManager.renewCertificates();
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Member management
app.get('/api/members', requireAuth, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, email, role, created_at FROM members ORDER BY created_at DESC');
    res.json(result.rows.map(sanitizeMember));
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/members', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { email, password, role } = req.body;
    if (!isValidEmailAddress(email)) {
      return res.status(400).json({ error: 'Geçerli bir e-posta adresi girin' });
    }
    if (!isValidPassword(password)) {
      return res.status(400).json({ error: 'Şifre en az 8 karakter olmalıdır' });
    }
    const normalizedEmail = email.trim().toLowerCase();
    const normalizedRole = role && ALLOWED_MEMBER_ROLES.includes(role.toLowerCase()) ? role.toLowerCase() : 'operator';
    const passwordHash = await bcrypt.hash(password, 10);
    const insert = await pool.query(
      'INSERT INTO members (email, password_hash, role) VALUES ($1, $2, $3) RETURNING id, email, role, created_at',
      [normalizedEmail, passwordHash, normalizedRole]
    );
    res.status(201).json(sanitizeMember(insert.rows[0]));
  } catch (error) {
    if (error.code === '23505') {
      return res.status(409).json({ error: 'Bu e-posta adresi zaten kayıtlı' });
    }
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/members/:id/password', requireAuth, requireAdmin, async (req, res) => {
  try {
    const memberId = parseInt(req.params.id, 10);
    const { password } = req.body;
    if (!Number.isInteger(memberId) || memberId <= 0) {
      return res.status(400).json({ error: 'Geçersiz kullanıcı' });
    }
    if (!isValidPassword(password)) {
      return res.status(400).json({ error: 'Şifre en az 8 karakter olmalıdır' });
    }
    const passwordHash = await bcrypt.hash(password, 10);
    const updated = await pool.query(
      'UPDATE members SET password_hash = $1 WHERE id = $2 RETURNING id, email, role, created_at',
      [passwordHash, memberId]
    );
    if (updated.rowCount === 0) {
      return res.status(404).json({ error: 'Kullanıcı bulunamadı' });
    }
    res.json(sanitizeMember(updated.rows[0]));
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/members/:id', requireAuth, requireAdmin, async (req, res) => {
  try {
    const memberId = parseInt(req.params.id, 10);
    if (!Number.isInteger(memberId) || memberId <= 0) {
      return res.status(400).json({ error: 'Geçersiz kullanıcı' });
    }
    if (req.user && req.user.id === memberId) {
      return res.status(400).json({ error: 'Kendi hesabınızı silemezsiniz' });
    }
    const deleted = await pool.query('DELETE FROM members WHERE id = $1 RETURNING id', [memberId]);
    if (deleted.rowCount === 0) {
      return res.status(404).json({ error: 'Kullanıcı bulunamadı' });
    }
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/auth/password', requireAuth, async (req, res) => {
  try {
    const { current_password: currentPassword, new_password: newPassword } = req.body || {};
    if (!isValidPassword(newPassword)) {
      return res.status(400).json({ error: 'Yeni şifre en az 8 karakter olmalıdır' });
    }
    const member = await pool.query('SELECT id, password_hash FROM members WHERE id = $1', [req.user.id]);
    if (member.rowCount === 0) {
      return res.status(404).json({ error: 'Kullanıcı bulunamadı' });
    }
    if (member.rows[0].password_hash) {
      const matches = await bcrypt.compare(currentPassword || '', member.rows[0].password_hash);
      if (!matches) {
        return res.status(400).json({ error: 'Mevcut şifre yanlış' });
      }
    }
    const passwordHash = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE members SET password_hash = $1 WHERE id = $2', [passwordHash, req.user.id]);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Start server
async function startServer() {
  await waitForDatabase();
  await initDatabase();
  await generateHAProxyConfig();

  // Schedule config regeneration every 5 minutes
  cron.schedule('*/5 * * * *', async () => {
    await generateHAProxyConfig();
  });

  // Schedule SSL certificate renewal check (daily at 2 AM)
  cron.schedule('0 2 * * *', async () => {
    console.log('Checking SSL certificate renewal...');
    await sslManager.renewCertificates();
  });

  // Debug endpoint: Run Certbot command and show real-time output
  app.post('/api/ssl/debug', requireAuth, async (req, res) => {
    try {
      const { domain, email, dnsProvider, retry } = req.body;

      if (!domain || !email) {
        return res.status(400).json({ error: 'Domain and email are required' });
      }

      const baseDomain = domain.startsWith('*.') ? domain.substring(2) : domain;
      let command;

      const baseCertbotCmd = `certbot certonly --manual \
          --config-dir ${sslManager.certbotDir} \
          --work-dir ${sslManager.certbotWorkDir} \
          --logs-dir ${sslManager.certbotLogsDir} \
          --preferred-challenges dns \
          --email ${email} \
          --agree-tos \
          --no-eff-email \
          --keep-until-expiring \
          -d ${domain} \
          -d ${baseDomain}`;

      if (retry) {
        command = `yes "" | timeout 120 ${baseCertbotCmd}`;
      } else {
        command = baseCertbotCmd;
      }

      console.log('Debug: Running Certbot command:', command);

      // Execute in certbot container and get full output
      const result = await sslManager.executeInCertbotContainer(command, 120000);

      return res.json({
        success: true,
        command: command,
        stdout: result.stdout || '',
        stderr: result.stderr || '',
        exitCode: result.exitCode,
        timeout: result.timeout,
        fullOutput: (result.stdout || '') + (result.stderr || '')
      });
    } catch (error) {
      console.error('Debug endpoint error:', error);
      return res.status(500).json({
        error: error.message,
        stack: error.stack
      });
    }
  });

  // WebSocket server for terminal access
  const wss = new WebSocket.Server({ server, path: '/ws/terminal' });

  wss.on('connection', (ws, req) => {
    console.log('Terminal WebSocket connection established');

    const token = new URL(req.url, 'http://localhost').searchParams.get('token') ||
      req.headers.authorization?.replace('Bearer ', '');

    if (!token) {
      ws.close(1008, 'Authentication required');
      return;
    }

    try {
      jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
    } catch (error) {
      ws.close(1008, 'Invalid token');
      return;
    }

    ws.send('Terminal geçici olarak devre dışı.');
    ws.close();
  });
}

const net = require('net');

// Generic HAProxy Socket Command Runner
function runHAProxyCommand(command) {
  return new Promise((resolve, reject) => {
    const client = net.createConnection(process.env.HAPROXY_SOCKET || '/app/sockets/haproxy.sock');
    let data = '';

    client.setTimeout(2000); // Timeout
    client.on('timeout', () => { client.destroy(); reject(new Error('Socket timeout')); });

    client.on('connect', () => {
      client.write(command + '\n');
    });

    client.on('data', (chunk) => { data += chunk.toString(); });

    client.on('end', () => { resolve(data); });

    client.on('error', (err) => { client.destroy(); reject(err); });
  });
}

// --- High Performance Stats Caching ---
let cachedStats = null;
let lastCacheUpdate = 0;

// Persistent Stats Logic
const STATS_FILE = '/app/data/stats_state.json';
let statsState = { cumulative: 0, lastRaw: 0 };

// Load stats from disk on startup
try {
  if (fs.existsSync(STATS_FILE)) {
    const raw = fs.readFileSync(STATS_FILE, 'utf-8');
    statsState = JSON.parse(raw);
    console.log('Loaded persistent stats:', statsState);
  }
} catch (e) {
  console.error('Failed to load stats file:', e);
}

function saveStatsState() {
  try {
    fs.writeFileSync(STATS_FILE, JSON.stringify(statsState));
  } catch (e) { /* ignore */ }
}

// Poll stats every 1000ms automatically
setInterval(async () => {
  try {
    const data = await runHAProxyCommand('show stat');
    if (data && data.length > 100) {
      cachedStats = data;
      lastCacheUpdate = Date.now();

      // Parse for persistent tracking
      const lines = data.trim().split('\n');
      if (lines.length > 1) {
        // Remove '# ' from header
        const headerLine = lines[0].startsWith('# ') ? lines[0].substring(2) : lines[0];
        const headers = headerLine.split(',');
        const svnameIdx = headers.indexOf('svname');
        const reqTotIdx = headers.indexOf('req_tot');

        if (svnameIdx !== -1 && reqTotIdx !== -1) {
          let currentSessionTotal = 0;
          for (let i = 1; i < lines.length; i++) {
            const cols = lines[i].split(',');
            // Match logic in app.js: sum FRONTEND and BACKEND
            if (cols[svnameIdx] === 'FRONTEND' || cols[svnameIdx] === 'BACKEND') {
              currentSessionTotal += (parseInt(cols[reqTotIdx]) || 0);
            }
          }

          // Calculate Delta
          let delta = currentSessionTotal - statsState.lastRaw;

          // Detect Restart (current < last)
          if (delta < 0) {
            // Restart happened. Assume delta is just current (since it reset to 0)
            delta = currentSessionTotal;
          }

          // Only update if traffic occurred
          if (delta > 0) {
            statsState.cumulative += delta;
            statsState.lastRaw = currentSessionTotal;
            saveStatsState();
          } else {
            // Even if no traffic, update lastRaw to match current (e.g. if it didn't change)
            // But if delta is 0, lastRaw is already equal to currentSessionTotal. 
            // If delta < 0 (restart), we need to update lastRaw.
            statsState.lastRaw = currentSessionTotal;
          }
        }
      }
    }
  } catch (e) {
    // Silent fail
  }
}, 1000);

app.get('/api/ha_stats', requireAuth, async (req, res) => {
  // Return cached data immediately
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('X-Stats-Age', Date.now() - lastCacheUpdate); // Monitoring header
  res.setHeader('X-Cumulative-Req-Tot', statsState.cumulative); // Persistent Total

  if (cachedStats) {
    return res.send(cachedStats);
  }

  // Fallback: If cache is empty
  try {
    const statsCsv = await runHAProxyCommand('show stat');
    cachedStats = statsCsv; // Update cache

    // Note: We don't process persistent stats here for simplicity, the interval will catch it in max 1s
    res.send(statsCsv);
  } catch (error) {
    console.error('Stats Socket Error:', error.message);
    res.status(500).json({ error: 'Failed to fetch stats' });
  }
});

// GET /api/ha_sessions - Live Sessions (Raw)
app.get('/api/ha_sessions', requireAuth, async (req, res) => {
  try {
    const output = await runHAProxyCommand('show sess');
    // DEBUG LOGGING
    console.log(`[DEBUG] Session Raw Output Length: ${output.length}`);

    const lines = output.trim().split('\n');
    console.log(`[DEBUG] Raw Lines Count: ${lines.length}`);
    if (lines.length > 0) {
      console.log(`[DEBUG] First Line Sample: ${lines[0]}`);
    }

    const sessions = lines.map(line => {
      const parts = {};
      line.trim().split(/\s+/).forEach(p => {
        const kv = p.split('=');
        if (kv.length === 2) parts[kv[0]] = kv[1];
      });

      // Log if src is missing (filtering reason)
      if (!parts.src) {
        // If src is missing, it's usually Health Checks or Internal Stats
        parts.src = 'Sistem (Internal/Check)';
        if (!parts.fe) parts.fe = 'Local';
        if (!parts.be) parts.be = '-';
      }
      return parts;
    }).filter(s => Object.keys(s).length > 2); // Keep if at least some fields parsed

    console.log(`[DEBUG] Successfully Parsed Sessions: ${sessions.length}`);
    res.json(sessions);
  } catch (error) {
    console.error('Session Socket Error:', error.message);
    res.status(500).json({ error: 'Failed to fetch sessions' });
  }
});

// Debug Endpoint for NAT/IP issues
app.get('/api/debug-headers', (req, res) => {
  res.json({
    canli_baglanti_ip: req.socket.remoteAddress,
    x_forwarded_for: req.headers['x-forwarded-for'],
    x_real_ip: req.headers['x-real-ip'],
    tum_basliklar: req.headers
  });
});

startServer().then(() => {
  // --- Security & Guard API Integration ---
  const GUARD_API = process.env.GUARD_API_URL || 'http://host.docker.internal:5005';

  // GET /api/security/bans - List banned IPs from Guard
  app.get('/api/security/bans', requireAuth, async (req, res) => {
    try {
      const response = await fetch(`${GUARD_API}/bans`);
      if (!response.ok) throw new Error(`Guard API returned ${response.status}`);
      const data = await response.json();
      res.json(data);
    } catch (err) {
      console.error("Guard API Error (List Bans):", err.message);
      // Fallback: return empty list if guard is down so UI doesn't crash
      res.status(503).json({ error: 'Security service unavailable', bans: [] });
    }
  });

  // POST /api/security/unban - Unban an IP via Guard
  app.post('/api/security/unban', requireAuth, async (req, res) => {
    try {
      const { ip } = req.body;
      if (!ip) return res.status(400).json({ error: 'IP address is required' });

      const response = await fetch(`${GUARD_API}/unban`, {
        method: 'POST',
        body: JSON.stringify({ ip }),
        headers: { 'Content-Type': 'application/json' }
      });

      if (!response.ok) throw new Error(`Guard API returned ${response.status}`);
      const data = await response.json();
      res.json(data);
    } catch (err) {
      console.error("Guard API Error (Unban):", err.message);
      res.status(503).json({ error: 'Security service unavailable' });
    }
  });

  // --- Whitelist Management ---

  // GET /api/security/whitelist
  app.get('/api/security/whitelist', requireAuth, async (req, res) => {
    try {
      const response = await fetch(`${GUARD_API}/whitelist`);
      if (!response.ok) throw new Error('Guard API Error');
      const data = await response.json();
      res.json(data);
    } catch (err) {
      console.error("Guard API Error (Whitelist):", err.message);
      res.status(503).json({ whitelist: [] });
    }
  });

  // POST /api/security/whitelist (Add)
  app.post('/api/security/whitelist', requireAuth, async (req, res) => {
    try {
      const response = await fetch(`${GUARD_API}/whitelist`, {
        method: 'POST',
        body: JSON.stringify(req.body),
        headers: { 'Content-Type': 'application/json' }
      });
      const data = await response.json();
      res.json(data);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // POST /api/security/unwhitelist (Remove)
  app.post('/api/security/unwhitelist', requireAuth, async (req, res) => {
    try {
      const response = await fetch(`${GUARD_API}/unwhitelist`, {
        method: 'POST',
        body: JSON.stringify(req.body),
        headers: { 'Content-Type': 'application/json' }
      });
      const data = await response.json();
      res.json(data);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // --- WAF (ModSecurity) Rules Management ---
  const WAF_RULES_DIR = '/app/config/modsecurity-rules';

  // GET /api/waf/rules - List all rule files
  app.get('/api/waf/rules', requireAuth, async (req, res) => {
    try {
      const files = await fsPromises.readdir(WAF_RULES_DIR);
      const ruleFiles = [];

      for (const file of files) {
        if (file.endsWith('.conf')) {
          const filePath = path.join(WAF_RULES_DIR, file);
          const stats = await fsPromises.stat(filePath);
          const content = await fsPromises.readFile(filePath, 'utf-8');
          const ruleCount = (content.match(/SecRule/gi) || []).length;

          ruleFiles.push({
            name: file,
            size: stats.size,
            modified: stats.mtime,
            ruleCount
          });
        }
      }

      res.json({ rules: ruleFiles });
    } catch (err) {
      if (err.code === 'ENOENT') {
        res.json({ rules: [] });
      } else {
        res.status(500).json({ error: err.message });
      }
    }
  });

  // GET /api/waf/rules/:filename - Get rule file content
  app.get('/api/waf/rules/:filename', requireAuth, async (req, res) => {
    try {
      const filename = req.params.filename;
      if (!filename.endsWith('.conf') || filename.includes('/') || filename.includes('..')) {
        return res.status(400).json({ error: 'Invalid filename' });
      }

      const filePath = path.join(WAF_RULES_DIR, filename);
      const content = await fsPromises.readFile(filePath, 'utf-8');
      res.json({ filename, content });
    } catch (err) {
      if (err.code === 'ENOENT') {
        res.status(404).json({ error: 'File not found' });
      } else {
        res.status(500).json({ error: err.message });
      }
    }
  });

  // PUT /api/waf/rules/:filename - Update rule file
  app.put('/api/waf/rules/:filename', requireAuth, async (req, res) => {
    try {
      const filename = req.params.filename;
      const { content } = req.body;

      if (!filename.endsWith('.conf') || filename.includes('/') || filename.includes('..')) {
        return res.status(400).json({ error: 'Invalid filename' });
      }
      if (typeof content !== 'string') {
        return res.status(400).json({ error: 'Content is required' });
      }

      const filePath = path.join(WAF_RULES_DIR, filename);
      await fsPromises.writeFile(filePath, content, 'utf-8');
      res.json({ status: 'updated', filename });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // POST /api/waf/rules - Create new rule file
  app.post('/api/waf/rules', requireAuth, async (req, res) => {
    try {
      const { filename, content } = req.body;

      if (!filename || !filename.endsWith('.conf')) {
        return res.status(400).json({ error: 'Filename must end with .conf' });
      }
      if (filename.includes('/') || filename.includes('..')) {
        return res.status(400).json({ error: 'Invalid filename' });
      }

      const filePath = path.join(WAF_RULES_DIR, filename);

      // Check if exists
      try {
        await fsPromises.access(filePath);
        return res.status(409).json({ error: 'File already exists' });
      } catch (e) {
        // File doesn't exist, good
      }

      await fsPromises.writeFile(filePath, content || '# Custom WAF Rules\n', 'utf-8');
      res.json({ status: 'created', filename });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // DELETE /api/waf/rules/:filename - Delete rule file
  app.delete('/api/waf/rules/:filename', requireAuth, async (req, res) => {
    try {
      const filename = req.params.filename;

      if (!filename.endsWith('.conf') || filename.includes('/') || filename.includes('..')) {
        return res.status(400).json({ error: 'Invalid filename' });
      }

      const filePath = path.join(WAF_RULES_DIR, filename);
      await fsPromises.unlink(filePath);
      res.json({ status: 'deleted', filename });
    } catch (err) {
      if (err.code === 'ENOENT') {
        res.status(404).json({ error: 'File not found' });
      } else {
        res.status(500).json({ error: err.message });
      }
    }
  });

  // --- Log Access Endpoint ---
  app.get('/api/logs/access', requireAuth, async (req, res) => {
    const limit = parseInt(req.query.limit) || 50;
    const search = req.query.search || '';
    const LOG_FILE = '/logs/haproxy/haproxy.log';

    try {
      const { exec } = require('child_process');

      let cmd = `tail -n ${limit} ${LOG_FILE}`;
      if (search) {
        if (!/^[a-zA-Z0-9.:-]+$/.test(search)) return res.status(400).json({ error: 'Invalid search' });
        cmd = `grep "${search}" ${LOG_FILE} | tail -n ${limit}`;
      }

      exec(cmd, { maxBuffer: 1024 * 1024 }, (error, stdout, stderr) => {
        if (error && error.code !== 1) {
          console.error('Log read error:', error);
          return res.status(500).json({ error: 'Failed to read logs' });
        }

        // Parse raw syslog lines into JSON objects
        // Format example: <134>Jan 29 13:13:38 haproxy[8]: 192.168.1.1:1234 ...
        const lines = stdout.trim().split('\n').reverse(); // Newest first
        const logs = lines.map(line => {
          // Simple parsing logic
          const parts = line.split(']: ');
          if (parts.length < 2) return { raw: line };

          const header = parts[0];
          const body = parts.slice(1).join(']: '); // Rejoin rest

          // Extract timestamp from header (Jan 29 13:13:38)
          const timeMatch = header.match(/>(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})/);
          const timestamp = timeMatch ? timeMatch[1] : '';

          // Body: ip:port [date] frontend backend ...
          // 195.87.80.179:40622 [29/Jan/2026:13:13:38.359] ...
          const ipMatch = body.match(/^([\d.]+):/);
          const ip = ipMatch ? ipMatch[1] : '-';

          // Request: "GET /foo HTTP/1.1"
          const reqMatch = body.match(/"([^"]+)"/);
          const request = reqMatch ? reqMatch[1] : '-';

          // Status code: usually after backend info
          // regex is tricky for all cases, let's keep it simple or raw
          // A common log format match:
          // IP:PORT [DATE] FRONT BACKEND ... STATUS BYTES ... "REQUEST"

          return {
            raw: line,
            timestamp,
            ip,
            request
          };
        });

        res.json({ logs });
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // --- OWASP CRS Management Endpoints ---

  app.get('/api/waf/crs', requireAuth, async (req, res) => {
    try {
      const rules = await crsManager.listRules();
      res.json(rules);
    } catch (err) {
      console.error('Error listing CRS rules:', err);
      res.status(500).json({ error: err.message });
    }
  });

  app.get('/api/waf/crs/:filename', requireAuth, async (req, res) => {
    try {
      const content = await crsManager.getRuleContent(req.params.filename);
      res.send(content);
    } catch (err) {
      console.error(`Error reading CRS rule ${req.params.filename}:`, err);
      res.status(500).json({ error: err.message });
    }
  });

  app.post('/api/waf/crs/:filename', requireAuth, async (req, res) => {
    try {
      const { content } = req.body;
      if (typeof content !== 'string') {
        return res.status(400).json({ error: 'Content is required' });
      }
      await crsManager.saveRuleContent(req.params.filename, content);
      res.json({ success: true });
    } catch (err) {
      console.error(`Error saving CRS rule ${req.params.filename}:`, err);
      res.status(500).json({ error: err.message });
    }
  });

  app.post('/api/waf/crs/:filename/toggle', requireAuth, async (req, res) => {
    try {
      const { enable } = req.body;
      if (typeof enable !== 'boolean') {
        return res.status(400).json({ error: 'Enable status is required' });
      }
      const result = await crsManager.toggleRule(req.params.filename, enable);
      res.json(result);
    } catch (err) {
      console.error(`Error toggling CRS rule ${req.params.filename}:`, err);
      res.status(500).json({ error: err.message });
    }
  });

  app.post('/api/waf/reload-spoa', requireAuth, async (req, res) => {
    try {
      await crsManager.reloadSPOA();
      res.json({ success: true });
    } catch (err) {
      console.error('Error reloading SPOA:', err);
      res.status(500).json({ error: err.message });
    }
  });

  // POST /api/waf/reload - Reload SPOA container
  app.post('/api/waf/reload', requireAuth, async (req, res) => {
    try {
      const { exec } = require('child_process');
      exec('docker restart haproxy-spoa', (error, stdout, stderr) => {
        if (error) {
          return res.status(500).json({ error: stderr || error.message });
        }
        res.json({ status: 'reloaded', message: 'SPOA container restarted' });
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // --- WAF Events (ModSecurity Audit Log) ---
  const MODSEC_AUDIT_LOG = '/app/config/modsecurity-logs/audit.log';

  app.get('/api/waf/events', requireAuth, async (req, res) => {
    const limit = Math.min(parseInt(req.query.limit, 10) || 100, 500);

    try {
      let content;
      try {
        content = await fsPromises.readFile(MODSEC_AUDIT_LOG, 'utf-8');
      } catch (err) {
        if (err.code === 'ENOENT') {
          return res.json({ events: [], message: 'Audit log not found. ModSecurity may not have logged any events yet.' });
        }
        throw err;
      }

      if (!content || !content.trim()) {
        return res.json({ events: [], message: 'Audit log is empty.' });
      }

      // ModSecurity v2 audit log: blocks separated by "--<id>-A--" markers
      // Sections: A (request line), B (request headers), H (audit trailer with messages), Z (end)
      const events = [];
      // Split on section-A markers: "--xxxxxxxx-A--"
      const blockPattern = /--([A-Za-z0-9]+)-A--\n([\s\S]*?)(?=--[A-Za-z0-9]+-A--|$)/g;
      let match;

      while ((match = blockPattern.exec(content)) !== null) {
        const blockId = match[1];
        const blockBody = match[2];

        // Section A: first line contains timestamp, unique id, source IP, ports
        // Format: [DD/Mon/YYYY:HH:MM:SS +ZZZZ] uniqueid sourceIP sourcePort destIP destPort
        const sectionAMatch = blockBody.match(/\[([^\]]+)\]\s+(\S+)\s+([\d.]+)\s+(\d+)/);
        const timestamp = sectionAMatch ? sectionAMatch[1] : '';
        const clientIp = sectionAMatch ? sectionAMatch[3] : '';

        // Section H: find "Message:" lines with rule details
        // e.g. Message: Warning. Matched ... [id "XXXXX"] [msg "..."] [severity "..."]
        // We must find the H section content
        const sectionHMatch = blockBody.match(/--[A-Za-z0-9]+-H--\n([\s\S]*?)(?=--[A-Za-z0-9]+-[A-Z]--|$)/);
        const sectionH = sectionHMatch ? sectionHMatch[1] : '';

        // Parse the request URI from section B
        const sectionBMatch = blockBody.match(/--[A-Za-z0-9]+-B--\n([\s\S]*?)(?=--[A-Za-z0-9]+-[A-Z]--|$)/);
        const sectionB = sectionBMatch ? sectionBMatch[1] : '';
        const requestLineMatch = sectionB.match(/^([A-Z]+)\s+(\S+)\s+HTTP/m);
        const method = requestLineMatch ? requestLineMatch[1] : '';
        const uri = requestLineMatch ? requestLineMatch[2] : '';

        // Extract all Message lines from section H
        const messageLines = sectionH.match(/^Message:.*$/mg) || [];

        if (messageLines.length === 0) continue;

        for (const msgLine of messageLines) {
          const ruleIdMatch = msgLine.match(/\[id "(\d+)"\]/);
          const msgMatch = msgLine.match(/\[msg "([^"]+)"\]/);
          const severityMatch = msgLine.match(/\[severity "([^"]+)"\]/);
          const actionMatch = msgLine.match(/^Message:\s*(Warning|Alert|Critical|Error|Notice|Info)\./i);

          events.push({
            block_id: blockId,
            timestamp,
            client_ip: clientIp,
            method,
            uri,
            rule_id: ruleIdMatch ? ruleIdMatch[1] : '',
            message: msgMatch ? msgMatch[1] : msgLine.replace(/^Message:\s*/, '').substring(0, 200),
            severity: severityMatch ? severityMatch[1] : '',
            action: actionMatch ? actionMatch[1] : 'Detection'
          });
        }

        if (events.length >= limit * 5) break; // Safety limit while parsing
      }

      // Return newest first, limited
      events.reverse();
      res.json({ events: events.slice(0, limit) });
    } catch (err) {
      console.error('WAF events error:', err);
      res.status(500).json({ error: err.message });
    }
  });

  // --- Global WAF Rule Management (HAProxy-level ACL lists) ---
  const HAPROXY_ACL_DIR = '/app/config/haproxy';
  const HAPROXY_MAPS_ACLS_DIR = '/app/config/haproxy_maps';

  const GLOBAL_WAF_FILES = {
    ip_blacklist: path.join(HAPROXY_ACL_DIR, 'ip_blacklist.lst'),
    bad_useragents: path.join(HAPROXY_MAPS_ACLS_DIR, 'bad_useragents.lst')
  };

  async function readListFile(filePath) {
    try {
      const content = await fsPromises.readFile(filePath, 'utf-8');
      return content.split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#'));
    } catch (err) {
      if (err.code === 'ENOENT') return [];
      throw err;
    }
  }

  async function writeListFile(filePath, entries) {
    await fsPromises.writeFile(filePath, entries.join('\n') + (entries.length ? '\n' : ''), 'utf-8');
  }

  // GET /api/waf/global/:type — list entries
  app.get('/api/waf/global/:type', requireAuth, async (req, res) => {
    const { type } = req.params;
    if (!GLOBAL_WAF_FILES[type]) return res.status(400).json({ error: 'Invalid type. Allowed: ip_blacklist, bad_useragents' });
    try {
      const entries = await readListFile(GLOBAL_WAF_FILES[type]);
      res.json({ entries });
    } catch (err) {
      console.error(`Error reading global WAF list (${type}):`, err);
      res.status(500).json({ error: err.message });
    }
  });

  // POST /api/waf/global/:type — add entry
  app.post('/api/waf/global/:type', requireAuth, async (req, res) => {
    const { type } = req.params;
    if (!GLOBAL_WAF_FILES[type]) return res.status(400).json({ error: 'Invalid type. Allowed: ip_blacklist, bad_useragents' });
    const { entry } = req.body;
    if (!entry || typeof entry !== 'string') return res.status(400).json({ error: 'entry is required' });
    const cleanEntry = entry.trim();
    if (!cleanEntry) return res.status(400).json({ error: 'entry cannot be empty' });
    try {
      const entries = await readListFile(GLOBAL_WAF_FILES[type]);
      if (entries.includes(cleanEntry)) return res.status(409).json({ error: 'Entry already exists' });
      entries.push(cleanEntry);
      await writeListFile(GLOBAL_WAF_FILES[type], entries);
      try { await reloadHAProxy(); } catch (reloadErr) { console.warn('HAProxy reload after global WAF add failed:', reloadErr.message); }
      res.json({ entries, message: 'Entry added and HAProxy reloaded.' });
    } catch (err) {
      console.error(`Error adding global WAF entry (${type}):`, err);
      res.status(500).json({ error: err.message });
    }
  });

  // DELETE /api/waf/global/:type — remove entry
  app.delete('/api/waf/global/:type', requireAuth, async (req, res) => {
    const { type } = req.params;
    if (!GLOBAL_WAF_FILES[type]) return res.status(400).json({ error: 'Invalid type. Allowed: ip_blacklist, bad_useragents' });
    const { entry } = req.body;
    if (!entry || typeof entry !== 'string') return res.status(400).json({ error: 'entry is required' });
    const cleanEntry = entry.trim();
    try {
      const entries = await readListFile(GLOBAL_WAF_FILES[type]);
      const newEntries = entries.filter(e => e !== cleanEntry);
      if (newEntries.length === entries.length) return res.status(404).json({ error: 'Entry not found' });
      await writeListFile(GLOBAL_WAF_FILES[type], newEntries);
      try { await reloadHAProxy(); } catch (reloadErr) { console.warn('HAProxy reload after global WAF delete failed:', reloadErr.message); }
      res.json({ entries: newEntries, message: 'Entry removed and HAProxy reloaded.' });
    } catch (err) {
      console.error(`Error removing global WAF entry (${type}):`, err);
      res.status(500).json({ error: err.message });
    }
  });

  // Start Server
  server.listen(PORT, () => {
    console.log(`HAProxy Management API running on port ${PORT}`);
  }).setTimeout(300000); // 5 minutes timeout for long running SSL requests
}).catch((error) => {
  console.error('Failed to start server', error);
  process.exit(1);
});