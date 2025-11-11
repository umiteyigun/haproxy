const { exec, spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const util = require('util');

const execPromise = util.promisify(exec);

function formatRetryAfterMessage(retryAfter) {
  if (!retryAfter) {
    return 'Lütfen 1 saat sonra tekrar deneyin.';
  }

  try {
    const utcMatch = retryAfter.match(/(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})/);
    if (!utcMatch) {
      return `Tekrar deneme: ${retryAfter}`;
    }

    const utcString = `${utcMatch[1]} UTC`;
    const utcDate = new Date(utcString);
    const turkeyDate = new Date(utcDate.getTime() + (3 * 60 * 60 * 1000));

    const format = (date, suffix) => date
      .toISOString()
      .replace('T', ' ')
      .substring(0, 19) + ` ${suffix}`;

    return `Tekrar deneme: ${format(utcDate, 'UTC')} / ${format(turkeyDate, 'TR')}`;
  } catch (error) {
    return `Tekrar deneme: ${retryAfter}`;
  }
}

class Logger {
  static log(level, message, data) {
    const timestamp = new Date().toISOString();
    if (data) {
      console.log(`[${timestamp}] [${level.toUpperCase()}] ${message}`, JSON.stringify(data, null, 2));
    } else {
      console.log(`[${timestamp}] [${level.toUpperCase()}] ${message}`);
    }
  }

  static info(message, data) { this.log('info', message, data); }
  static warn(message, data) { this.log('warn', message, data); }
  static error(message, data) { this.log('error', message, data); }
  static debug(message, data) { this.log('debug', message, data); }
}

class SSLManagerError extends Error {
  constructor(message, code = 'SSL_ERROR', details = null) {
    super(message);
    this.name = 'SSLManagerError';
    this.code = code;
    this.details = details;
    this.timestamp = new Date().toISOString();
  }
}

class DNSChallengeError extends SSLManagerError {
  constructor(message, txtDomain, txtValue, details = null) {
    super(message, 'DNS_CHALLENGE_ERROR', details);
    this.name = 'DNSChallengeError';
    this.txtDomain = txtDomain;
    this.txtValue = txtValue;
  }
}

class CertbotError extends SSLManagerError {
  constructor(message, stdout = '', stderr = '', exitCode = null, details = null) {
    super(message, 'CERTBOT_ERROR', details);
    this.name = 'CertbotError';
    this.stdout = stdout;
    this.stderr = stderr;
    this.exitCode = exitCode;
  }
}

class SSLManager {
  constructor() {
    this.certbotDir = '/app/config/certbot';
    this.certbotWorkDir = '/app/config/certbot-work';
    this.certbotLogsDir = '/app/config/certbot-logs';
    this.certsDir = path.join(this.certbotDir, 'live');
    this.haproxyCertsDir = '/app/config/haproxy-certs';
    this.credsDir = path.join(this.certbotDir, 'creds');
    this.manualSessionRoot = '/app/tmp/certbot-sessions';

    this.ensureDir(this.certbotDir);
    this.ensureDir(this.certbotWorkDir);
    this.ensureDir(this.certbotLogsDir);
    this.ensureDir(this.credsDir);
    this.manualSessions = new Map();
  }

  ensureDir(dirPath) {
    try {
      if (!fs.existsSync(dirPath)) {
        fs.mkdirSync(dirPath, { recursive: true });
      }
    } catch (error) {
      if (error.code !== 'EEXIST' && error.code !== 'EROFS') {
        throw error;
      }
    }
  }

  ensureSessionRoot() {
    this.ensureDir(this.manualSessionRoot);
  }

  createSessionDir(domain) {
    this.ensureSessionRoot();
    const safeDomain = domain.replace(/[^a-zA-Z0-9.\-_*]/g, '_').replace(/\*/g, 'star');
    const sessionId = `${safeDomain}_${Date.now()}`;
    const sessionDir = path.join(this.manualSessionRoot, sessionId);
    fs.mkdirSync(sessionDir, { recursive: true });
    return { sessionId, sessionDir };
  }

  sanitizeDomain(domain) {
    return domain.startsWith('*.') ? domain.substring(2) : domain;
  }

  getCertificatePaths(domain) {
    const baseDomain = this.sanitizeDomain(domain);
    const certDir = path.join(this.certsDir, baseDomain);
    const fullchainPath = path.join(certDir, 'fullchain.pem');
    const privkeyPath = path.join(certDir, 'privkey.pem');
    const archiveDir = path.join(this.certbotDir, 'archive', baseDomain);
    const renewalConfigPath = path.join(this.certbotDir, 'renewal', `${baseDomain}.conf`);
    const haproxyCertPath = path.join(this.haproxyCertsDir, `${baseDomain}.pem`);

    return {
      baseDomain,
      certDir,
      fullchainPath,
      privkeyPath,
      archiveDir,
      renewalConfigPath,
      haproxyCertPath
    };
  }

  async parseCertificateMetadata(fullchainPath) {
    const command = `openssl x509 -in ${fullchainPath} -noout -subject -issuer -serial -startdate -enddate`;
    const { stdout } = await execPromise(command);
    const lines = stdout.split(/\r?\n/).filter(Boolean);
    const metadata = {};
    lines.forEach((line) => {
      const [key, value] = line.split('=');
      if (!key || typeof value === 'undefined') return;
      const normalizedKey = key.trim().toLowerCase();
      const trimmedValue = value.trim();
      switch (normalizedKey) {
        case 'subject':
          metadata.subject = trimmedValue;
          break;
        case 'issuer':
          metadata.issuer = trimmedValue;
          break;
        case 'serial':
          metadata.serial = trimmedValue;
          break;
        case 'notbefore':
          metadata.notBefore = trimmedValue;
          break;
        case 'notafter':
          metadata.notAfter = trimmedValue;
          break;
        default:
          metadata[normalizedKey] = trimmedValue;
      }
    });
    return metadata;
  }

  async deleteCertificate(certDomain) {
    const { baseDomain, certDir, archiveDir, renewalConfigPath, haproxyCertPath } = this.getCertificatePaths(certDomain);

    const removePath = async (targetPath, options = {}) => {
      try {
        await fs.promises.rm(targetPath, { force: true, recursive: true, ...options });
      } catch (error) {
        if (error.code !== 'ENOENT') {
          throw error;
        }
      }
    };

    await removePath(certDir);
    await removePath(archiveDir);
    await removePath(renewalConfigPath);
    await removePath(haproxyCertPath, { recursive: false });

    return { baseDomain };
  }

  async getCertificateInfo(certDomain) {
    const paths = this.getCertificatePaths(certDomain);
    if (!fs.existsSync(paths.fullchainPath)) {
      return null;
    }

    const [fullchain, metadata, expires] = await Promise.all([
      fs.promises.readFile(paths.fullchainPath, 'utf8'),
      this.parseCertificateMetadata(paths.fullchainPath).catch(() => ({})),
      this.getCertificateExpiry(certDomain)
    ]);

    return {
      baseDomain: paths.baseDomain,
      certDomain: paths.baseDomain,
      fullchainPath: paths.fullchainPath,
      haproxyCertPath: paths.haproxyCertPath,
      certbotPath: paths.certDir,
      renewalConfigPath: paths.renewalConfigPath,
      metadata,
      expiresAt: expires ? expires.toISOString() : null,
      certificate: fullchain
    };
  }

  async waitForJsonFile(filePath, timeoutMs, label) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      try {
        if (fs.existsSync(filePath)) {
          const raw = await fs.promises.readFile(filePath, 'utf8');
          return JSON.parse(raw || '{}');
        }
      } catch (error) {
        Logger.warn(`Failed to parse ${label}`, { filePath, error: error.message });
      }
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
    throw new Error(`Timeout waiting for ${label}`);
  }

  async executeInCertbotContainer(command, timeoutMs = 300000) {
    return new Promise((resolve, reject) => {
      const child = spawn('sh', ['-c', command], {
        stdio: ['ignore', 'pipe', 'pipe']
      });

      let stdout = '';
      let stderr = '';
      let finished = false;

      const cleanup = () => clearTimeout(timer);

      child.stdout.on('data', (data) => {
        stdout += data.toString();
      });

      child.stderr.on('data', (data) => {
        stderr += data.toString();
      });

      child.on('error', (error) => {
        if (finished) return;
        finished = true;
        cleanup();
        reject(new CertbotError(`Certbot process error: ${error.message}`, stdout, stderr, null));
      });

      child.on('close', (code) => {
        if (finished) return;
        finished = true;
        cleanup();
        if (code === 0) {
          resolve({ stdout, stderr, exitCode: 0 });
        } else {
          reject(new CertbotError(`Certbot exited with code ${code}`, stdout, stderr, code));
        }
      });

      const timer = setTimeout(() => {
        if (finished) return;
        finished = true;
        try { child.kill('SIGTERM'); } catch (_) {}
        resolve({ stdout, stderr, exitCode: -1, timeout: true });
      }, timeoutMs);
    });
  }

  async startManualDNSSession(domain, baseDomain, email, dnsProvider = null) {
    const existing = this.manualSessions.get(domain);
    if (existing) {
      Logger.warn('Existing manual session detected, terminating', { domain, sessionId: existing.sessionId });
      try { existing.process?.kill('SIGTERM'); } catch (error) {
        Logger.warn('Failed to terminate existing manual session', { domain, error: error.message });
      }
      this.manualSessions.delete(domain);
    }

    const { sessionId, sessionDir } = this.createSessionDir(domain);
    const scriptPath = path.join(__dirname, 'scripts', 'certbot_dns_manual.expect');

    Logger.info('Starting manual DNS Certbot session', { domain, baseDomain, email, sessionId, sessionDir });

    const child = spawn('expect', [scriptPath, domain, baseDomain, email, sessionDir], {
      stdio: ['ignore', 'pipe', 'pipe']
    });

    const sessionRecord = {
      domain,
      baseDomain,
      email,
      dnsProvider,
      sessionId,
      sessionDir,
      process: child,
      createdAt: Date.now(),
      stdout: '',
      stderr: ''
    };

    child.stdout.on('data', (data) => {
      const text = data.toString();
      sessionRecord.stdout += text;
      Logger.debug('Manual session stdout', { domain, sessionId, text: text.substring(0, 200) });
    });

    child.stderr.on('data', (data) => {
      const text = data.toString();
      sessionRecord.stderr += text;
      Logger.debug('Manual session stderr', { domain, sessionId, text: text.substring(0, 200) });
    });

    child.on('exit', (code) => {
      Logger.info('Manual Certbot session exited', { domain, sessionId, code });
      const info = this.manualSessions.get(domain);
      if (info && !fs.existsSync(path.join(info.sessionDir, 'result.json'))) {
        info.exitCode = code;
        info.exited = true;
      }
    });

    this.manualSessions.set(domain, sessionRecord);

    const challengePath = path.join(sessionDir, 'challenge.json');

    try {
      const challenge = await this.waitForJsonFile(challengePath, 180000, 'challenge');
      sessionRecord.challenge = challenge;
      return { sessionId, sessionDir, challenge };
    } catch (error) {
      Logger.error('Manual DNS challenge did not produce challenge file', { domain, sessionId, error: error.message });
      try { child.kill('SIGTERM'); } catch (_) {}
      this.manualSessions.delete(domain);
      throw error;
    }
  }

  async continueManualDNSSession(domain) {
    const session = this.manualSessions.get(domain);
    if (!session) {
      throw new Error(`Manual DNS session not found for domain: ${domain}`);
    }

    const challengePath = path.join(session.sessionDir, 'challenge.json');
    const resultPath = path.join(session.sessionDir, 'result.json');
    const continuePath = path.join(session.sessionDir, 'continue');
    const logPath = path.join(session.sessionDir, 'certbot.log');

    Logger.info('Continuing manual DNS session', { domain, sessionId: session.sessionId });

    const previousChallenge = session.challenge || {};

    await fs.promises.writeFile(continuePath, new Date().toISOString());

    const maxWaitMs = 90000;
    const pollIntervalMs = 2000;
    const start = Date.now();

    while (Date.now() - start < maxWaitMs) {
      if (fs.existsSync(resultPath)) {
        const raw = await fs.promises.readFile(resultPath, 'utf8');
        let result;
        try {
          result = JSON.parse(raw || '{}');
        } catch (error) {
          Logger.error('Failed to parse manual session result', { domain, error: error.message });
          throw error;
        }

        let logOutput = '';
        if (fs.existsSync(logPath)) {
          logOutput = await fs.promises.readFile(logPath, 'utf8');
        }

        try { session.process?.kill('SIGTERM'); } catch (_) {}
        this.manualSessions.delete(domain);

        const exitCode = result.exitCode ?? result.exit_code ?? 1;
        const success = String(result.success).toLowerCase() === 'true' || result.success === true;
        const certDomain = domain.startsWith('*.') ? session.baseDomain : domain;

        if (success) {
          try {
            await this.prepareCertificateForHAProxy(certDomain);
          } catch (error) {
            Logger.error('Failed to prepare certificate for HAProxy', { domain, error: error.message });
          }
        }

        return {
          success,
          exitCode,
          certDomain,
          message: result.message || '',
          txtDomain: result.txt_domain || result.txtDomain,
          txtValue: result.txt_value || result.txtValue,
          logOutput,
          email: session.email,
          dnsProvider: session.dnsProvider,
          sessionId: session.sessionId
        };
      }

      if (fs.existsSync(challengePath)) {
        try {
          const raw = await fs.promises.readFile(challengePath, 'utf8');
          const challenge = JSON.parse(raw || '{}');

          const newValue = challenge.txt_value || challenge.txtValue;
          const oldValue = previousChallenge.txt_value || previousChallenge.txtValue;

          if (newValue && newValue !== oldValue) {
            session.challenge = challenge;
            return {
              success: false,
              challengeUpdated: true,
              txtDomain: challenge.txt_domain || challenge.txtDomain,
              txtValue: newValue,
              email: session.email,
              dnsProvider: session.dnsProvider,
              sessionId: session.sessionId
            };
          }
        } catch (error) {
          Logger.warn('Failed to read updated challenge file', { domain, error: error.message });
        }
      }

      await new Promise(resolve => setTimeout(resolve, pollIntervalMs));
    }

    Logger.error('Manual DNS session did not finish in time', { domain, sessionId: session.sessionId });
    throw new Error('Timeout waiting for result');
  }

  async requestCertificate(domain, email, options = {}) {
    const requestId = Math.random().toString(36).substring(7);
    const isWildcard = domain.startsWith('*.');
    const baseDomain = isWildcard ? domain.substring(2) : domain;
    const dnsProviderRaw = options.dnsProvider || null;
    const dnsProvider = dnsProviderRaw ? dnsProviderRaw.toLowerCase() : null;

    Logger.info('Starting SSL certificate request', {
      requestId,
      domain,
      email,
      options,
      isWildcard
    });

    try {
      Logger.debug('Certificate request parameters', {
        requestId,
        isWildcard,
        baseDomain,
        dnsProvider: dnsProviderRaw
      });

      let stdout = '';
      let stderr = '';

      if (isWildcard) {
        const providerKey = dnsProvider || 'he-net';
        const pluginMap = {
          'he-net': null,
          'cloudflare': 'cloudflare',
          'route53': 'route53',
          'digitalocean': 'digitalocean',
          'godaddy': 'godaddy'
        };
        const pluginName = pluginMap[providerKey] || null;

        if (!pluginName) {
          const manual = await this.startManualDNSSession(domain, baseDomain, email, providerKey);
          const challenge = manual.challenge || {};

          throw new DNSChallengeError(
            'Manual DNS challenge required',
            challenge.txt_domain,
            challenge.txt_value,
            {
              domain,
              baseDomain,
              dnsProvider: providerKey,
              sessionId: manual.sessionId
            }
          );
        }

        const credentialsPath = path.join(this.credsDir, `${providerKey}.ini`);
        const command = `certbot certonly --dns-${pluginName} \
          --config-dir ${this.certbotDir} \
          --work-dir ${this.certbotWorkDir} \
          --logs-dir ${this.certbotLogsDir} \
          --dns-${pluginName}-credentials ${credentialsPath} \
          --email ${email} \
          --agree-tos \
          --no-eff-email \
          --keep-until-expiring \
          -d ${domain} \
          -d ${baseDomain}`;

        const result = await this.executeInCertbotContainer(command, 300000);
        stdout = result.stdout || '';
        stderr = result.stderr || '';
      } else {
        const command = `certbot certonly --webroot \
          --config-dir ${this.certbotDir} \
          --work-dir ${this.certbotWorkDir} \
          --logs-dir ${this.certbotLogsDir} \
          --webroot-path=/app/config/certbot-www \
          --email ${email} \
          --agree-tos \
          --no-eff-email \
          --keep-until-expiring \
          -d ${domain}`;

        const result = await this.executeInCertbotContainer(command, 300000);
        stdout = result.stdout || '';
        stderr = result.stderr || '';
      }

      const certDomain = isWildcard ? baseDomain : domain;

      try {
        await this.prepareCertificateForHAProxy(certDomain);
      } catch (prepareError) {
        Logger.error('Error preparing certificate for HAProxy', { requestId, error: prepareError.message });
      }

      Logger.info('SSL certificate request completed successfully', {
        requestId,
        domain,
        isWildcard,
        dnsProvider: dnsProviderRaw
      });

      return {
        success: true,
        domain,
        message: 'Sertifika başarıyla oluşturuldu',
        stdout: stdout || '',
        stderr: stderr || '',
        requestId
      };
    } catch (error) {
      Logger.error('SSL certificate request failed', {
        requestId,
        domain,
        errorType: error.constructor.name,
        errorCode: error.code,
        errorMessage: error.message,
        stack: error.stack
      });

      if (error instanceof DNSChallengeError) {
        return {
          success: false,
          error: error.message,
          type: 'DNS_CHALLENGE',
          txtDomain: error.txtDomain,
          txtValue: error.txtValue,
          details: error.details
        };
      }

      if (error instanceof CertbotError) {
        return {
          success: false,
          error: error.message,
          type: 'CERTBOT_ERROR',
          stdout: error.stdout,
          stderr: error.stderr,
          exitCode: error.exitCode,
          details: error.details
        };
      }

      if (error instanceof SSLManagerError) {
        return {
          success: false,
          error: error.message,
          type: error.code,
          details: error.details
        };
      }

      return {
        success: false,
        error: error.message,
        type: 'UNKNOWN_ERROR'
      };
    }
  }

  async prepareCertificateForHAProxy(domain) {
    const certDir = path.join(this.certsDir, domain);
    const fullchainPath = path.join(certDir, 'fullchain.pem');
    const privkeyPath = path.join(certDir, 'privkey.pem');

    if (!fs.existsSync(fullchainPath) || !fs.existsSync(privkeyPath)) {
      throw new Error('Sertifika dosyaları bulunamadı');
    }

    this.ensureDir(this.haproxyCertsDir);

    const fullchain = await fs.promises.readFile(fullchainPath, 'utf8');
    const privkey = await fs.promises.readFile(privkeyPath, 'utf8');
    const combined = `${fullchain}\n${privkey}`;

    const certFileName = domain.startsWith('*.') ? domain.substring(2) : domain;
    const haproxyCertPath = path.join(this.haproxyCertsDir, `${certFileName}.pem`);

    await fs.promises.writeFile(haproxyCertPath, combined, { mode: 0o644 });
    Logger.info('Certificate prepared for HAProxy', { domain, haproxyCertPath });

    return { success: true, path: haproxyCertPath };
  }

  async getCertificateExpiry(domain) {
    const certDomain = domain.startsWith('*.') ? domain.substring(2) : domain;
    const fullchainPath = path.join(this.certsDir, certDomain, 'fullchain.pem');

    if (!fs.existsSync(fullchainPath)) {
      return null;
    }

    const command = `openssl x509 -in ${fullchainPath} -noout -enddate`;
    try {
      const { stdout } = await execPromise(command);
      const match = stdout.match(/notAfter=(.*)/);
      if (!match) {
        return null;
      }
      return new Date(match[1]);
    } catch (error) {
      Logger.error('Failed to read certificate expiry', { domain, error: error.message });
      return null;
    }
  }

  async listCertificates() {
    if (!fs.existsSync(this.certsDir)) {
      return [];
    }

    const directories = fs.readdirSync(this.certsDir, { withFileTypes: true })
      .filter((entry) => entry.isDirectory())
      .map((entry) => entry.name);

    const results = [];
    for (const dir of directories) {
      const fullchainPath = path.join(this.certsDir, dir, 'fullchain.pem');
      if (!fs.existsSync(fullchainPath)) {
        continue;
      }

      const stats = fs.statSync(fullchainPath);
      const expires = await this.getCertificateExpiry(dir);

      results.push({
        domain: dir,
        path: fullchainPath,
        modified: stats.mtime.toISOString(),
        expires: expires ? expires.toISOString() : null
      });
    }

    return results;
  }

  async renewCertificates() {
    try {
      const command = `certbot renew --quiet --config-dir ${this.certbotDir} --work-dir ${this.certbotWorkDir} --logs-dir ${this.certbotLogsDir}`;
      const result = await this.executeInCertbotContainer(command, 300000);

      const certificates = await this.listCertificates();
      for (const cert of certificates) {
        try {
          await this.prepareCertificateForHAProxy(cert.domain);
        } catch (error) {
          Logger.error('Failed to prepare renewed certificate for HAProxy', { domain: cert.domain, error: error.message });
        }
      }

      return {
        success: true,
        message: 'Sertifikalar yenilendi',
        stdout: result.stdout,
        stderr: result.stderr
      };
    } catch (error) {
      Logger.error('Certificate renewal error', { error: error.message });
      return {
        success: false,
        error: error.message,
        type: error.code || 'RENEW_ERROR',
        details: error.details || null
      };
    }
  }
}

module.exports = SSLManager;

