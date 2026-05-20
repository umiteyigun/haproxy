// ─── Auth ─────────────────────────────────────────────────────────────────────
export interface LoginRequest { email: string; password: string; }
export interface LoginResponse { token: string; }

// ─── Ingress Rules ────────────────────────────────────────────────────────────
export interface RuleBackend {
  id?: number;
  rule_id?: number;
  host: string;
  port: number;
  weight?: number;
}

export interface Rule {
  id: number;
  name: string;
  type?: string;
  domain: string;
  path?: string | null;
  frontend_port?: number;
  backend_host: string;
  backend_port: number;
  ssl_enabled: boolean;
  ssl_cert?: string | null;
  ssl_type?: string;
  dns_provider?: string | null;
  lb_mode?: string;
  redirect_to_https?: boolean;
  active?: boolean;
  backend_protocol?: string;
  backends?: RuleBackend[];
  created_at?: string;
  updated_at?: string;
}

export interface RuleFormData {
  id?: number;
  name: string;
  domain: string;
  path?: string | null;
  backend_host: string;
  backend_port: number;
  ssl_type: 'none' | 'new' | 'select' | 'wildcard';
  ssl_cert?: string | null;
  ssl_cert_id?: string | null;
  dns_provider?: string | null;
  lb_mode: string;
  redirect_to_https: boolean;
  backend_protocol: string;
  extra_backends?: string;
}

// ─── Port Forwarding ─────────────────────────────────────────────────────────
export interface PortForwarding {
  id: number;
  name: string;
  frontend_port: number;
  backend_host: string;
  backend_port: number;
  protocol: 'tcp' | 'udp';
  active?: boolean;
  created_at?: string;
  updated_at?: string;
}

// ─── SSL / Certificates ──────────────────────────────────────────────────────
export interface Certificate {
  id?: number;
  domain: string;
  cert_domain: string;
  cert_path?: string;
  ssl_type: 'wildcard' | 'single' | 'normal';
  dns_provider?: string | null;
  email?: string;
  expires_at?: string | null;
  auto_renew?: boolean;
  created_at?: string;
  updated_at?: string;
}

export interface SslRequestData {
  domain: string;
  email: string;
  ssl_type: 'normal' | 'wildcard';
  dns_provider?: string;
  he_username?: string;
  he_password?: string;
  he_ids?: string;
  cloudflare_api_key?: string;
}

export interface DnsChallenge {
  txt_domain: string;
  txt_value: string;
  domain: string;
  email: string;
  ssl_type: string;
  dns_provider?: string;
}

// ─── Security / Guard ─────────────────────────────────────────────────────────
export interface Ban {
  ip: string;
  count?: number;
  reason?: string;
  banned_at?: string;
  expires_at?: string;
  last_path?: string;
  status_codes?: number[];
}

// ─── WAF ──────────────────────────────────────────────────────────────────────
export interface WafRule {
  filename: string;
  content?: string;
  enabled?: boolean;
  size?: number;
  modified?: string;
}

// ─── Members ──────────────────────────────────────────────────────────────────
export interface Member {
  id: number;
  email: string;
  role: string;
  created_at?: string;
}

// ─── HAProxy Stats ────────────────────────────────────────────────────────────
export interface HaStats {
  pxname: string;
  svname: string;
  status?: string;
  scur?: number;
  stot?: number;
  req_rate?: number;
  conn_rate?: number;
  bin?: number;
  bout?: number;
  ereq?: number;
  econ?: number;
  eresp?: number;
  [key: string]: string | number | undefined;
}

// ─── WAF Events ───────────────────────────────────────────────────────────────
export interface WafEvent {
  block_id?: string;
  timestamp?: string;
  client_ip?: string;
  method?: string;
  uri?: string;
  rule_id?: string;
  message?: string;
  severity?: string;
  action?: string;
}

// ─── Global WAF Rules (HAProxy ACL lists) ────────────────────────────────────
export interface GlobalWafList {
  entries: string[];
  message?: string;
}

// ─── Traffic Log ──────────────────────────────────────────────────────────────
export interface TrafficLog {
  time: string;
  client_ip?: string;
  method?: string;
  url?: string;
  status?: number | string;
  bytes?: number | string;
  duration?: string;
  backend?: string;
  raw?: string;
}
