import { readFile } from 'node:fs/promises';
import { isIP } from 'node:net';
import { domainToASCII } from 'node:url';

export function normalizeHost(value) {
  if (typeof value !== 'string') return null;
  const host = value.trim().replace(/\.$/, '').toLowerCase();
  if (!host || /[\s\/?#@%\\]/.test(host)) return null;
  if (isIP(host)) return host;
  const ascii = domainToASCII(host);
  if (!ascii || ascii !== host || host.length > 253 || !host.split('.').every(
    label => label.length > 0 && label.length <= 63 && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label)
  )) return null;
  return host;
}

export function parseAclLine(line) {
  // Squid external ACL format: %ul %>a %METHOD %DST %PORT.
  const parts = line.trim().split(/\s+/);
  if (parts.length !== 5) return null;
  const [principal, sourceIp, method, rawHost, rawPort] = parts;
  const host = normalizeHost(rawHost);
  const port = Number(rawPort);
  if (!principal || principal === '-' || /[\s|]/.test(principal) || !host ||
      !Number.isInteger(port) || port < 1 || port > 65535 ||
      !/^[A-Z]+$/.test(method) || !isIP(sourceIp)) return null;
  return { principal, sourceIp, method, host, port };
}

function parseOrigin(origin) {
  if (typeof origin !== 'string') throw new Error('policy origin must be a URL string');
  let url;
  try { url = new URL(origin); } catch { throw new Error('invalid policy origin'); }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password ||
      url.search || url.hash || url.pathname !== '/' || !normalizeHost(url.hostname)) {
    throw new Error('policy origin must be an HTTP(S) host and optional port');
  }
  return `${normalizeHost(url.hostname)}:${Number(url.port) || (url.protocol === 'https:' ? 443 : 80)}`;
}

export function compileFilePolicy(document) {
  if (!document || typeof document !== 'object' || Array.isArray(document) ||
      document.version !== 1 || !document.principals ||
      typeof document.principals !== 'object' || Array.isArray(document.principals)) {
    throw new Error('policy must contain version 1 and a principals object');
  }
  const entries = new Map();
  for (const [principal, origins] of Object.entries(document.principals)) {
    if (!principal || /[\s|]/.test(principal) || !Array.isArray(origins)) {
      throw new Error('invalid principal or origin list');
    }
    entries.set(principal, new Set(origins.map(parseOrigin)));
  }
  return entries;
}

export async function loadFilePolicy(path) {
  return compileFilePolicy(JSON.parse(await readFile(path, 'utf8')));
}

export function filePolicyBackend(entries) {
  return async request => entries.get(request.principal)?.has(`${request.host}:${request.port}`) === true;
}

export function httpPolicyBackend(url, { token, timeoutMs = 2000, fetchImpl = fetch } = {}) {
  const endpoint = new URL(url);
  const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(endpoint.hostname);
  if (endpoint.protocol !== 'https:' && !(endpoint.protocol === 'http:' && loopback)) {
    throw new Error('policy API must use HTTPS or local loopback HTTP');
  }
  if (endpoint.username || endpoint.password || endpoint.hash || !Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new Error('invalid policy API configuration');
  }
  if (!loopback && !token) throw new Error('remote policy API requires a bearer token');
  return async request => {
    const response = await fetchImpl(endpoint, {
      method: 'POST', redirect: 'error',
      headers: { 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}) },
      body: JSON.stringify(request), signal: AbortSignal.timeout(timeoutMs),
    });
    if (!response.ok) return false;
    const body = await response.json();
    return body?.decision === 'allow';
  };
}

export function createAuthorizer(backend) {
  if (typeof backend !== 'function') throw new TypeError('backend must be a function');
  return async request => {
    if (!request || !request.principal || !normalizeHost(request.host) ||
        !Number.isInteger(request.port) || request.port < 1 || request.port > 65535) return false;
    try { return (await backend(request)) === true; } catch { return false; }
  };
}
