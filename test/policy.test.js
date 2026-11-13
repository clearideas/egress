import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  compileFilePolicy, createAuthorizer, filePolicyBackend, httpPolicyBackend,
  normalizeHost, parseAclLine,
} from '../src/index.js';

const request = { principal: 'demo', sourceIp: '192.0.2.10', method: 'CONNECT', host: 'example.com', port: 443 };

test('file policy permits only the matching principal, host and port', async () => {
  const authorize = createAuthorizer(filePolicyBackend(compileFilePolicy({
    version: 1, principals: { demo: ['https://example.com'] },
  })));
  assert.equal(await authorize(request), true);
  assert.equal(await authorize({ ...request, principal: 'other' }), false);
  assert.equal(await authorize({ ...request, host: 'evil-example.com' }), false);
  assert.equal(await authorize({ ...request, port: 80 }), false);
});

test('invalid file policy cannot silently widen an allowlist', () => {
  for (const origin of ['https://example.com/path', 'https://user@example.com',
    'https://example.com?x=1', 'ftp://example.com', 'https://*.example.com']) {
    assert.throws(() => compileFilePolicy({ version: 1, principals: { demo: [origin] } }));
  }
  assert.throws(() => compileFilePolicy({ version: 2, principals: {} }));
});

test('ACL parser rejects malformed identities, ports and hosts', () => {
  assert.deepEqual(parseAclLine('demo 192.0.2.10 CONNECT example.com 443'), request);
  for (const input of ['- 192.0.2.10 CONNECT example.com 443',
    'demo 192.0.2.10 CONNECT example.com 0',
    'demo 192.0.2.10 CONNECT example.com 65536',
    'demo 192.0.2.10 CONNECT example.com:443 443',
    'demo 192.0.2.10 CONNECT example.com 443 extra']) {
    assert.equal(parseAclLine(input), null);
  }
  assert.equal(normalizeHost('example.com.evil'), 'example.com.evil');
});

test('HTTP backend requires protected transport and treats only explicit allow as allow', async () => {
  assert.throws(() => httpPolicyBackend('http://policy.example/decide', { token: 'x' }));
  assert.throws(() => httpPolicyBackend('https://policy.example/decide'));
  const calls = [];
  const backend = httpPolicyBackend('https://policy.example/decide', {
    token: 'test-token',
    fetchImpl: async (_url, options) => {
      calls.push(options);
      return { ok: true, json: async () => ({ decision: 'allow' }) };
    },
  });
  assert.equal(await createAuthorizer(backend)(request), true);
  assert.equal(JSON.parse(calls[0].body).principal, 'demo');
  assert.equal(calls[0].headers.authorization, 'Bearer test-token');
  assert.equal(calls[0].redirect, 'error');
  const deny = createAuthorizer(httpPolicyBackend('http://127.0.0.1:9999/decide', {
    fetchImpl: async () => ({ ok: true, json: async () => ({ allowed: true }) }),
  }));
  assert.equal(await deny(request), false);
});

test('policy backend failures and non-boolean responses fail closed', async () => {
  assert.equal(await createAuthorizer(async () => { throw new Error('offline'); })(request), false);
  assert.equal(await createAuthorizer(async () => 'allow')(request), false);
});

test('CLI processes multiple Squid ACL lines with one response each', () => {
  const dir = mkdtempSync(join(tmpdir(), 'egress-test-'));
  try {
    const policy = join(dir, 'policy.json');
    writeFileSync(policy, JSON.stringify({ version: 1, principals: { demo: ['https://example.com'] } }));
    const result = spawnSync(process.execPath, ['bin/egress-acl.js'], {
      cwd: new URL('..', import.meta.url),
      env: { ...process.env, EGRESS_POLICY_FILE: policy, EGRESS_POLICY_URL: '' },
      input: 'demo 192.0.2.10 CONNECT example.com 443\nother 192.0.2.10 CONNECT example.com 443\nbroken\n',
      encoding: 'utf8',
    });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout, 'OK\nERR\nERR\n');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
