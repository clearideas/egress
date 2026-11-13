#!/usr/bin/env node
import { createInterface } from 'node:readline';
import { createAuthorizer, filePolicyBackend, httpPolicyBackend, loadFilePolicy, parseAclLine } from '../src/index.js';

let backend;
try {
  if (process.env.EGRESS_POLICY_FILE && !process.env.EGRESS_POLICY_URL) {
    backend = filePolicyBackend(await loadFilePolicy(process.env.EGRESS_POLICY_FILE));
  } else if (process.env.EGRESS_POLICY_URL && !process.env.EGRESS_POLICY_FILE) {
    backend = httpPolicyBackend(process.env.EGRESS_POLICY_URL, { token: process.env.EGRESS_POLICY_TOKEN });
  } else {
    throw new Error('set exactly one of EGRESS_POLICY_FILE or EGRESS_POLICY_URL');
  }
} catch (error) {
  console.error(`egress ACL startup failed: ${error.message}`);
  process.exit(1);
}

const authorize = createAuthorizer(backend);
for await (const line of createInterface({ input: process.stdin, crlfDelay: Infinity })) {
  const request = parseAclLine(line);
  const allowed = request ? await authorize(request) : false;
  process.stdout.write(allowed ? 'OK\n' : 'ERR\n');
}
