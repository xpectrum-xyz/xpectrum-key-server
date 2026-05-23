/**
 * Xpectrum key server end-to-end test
 *
 * Hits /health, /challenge, /key, and /content against a running local server.
 * Includes a self-contained offline mock test for /content that spins up a
 * mock RPC server and a fresh key-server process — no real chain required.
 *
 * Env vars:
 *   SERVER_URL       (default: http://localhost:3000)
 *   TEST_ADDRESS     oct address that owns TEST_TOKEN_ID in TEST_COLLECTION
 *   TEST_PRIVATE_KEY 32-byte Ed25519 seed in hex (64 hex chars)
 *   TEST_COLLECTION  collection contract address
 *   TEST_TOKEN_ID    token id owned by TEST_ADDRESS (default: 0)
 *   TEST_CIRCLE_ID   circle address for /content full-flow test
 *   TEST_PATH        asset path for /content full-flow test (default: /index.html)
 */

import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';
import { hkdfSync, pbkdf2Sync, createCipheriv, createHash, randomBytes } from 'node:crypto';
import { createServer as httpCreateServer } from 'node:http';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';

ed.etc.sha512Sync = (...m) => sha512(...m);

const __dirname = dirname(fileURLToPath(import.meta.url));

const BASE        = process.env.SERVER_URL    ?? 'http://localhost:3000';
const ADDRESS     = process.env.TEST_ADDRESS;
const PRIVATE_KEY = process.env.TEST_PRIVATE_KEY;
const COLLECTION  = process.env.TEST_COLLECTION;
const TOKEN_ID    = Number(process.env.TEST_TOKEN_ID ?? '0');
const CIRCLE_ID   = process.env.TEST_CIRCLE_ID;
const ASSET_PATH  = process.env.TEST_PATH ?? '/index.html';


// Helpers
const pass = (msg) => console.log(`  ✓  ${msg}`);
const fail = (msg) => { console.error(`  ✗  ${msg}`); process.exit(1); };

async function get(path, base = BASE) {
  const res = await fetch(`${base}${path}`);
  const body = await res.json();
  return { status: res.status, body };
}

async function post(path, data, base = BASE) {
  const res = await fetch(`${base}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  const body = await res.json();
  return { status: res.status, body };
}


// Tests
console.log(`\nXpectrum Key Server — E2E Test`);
console.log(`Target: ${BASE}\n`);

// --- /health ---
console.log('[ /health ]');
{
  const { status, body } = await get('/health');
  if (status !== 200)  fail(`expected 200, got ${status}`);
  if (body.status !== 'ok') fail(`expected status:ok, got ${JSON.stringify(body)}`);
  pass(`status ok, rpc: ${body.rpc}, ts: ${body.timestamp}`);
}

// --- /challenge input validation ---
console.log('\n[ /challenge — validation ]');
{
  const { status } = await get('/challenge');
  if (status !== 400) fail(`expected 400 for missing address, got ${status}`);
  pass('missing address → 400');

  const r2 = await get('/challenge?address=not-an-oct-address');
  if (r2.status !== 400) fail(`expected 400 for invalid address, got ${r2.status}`);
  pass('invalid address → 400');
}

// --- /key input validation ---
console.log('\n[ /key — validation ]');
{
  const { status } = await post('/key', {});
  if (status !== 400) fail(`expected 400 for empty body, got ${status}`);
  pass('empty body → 400');

  const r2 = await post('/key', {
    address: 'octFakeAddr', collection: 'octFakeCol',
    token_id: 0, challenge: 'fake-challenge', signature: 'fakesig',
  });
  if (r2.status !== 401) fail(`expected 401 for unknown challenge, got ${r2.status}: ${JSON.stringify(r2.body)}`);
  pass('unknown challenge → 401');
}

// --- /content input validation ---
console.log('\n[ /content — validation ]');
{
  const { status } = await post('/content', {});
  if (status !== 400) fail(`expected 400 for empty body, got ${status}`);
  pass('empty body → 400');

  // Missing circle_id + path
  const r2 = await post('/content', {
    address: 'octAddr', collection: 'octCol', token_id: 0,
    challenge: 'x', signature: 'x',
  });
  if (r2.status !== 400) fail(`expected 400 for missing circle_id/path, got ${r2.status}: ${JSON.stringify(r2.body)}`);
  pass('missing circle_id/path → 400');

  // Invalid circle_id prefix
  const r3 = await post('/content', {
    address: 'octAddr', collection: 'octCol', token_id: 0,
    challenge: 'x', signature: 'x', circle_id: 'notAnOctAddress', path: '/foo',
  });
  if (r3.status !== 400) fail(`expected 400 for invalid circle_id, got ${r3.status}: ${JSON.stringify(r3.body)}`);
  pass('invalid circle_id → 400');

  // Path not starting with /
  const r4 = await post('/content', {
    address: 'octAddr', collection: 'octCol', token_id: 0,
    challenge: 'x', signature: 'x', circle_id: 'octCircle', path: 'no-slash',
  });
  if (r4.status !== 400) fail(`expected 400 for path without /, got ${r4.status}: ${JSON.stringify(r4.body)}`);
  pass('path without leading / → 400');

  // Unknown challenge
  const r5 = await post('/content', {
    address: 'octFakeAddr', collection: 'octFakeCol', token_id: 0,
    challenge: 'nonexistent-challenge', signature: 'fakesig',
    circle_id: 'octFakeCircle', path: '/index.html',
  });
  if (r5.status !== 401) fail(`expected 401 for unknown challenge, got ${r5.status}: ${JSON.stringify(r5.body)}`);
  pass('unknown challenge → 401');
}

// --- challenge replay prevention + /key full flow ---
console.log('\n[ challenge replay prevention ]');
if (!ADDRESS) {
  console.log('  –  TEST_ADDRESS not set, skipping challenge + key tests');
} else {
  const { status: cs, body: cb } = await get(`/challenge?address=${ADDRESS}`);
  if (cs !== 200) fail(`/challenge failed: ${cs} ${JSON.stringify(cb)}`);
  const { challenge, expires_at } = cb;
  pass(`challenge issued: ${challenge.slice(0, 40)}... expires ${new Date(expires_at).toISOString()}`);

  console.log('\n[ /key — full end-to-end ]');

  if (!PRIVATE_KEY || !COLLECTION) {
    console.log('  –  TEST_PRIVATE_KEY or TEST_COLLECTION not set, skipping signed key test');
    console.log(`  –  Challenge was: ${challenge}`);
    console.log('  –  Sign it manually and POST to /key to complete the test');
  } else {
    const privBytes = Uint8Array.from(Buffer.from(PRIVATE_KEY, 'hex'));
    const msgBytes  = new TextEncoder().encode(challenge);
    const sigBytes  = ed.sign(msgBytes, privBytes);
    const signature = Buffer.from(sigBytes).toString('base64');
    pass(`challenge signed, sig: ${signature.slice(0, 20)}...`);

    const { status: ks, body: kb } = await post('/key', {
      address: ADDRESS, collection: COLLECTION,
      token_id: TOKEN_ID, challenge, signature,
    });

    if (ks === 200) {
      if (!kb.passphrase || !kb.key_id) fail(`200 but missing fields: ${JSON.stringify(kb)}`);
      pass(`key issued: key_id=${kb.key_id}, passphrase=${kb.passphrase.slice(0, 8)}...[${kb.passphrase.length} chars]`);
    } else if (ks === 401 && kb.error?.includes('invalid signature')) {
      fail(`signature rejected — TEST_PRIVATE_KEY does not match the registered octra_viewPubkey for ${ADDRESS}`);
    } else if (ks === 403) {
      fail(`not the token owner — ${ADDRESS} does not own token ${TOKEN_ID} in ${COLLECTION}`);
    } else {
      fail(`unexpected response ${ks}: ${JSON.stringify(kb)}`);
    }

    console.log('\n[ challenge replay prevention ]');
    const { status: rs, body: rb } = await post('/key', {
      address: ADDRESS, collection: COLLECTION, token_id: TOKEN_ID,
      challenge, signature,
    });
    if (rs !== 401) fail(`expected 401 on replay, got ${rs}: ${JSON.stringify(rb)}`);
    pass('replayed challenge → 401');

    // --- /content full flow (real chain) ---
    if (CIRCLE_ID) {
      console.log('\n[ /content — full end-to-end (real chain) ]');
      const { status: cs2, body: cb2 } = await get(`/challenge?address=${ADDRESS}`);
      if (cs2 !== 200) fail(`/challenge failed: ${cs2}`);
      const { challenge: ch2 } = cb2;
      const sig2 = Buffer.from(ed.sign(new TextEncoder().encode(ch2), privBytes)).toString('base64');

      const { status: cos, body: cob } = await post('/content', {
        address: ADDRESS, collection: COLLECTION, token_id: TOKEN_ID,
        challenge: ch2, signature: sig2,
        circle_id: CIRCLE_ID, path: ASSET_PATH,
      });

      if (cos === 200) {
        if (!cob.plaintext_b64 || !cob.content_type) fail(`200 but missing fields: ${JSON.stringify(cob)}`);
        const decoded = Buffer.from(cob.plaintext_b64, 'base64').toString('utf8');
        pass(`content served: content_type=${cob.content_type}, plaintext length=${decoded.length} chars`);
        pass(`plaintext preview: ${decoded.slice(0, 60).replace(/\n/g, ' ')}...`);
      } else if (cos === 403) {
        fail(`not the token owner — ${ADDRESS} does not own token ${TOKEN_ID} in ${COLLECTION}`);
      } else {
        fail(`unexpected /content response ${cos}: ${JSON.stringify(cob)}`);
      }
    } else {
      console.log('  –  TEST_CIRCLE_ID not set, skipping /content real-chain test');
    }
  }
}


// /content — offline mock test
// Spins up a mock RPC server + a fresh key-server process, runs the full
// challenge >> sign >> /content flow without touching a real chain.
console.log('\n[ /content — offline mock test ]');
{
  // Fixed test fixtures
  const MOCK_SECRET     = 'mock-server-secret-xpectrum-test';
  const MOCK_ADDRESS    = 'octMOCKADDR111111111111111111111111111111111';
  const MOCK_COLLECTION = 'octMOCKCOLLECTION11111111111111111111111111';
  const MOCK_CIRCLE_ID  = 'octMOCKCIRCLEID1111111111111111111111111111';
  const MOCK_TOKEN_ID   = 0;
  const MOCK_PATH       = '/index.html';
  const MOCK_CONTENT    = '<html><body>mock NFT-gated content</body></html>';
  const MOCK_CONTENT_TYPE = 'text/html; charset=utf-8';
  const MOCK_KEY_ID     = 'xpectrum-key-v0';

  // Deterministic Ed25519 keypair from fixed seed
  const MOCK_SEED    = Buffer.from('deadbeefcafe'.repeat(5) + 'dead', 'hex').subarray(0, 32);
  const MOCK_PUBKEY  = await ed.getPublicKey(MOCK_SEED);
  const MOCK_PUBKEY_B64 = Buffer.from(MOCK_PUBKEY).toString('base64');

  // Derive passphrase the same way the server will (same HKDF formula)
  const mockPassphrase = Buffer.from(
    hkdfSync('sha256', Buffer.from(MOCK_SECRET, 'utf8'), Buffer.from(MOCK_COLLECTION, 'utf8'),
             Buffer.from(`xpectrum:circle-key:v1:${MOCK_TOKEN_ID}:0`, 'utf8'), 32)
  ).toString('hex');

  // Encrypt fixture content as OCRS1 using the derived passphrase
  const pbkdf2Salt = Buffer.from(`octra:circle:sealed_read:v1:${MOCK_CIRCLE_ID}:${MOCK_KEY_ID}`, 'utf8');
  const aesKey  = pbkdf2Sync(mockPassphrase, pbkdf2Salt, 120_000, 32, 'sha256');
  const nonce   = randomBytes(12);
  const plain   = Buffer.from(MOCK_CONTENT, 'utf8');
  const frame   = Buffer.alloc(4 + plain.length);
  frame.writeUInt32BE(plain.length, 0);
  plain.copy(frame, 4);
  const aesCipher  = createCipheriv('aes-256-gcm', aesKey, nonce);
  const encrypted  = Buffer.concat([aesCipher.update(frame), aesCipher.final()]);
  const authTag    = aesCipher.getAuthTag();
  const envelope   = Buffer.concat([Buffer.from('OCRS1'), nonce, encrypted, authTag]);
  const MOCK_CIPHERTEXT_B64 = envelope.toString('base64');
  const MOCK_PLAINTEXT_HASH = createHash('sha256').update(plain).digest('hex');

  // Spin up mock RPC server
  const mockRpcServer = await new Promise((resolve) => {
    const srv = httpCreateServer((req, res) => {
      let body = '';
      req.on('data', chunk => { body += chunk; });
      req.on('end', () => {
        let result = null;
        try {
          const { method } = JSON.parse(body);
          if (method === 'octra_publicKey') {
            result = { public_key: MOCK_PUBKEY_B64 };
          } else if (method === 'contract_call') {
            result = { result: MOCK_ADDRESS };
          } else if (method === 'circle_asset_ciphertext') {
            result = {
              ciphertext_b64:  MOCK_CIPHERTEXT_B64,
              plaintext_hash:  MOCK_PLAINTEXT_HASH,
              key_id:          MOCK_KEY_ID,
              content_type:    MOCK_CONTENT_TYPE,
            };
          }
        } catch { /* ignore parse errors */ }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ jsonrpc: '2.0', id: 1, result }));
      });
    });
    srv.listen(0, '127.0.0.1', () => resolve(srv));
  });

  const mockRpcPort = mockRpcServer.address().port;
  const MOCK_RPC_URL = `http://127.0.0.1:${mockRpcPort}`;
  const MOCK_SERVER_PORT = 13799;
  const MOCK_BASE = `http://127.0.0.1:${MOCK_SERVER_PORT}`;

  // Spawn key server against mock RPC
  const serverProc = spawn('node', ['server.js'], {
    cwd: __dirname,
    env: {
      ...process.env,
      SERVER_SECRET:  MOCK_SECRET,
      OCTRA_RPC_URL:  MOCK_RPC_URL,
      PORT:           String(MOCK_SERVER_PORT),
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  const serverReady = await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error('server startup timeout (5s)')), 5_000);
    const check = (data) => {
      if (data.toString().includes('server_start')) { clearTimeout(timeout); resolve(); }
    };
    serverProc.stdout.on('data', check);
    serverProc.stderr.on('data', check);
    serverProc.on('error', (err) => { clearTimeout(timeout); reject(err); });
  }).catch(err => err);

  if (serverReady instanceof Error) {
    serverProc.kill();
    mockRpcServer.close();
    fail(`mock server failed to start: ${serverReady.message}`);
  }

  try {
    // Get challenge
    const { status: cs, body: cb } = await get(`/challenge?address=${MOCK_ADDRESS}`, MOCK_BASE);
    if (cs !== 200) fail(`mock /challenge failed: ${cs} ${JSON.stringify(cb)}`);
    const { challenge } = cb;
    pass(`mock challenge issued`);

    // Sign with mock private key
    const msgBytes  = new TextEncoder().encode(challenge);
    const sigBytes  = ed.sign(msgBytes, MOCK_SEED);
    const signature = Buffer.from(sigBytes).toString('base64');

    // POST /content
    const { status: cos, body: cob } = await post('/content', {
      address:    MOCK_ADDRESS,
      collection: MOCK_COLLECTION,
      token_id:   MOCK_TOKEN_ID,
      challenge,
      signature,
      circle_id:  MOCK_CIRCLE_ID,
      path:       MOCK_PATH,
    }, MOCK_BASE);

    if (cos !== 200) fail(`mock /content returned ${cos}: ${JSON.stringify(cob)}`);
    if (!cob.plaintext_b64) fail(`missing plaintext_b64 in response`);
    if (!cob.content_type)  fail(`missing content_type in response`);

    const decoded = Buffer.from(cob.plaintext_b64, 'base64').toString('utf8');
    if (decoded !== MOCK_CONTENT) {
      fail(`decrypted content mismatch\n  expected: ${MOCK_CONTENT}\n  got:      ${decoded}`);
    }
    if (cob.content_type !== MOCK_CONTENT_TYPE) {
      fail(`content_type mismatch: expected ${MOCK_CONTENT_TYPE}, got ${cob.content_type}`);
    }

    pass(`server-side decrypt correct: "${decoded}"`);
    pass(`content_type: ${cob.content_type}`);

    // Replay: same challenge should be rejected
    const { status: rs } = await post('/content', {
      address: MOCK_ADDRESS, collection: MOCK_COLLECTION, token_id: MOCK_TOKEN_ID,
      challenge, signature, circle_id: MOCK_CIRCLE_ID, path: MOCK_PATH,
    }, MOCK_BASE);
    if (rs !== 401) fail(`expected 401 on replay, got ${rs}`);
    pass('replayed challenge → 401');

  } finally {
    serverProc.kill();
    mockRpcServer.close();
  }
}

console.log('\nAll tests passed.\n');
