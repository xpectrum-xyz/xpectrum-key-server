import express from 'express';
import cors from 'cors';
import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';
import { randomBytes, hkdfSync, pbkdf2Sync, createDecipheriv, createHash } from 'node:crypto';

// noble/ed25519 v2 needs a synchronous sha512
ed.etc.sha512Sync = (...m) => sha512(...m);


// Config
const {
  SERVER_SECRET,
  OCTRA_RPC_URL,
  PORT = '3000',
} = process.env;

if (!SERVER_SECRET) { console.error('[xpectrum-key-server] SERVER_SECRET env var required'); process.exit(1); }
if (!OCTRA_RPC_URL) { console.error('[xpectrum-key-server] OCTRA_RPC_URL env var required'); process.exit(1); }

const CHALLENGE_TTL_MS = 5 * 60 * 1000;


// In-memory state

// challenge string -> { address, expires_at, used }
const challenges = new Map();

// "${collection}:${token_id}" -> version (int, starts at 0)
// increment to rotate content — new passphrase, old owners locked out
const versions = new Map();

setInterval(() => {
  const now = Date.now();
  for (const [key, val] of challenges) {
    if (val.expires_at < now) challenges.delete(key);
  }
}, 60_000).unref();


// Logging — never log passphrases or keys
function log(fields) {
  console.log(JSON.stringify({ ts: new Date().toISOString(), ...fields }));
}


// RPC
async function rpc(method, params) {
  const res = await fetch(OCTRA_RPC_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
    signal: AbortSignal.timeout(10_000),
  });
  if (!res.ok) throw new Error(`RPC HTTP ${res.status}`);
  const data = await res.json();
  if (data.error) throw new Error(data.error.message ?? JSON.stringify(data.error));
  return data.result;
}

async function fetchPubkey(address) {
  const result = await rpc('octra_publicKey', [address]);
  const b64 = result?.public_key;
  if (!b64) throw new Error(`no pubkey registered for ${address}`);
  return Uint8Array.from(Buffer.from(b64, 'base64'));
}

async function fetchOwner(collection, tokenId, caller) {
  const result = await rpc('contract_call', [collection, 'owner_of', [tokenId], caller]);
  const owner = result?.result;
  if (!owner) throw new Error('owner_of returned empty result');
  return String(owner);
}


// OCRS1 decryption
// envelope = "OCRS1" (5) + nonce (12) + ciphertext + auth_tag (16)
// frame    = u32be(len) + plaintext
function decryptSealedAsset(circleId, asset, passphrase) {
  const envelope = Buffer.from(asset.ciphertext_b64, 'base64');
  if (envelope.subarray(0, 5).toString('utf8') !== 'OCRS1') {
    throw new Error('invalid sealed envelope magic');
  }
  const nonce         = envelope.subarray(5, 17);
  const cipherWithTag = envelope.subarray(17);
  const authTag       = cipherWithTag.subarray(cipherWithTag.length - 16);
  const ciphertext    = cipherWithTag.subarray(0, cipherWithTag.length - 16);

  const salt = Buffer.from(`octra:circle:sealed_read:v1:${circleId}:${asset.key_id}`, 'utf8');
  const key  = pbkdf2Sync(passphrase, salt, 120_000, 32, 'sha256');

  const decipher = createDecipheriv('aes-256-gcm', key, nonce);
  decipher.setAuthTag(authTag);
  const plainFrame = Buffer.concat([decipher.update(ciphertext), decipher.final()]);

  if (plainFrame.length < 4) throw new Error('invalid sealed payload');
  const size      = plainFrame.readUInt32BE(0);
  const plaintext = plainFrame.subarray(4, 4 + size);

  const actualHash = createHash('sha256').update(plaintext).digest('hex');
  if (actualHash !== asset.plaintext_hash) throw new Error('plaintext hash mismatch');

  return plaintext;
}


// Passphrase derivation — HKDF-SHA256
function derivePassphrase(collection, tokenId, version) {
  const ikm    = Buffer.from(SERVER_SECRET, 'utf8');
  const salt   = Buffer.from(collection, 'utf8');
  const info   = Buffer.from(`xpectrum:circle-key:v1:${tokenId}:${version}`, 'utf8');
  return Buffer.from(hkdfSync('sha256', ikm, salt, info, 32)).toString('hex');
}


// Express
const app = express();
app.use(cors());
app.use(express.json());


// GET /health
app.get('/health', (_req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString(), rpc: OCTRA_RPC_URL });
});

// GET /challenge?address=<oct_addr>
app.get('/challenge', (req, res) => {
  const { address } = req.query;

  if (!address || typeof address !== 'string' || !address.startsWith('oct')) {
    return res.status(400).json({ error: 'valid oct address required' });
  }

  const nonce      = randomBytes(16).toString('hex');
  const timestamp  = Math.floor(Date.now() / 1000);
  const challenge  = `xpectrum:auth:v1:${nonce}:${timestamp}`;
  const expires_at = Date.now() + CHALLENGE_TTL_MS;

  challenges.set(challenge, { address, expires_at, used: false });
  log({ event: 'challenge_issued', address });

  res.json({ challenge, expires_at });
});

// POST /key  (legacy — returns passphrase for client-side decrypt)
app.post('/key', async (req, res) => {
  const { address, collection, token_id, challenge, signature } = req.body ?? {};

  if (!address || !collection || token_id == null || !challenge || !signature) {
    return res.status(400).json({ error: 'address, collection, token_id, challenge, and signature are required' });
  }
  if (typeof address !== 'string' || !address.startsWith('oct')) {
    return res.status(400).json({ error: 'invalid address' });
  }
  if (typeof collection !== 'string' || !collection.startsWith('oct')) {
    return res.status(400).json({ error: 'invalid collection' });
  }

  const entry = challenges.get(challenge);
  if (!entry)                       return res.status(401).json({ error: 'challenge not found or expired' });
  if (entry.used)                   return res.status(401).json({ error: 'challenge already used' });
  if (Date.now() > entry.expires_at) { challenges.delete(challenge); return res.status(401).json({ error: 'challenge expired' }); }
  if (entry.address !== address)    return res.status(401).json({ error: 'challenge was issued for a different address' });

  // mark used before any await — prevents replay if downstream fails
  entry.used = true;

  try {
    let pubkeyBytes;
    try {
      pubkeyBytes = await fetchPubkey(address);
    } catch (err) {
      log({ event: 'key_error', address, collection, token_id, reason: 'pubkey_fetch_failed', detail: err.message });
      return res.status(502).json({ error: 'failed to fetch public key', detail: err.message });
    }

    const msgBytes = new TextEncoder().encode(challenge);
    const sigBytes = Uint8Array.from(Buffer.from(signature, 'base64'));
    let valid = false;
    try { valid = ed.verify(sigBytes, msgBytes, pubkeyBytes); } catch { valid = false; }
    if (!valid) {
      log({ event: 'key_denied', address, collection, token_id, reason: 'invalid_signature' });
      return res.status(401).json({ error: 'invalid signature' });
    }

    // ownership check — live, no cache
    let owner;
    try {
      owner = await fetchOwner(collection, Number(token_id), address);
    } catch (err) {
      log({ event: 'key_error', address, collection, token_id, reason: 'owner_of_failed', detail: err.message });
      return res.status(502).json({ error: 'ownership check failed', detail: err.message });
    }

    if (owner !== address) {
      log({ event: 'key_denied', address, collection, token_id, reason: 'not_owner', owner });
      return res.status(403).json({ error: 'not the token owner' });
    }

    const versionKey = `${collection}:${token_id}`;
    const version    = versions.get(versionKey) ?? 0;
    const passphrase = derivePassphrase(collection, Number(token_id), version);

    log({ event: 'key_issued', address, collection, token_id, version });
    res.json({ passphrase, key_id: `xpectrum-key-v${version}` });

  } catch (err) {
    log({ event: 'key_error', address, collection, token_id, reason: 'internal', detail: err.message });
    res.status(500).json({ error: 'internal server error' });
  }
});


// POST /content  (preferred — server-side decrypt, passphrase never leaves)
app.post('/content', async (req, res) => {
  const { address, collection, token_id, challenge, signature, circle_id, path } = req.body ?? {};

  if (!address || !collection || token_id == null || !challenge || !signature || !circle_id || !path) {
    return res.status(400).json({ error: 'address, collection, token_id, challenge, signature, circle_id, and path are required' });
  }
  if (typeof address !== 'string' || !address.startsWith('oct')) {
    return res.status(400).json({ error: 'invalid address' });
  }
  if (typeof collection !== 'string' || !collection.startsWith('oct')) {
    return res.status(400).json({ error: 'invalid collection' });
  }
  if (typeof circle_id !== 'string' || !circle_id.startsWith('oct')) {
    return res.status(400).json({ error: 'invalid circle_id' });
  }
  if (typeof path !== 'string' || !path.startsWith('/')) {
    return res.status(400).json({ error: 'path must start with /' });
  }

  const entry = challenges.get(challenge);
  if (!entry)                       return res.status(401).json({ error: 'challenge not found or expired' });
  if (entry.used)                   return res.status(401).json({ error: 'challenge already used' });
  if (Date.now() > entry.expires_at) { challenges.delete(challenge); return res.status(401).json({ error: 'challenge expired' }); }
  if (entry.address !== address)    return res.status(401).json({ error: 'challenge was issued for a different address' });

  entry.used = true;

  try {
    let pubkeyBytes;
    try {
      pubkeyBytes = await fetchPubkey(address);
    } catch (err) {
      log({ event: 'content_error', address, collection, token_id, reason: 'pubkey_fetch_failed', detail: err.message });
      return res.status(502).json({ error: 'failed to fetch public key', detail: err.message });
    }

    const msgBytes = new TextEncoder().encode(challenge);
    const sigBytes = Uint8Array.from(Buffer.from(signature, 'base64'));
    let valid = false;
    try { valid = ed.verify(sigBytes, msgBytes, pubkeyBytes); } catch { valid = false; }
    if (!valid) {
      log({ event: 'content_denied', address, collection, token_id, reason: 'invalid_signature' });
      return res.status(401).json({ error: 'invalid signature' });
    }

    // ownership check — live, no cache
    let owner;
    try {
      owner = await fetchOwner(collection, Number(token_id), address);
    } catch (err) {
      log({ event: 'content_error', address, collection, token_id, reason: 'owner_of_failed', detail: err.message });
      return res.status(502).json({ error: 'ownership check failed', detail: err.message });
    }

    if (owner !== address) {
      log({ event: 'content_denied', address, collection, token_id, reason: 'not_owner', owner });
      return res.status(403).json({ error: 'not the token owner' });
    }

    const versionKey = `${collection}:${token_id}`;
    const version    = versions.get(versionKey) ?? 0;
    const passphrase = derivePassphrase(collection, Number(token_id), version);

    let asset;
    try {
      asset = await rpc('circle_asset_ciphertext', [circle_id, path]);
    } catch (err) {
      log({ event: 'content_error', address, circle_id, path, reason: 'ciphertext_fetch_failed', detail: err.message });
      return res.status(502).json({ error: 'failed to fetch circle asset', detail: err.message });
    }

    if (!asset?.ciphertext_b64) {
      return res.status(404).json({ error: 'asset not found or missing ciphertext' });
    }

    let plaintext;
    try {
      plaintext = decryptSealedAsset(circle_id, asset, passphrase);
    } catch (err) {
      log({ event: 'content_error', address, circle_id, path, reason: 'decrypt_failed', detail: err.message });
      return res.status(500).json({ error: 'decryption failed', detail: err.message });
    }

    log({ event: 'content_served', address, collection, token_id, circle_id, path, version });
    res.json({
      content_type:  asset.content_type ?? 'application/octet-stream',
      plaintext_b64: plaintext.toString('base64'),
    });

  } catch (err) {
    log({ event: 'content_error', address, collection, token_id, reason: 'internal', detail: err.message });
    res.status(500).json({ error: 'internal server error' });
  }
});


// Start
app.listen(Number(PORT), () => {
  log({ event: 'server_start', port: PORT, rpc: OCTRA_RPC_URL });
});
