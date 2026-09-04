# xpectrum-key-server

> **Retired, 2026-09-04. Do not build on this.**
>
> This server proved NFT ownership and returned decrypted circle content. Nothing in
> production uses it, and the approach is being replaced.
>
> The reason is the trust model. Decryption happened here, which meant this server held
> `SERVER_SECRET` and could derive every passphrase, and a reader had to take that on
> trust. Holder-gated content is being rebuilt so the only parties involved are the chain
> and the holder.
>
> Kept for reference. Nothing here is deployed and the endpoints are not maintained.

proves nft ownership then serves decrypted circle content. hold the token, get the content.

built for [octra](https://octra.network). nfts live in an xcollection contract. content lives in a sealed circle. this server sits in the middle.

contracts: [xpectrum-xyz/xpectrum-contracts](https://github.com/xpectrum-xyz/xpectrum-contracts)

---

## how it works

1. client requests a one-time challenge for their address
2. client signs it with their octra wallet (`octra_signMessage`)
3. server verifies the ed25519 sig, calls `owner_of(token_id)` on-chain
4. if owner matches: derives passphrase via hkdf, fetches the ocrs1 ciphertext from the rpc, decrypts it server-side, returns plaintext
5. client renders it — the aes key never leaves the server

---

## endpoints

### `GET /health`
```
{ "status": "ok", "timestamp": "...", "rpc": "..." }
```

### `GET /challenge?address=<oct_addr>`
```
{ "challenge": "xpectrum:auth:v1:<nonce>:<ts>", "expires_at": 1234567890000 }
```
single-use, expires in 5 minutes.

### `POST /content`
```json
{
  "address":    "oct...",
  "collection": "oct...",
  "token_id":   0,
  "challenge":  "xpectrum:auth:v1:...",
  "signature":  "<base64>",
  "circle_id":  "oct...",
  "path":       "/index.html"
}
```
returns:
```json
{ "content_type": "text/html; charset=utf-8", "plaintext_b64": "<base64>" }
```
decode `plaintext_b64` and render. 400/401/403/404/502 on errors.

### `POST /key` (legacy)
same auth, returns `{ "passphrase": "<64 hex>", "key_id": "xpectrum-key-v0" }` for client-side decryption. use `/content` instead.

---

## setup

```bash
cp .env.example .env
# fill in SERVER_SECRET and OCTRA_RPC_URL
npm install
npm start
```

generate a secret:
```bash
openssl rand -hex 32
```

keep `SERVER_SECRET` stable — rotating it changes all derived passphrases and breaks existing content.

---

## env vars

| var | description |
|---|---|
| `SERVER_SECRET` | hkdf input key material. generate once, never rotate unless re-encrypting all circles. |
| `OCTRA_RPC_URL` | octra rpc endpoint. use an https proxy if deploying to cloud (direct devnet ip may be unreachable). |
| `PORT` | default `3000` |

---

## deploying to railway

set env vars in the Railway dashboard. for `OCTRA_RPC_URL`, use an https-accessible proxy rather than the raw devnet ip — cloud providers can't reach bare ips on non-standard ports.

---

## tests

```bash
# validation only (no chain needed)
npm test

# full e2e (real devnet address that owns a token)
TEST_ADDRESS=oct... \
TEST_PRIVATE_KEY=<64-char-hex-seed> \
TEST_COLLECTION=oct... \
TEST_TOKEN_ID=0 \
TEST_CIRCLE_ID=oct... \
npm test
```

the offline mock test at the end of `test.js` runs automatically — spins up a mock rpc and fresh server process, no chain needed.

---

## key rotation

increment `version` in the server's in-memory `versions` map for a given `(collection, token_id)`. next `/content` call derives a new passphrase. old content (encrypted under version 0) needs to be re-uploaded under the new key.

---

## notes

- `owner_of` is called live on every request, no caching
- challenges are single-use
- passphrase and aes key are never logged or returned to the client
