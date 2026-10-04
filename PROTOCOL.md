# Vicinity — protocol v1 (RN1)

This is the authoritative specification. Code must match it byte for byte. If code and this
document disagree, the code is wrong.

## Goal and threat model

Two people, **A** (initiator) and **B** (responder), each manually pick a hex cell. Both learn one
bit: whether their cells are the same or directly bordering at the coarser of their two chosen
levels. Nothing else.

Assume everyone beyond that base agreement is adversarial:

- The **relay/server** must learn no cell, no level, and not the result.
- **B** must learn only the bit (and A's chosen maximum level, which is part of the request A sends).
- **A** must learn only the bit (and the common level).
- **B colluding with the server** must still learn only the bit.
- Neither party can make the other's screen show a result different from their own. The only
  deviation available is aborting, which the other side sees as "didn't finish", never as a
  wrong answer.

Out of scope (documented in [SECURITY.md](SECURITY.md)): lying about one's own cell, repeated sessions,
fairness on abort, and malicious client code.

## Notation

- Group: **ristretto255** (RFC 9496). `G` = base point, `L` = group order
  `2^252 + 27742317777372353535851937790883648493`. `·` = scalar multiplication.
- `enc(P)`: 32-byte canonical ristretto255 encoding. `dec(b)`: decode; MUST reject non-canonical
  encodings. Every point received from the other party MUST also be rejected if it is the identity.
- Scalars are encoded as 32-byte little-endian `le32(s)`. On decode, MUST reject `s >= L`.
- `randScalar()`: 64 bytes from `crypto.getRandomValues`, little-endian integer mod `L`; retry if 0.
- `||` = byte concatenation. Strings are UTF-8 bytes. `u8(x)` = 1 byte, `i16be(x)` = 2-byte
  big-endian two's complement.
- `Hs(dst, msg)`: hash to scalar = `LE(SHA-512(u8(len(dst)) || dst || msg)) mod L`.
- `Hg(sid, level, q, r)`: hash to group = RFC 9380 `hash_to_ristretto255` (expand_message_xmd,
  SHA-512) with `DST = "RoughlyNearby-v1-cell"` and `msg = sid || u8(level) || i16be(q) || i16be(r)`.
- `SHA256`, `HKDF-SHA256`, `AES-256-GCM`: WebCrypto. GCM nonces are 12 random bytes; tag 16 bytes.

## Cells (must match the map UI)

- Map space is 1000 × 500. Levels `0..4` have hex sizes `[90, 50, 25, 12, 6]`
  (names: Very broad, Broad, Regional, Closer, Most detail).
- Pointy-top axial hexes: `hexToPixel(q, r, s) = (s·√3·(q + r/2), s·1.5·r)`;
  `pixelToHex` = inverse with cube rounding (reference implementation in `public/rn/cells.js`).
- `coarsen(cell, fromLevel, toLevel)`: take the center of `cell` at `fromLevel`,
  `pixelToHex` at `toLevel`. Identity when levels are equal. Always coarsen directly from the
  selected level, never chained.
- `N7(c)`: `c` plus its 6 axial neighbors in this order before shuffling:
  `(+1,0) (+1,−1) (0,−1) (−1,0) (−1,+1) (0,+1)`.
- NEAR ⇔ `hexDistance(coarsen(cA, lA, lc), coarsen(cB, lB, lc)) <= 1` where `lc = min(lA, lB)`.

## Keys (all fresh per session, memory only)

| Party | Secret | Public | Purpose |
|---|---|---|---|
| A | `a` | `PA = a·G` | blinding key; proofs |
| A | `ea` | `EA = ea·G` | ephemeral DH for encrypting M2/M3 |
| B | `b_1..b_7`, `δ_1..δ_7` | none (never publish `b_j·G` or `δ_j·G`) | per-slot blinding and masks |
| B | `eb` | `EB = eb·G` | ephemeral DH |

## Messages

### M1 — request (A → B), plaintext

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | version `0x01` |
| 1 | 1 | type `0x01` |
| 2 | 16 | `sid` (random) |
| 18 | 1 | `lA` (0..4) |
| 19 | 32 | `enc(PA)` |
| 51 | 32 | `enc(EA)` |
| 83 | 32·(lA+1) | `enc(X_l)` for `l = 0..lA`, where `X_l = a·Hg(sid, l, coarsen(cA, lA, l))` |

Length MUST equal `83 + 32·(lA+1)`.

`th1 = SHA256(M1)`.

### M2 — response (B → A)

B validates M1, chooses `cB` at `lB`, sets `lc = min(lA, lB)`, `cBc = coarsen(cB, lB, lc)`,
`X = X_lc`.

For each candidate `t_j ∈ N7(cBc)`, with fresh `b_j = randScalar()` and `δ_j = randScalar()`
per slot:

- `V_j = b_j·Hg(sid, lc, t_j) + δ_j·G`
- `Z_j = b_j·X + δ_j·PA`

Then shuffle the 7 `(V_j, Z_j)` pairs together with an unbiased Fisher–Yates driven by
`crypto.getRandomValues` (rejection sampling, no modulo bias).

`πB` = per-slot proofs (below) that each `Z_j` has the form `b_j·X + δ_j·PA`.

Plaintext body `P2` (929 bytes):
`u8(lc) || for j=1..7: enc(V_j) || enc(Z_j) || le32(πB.c) || for j=1..7: le32(πB.su_j) || le32(πB.sv_j)`

Encryption: `shared = enc(eb·EA)` (reject identity). `k2 = HKDF-SHA256(ikm=shared, salt=th1,
info="RN1/m2-key" || enc(EB), 32 bytes)`. AAD = the 50-byte header below.

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | version `0x01` |
| 1 | 1 | type `0x02` |
| 2 | 16 | `sid` |
| 18 | 32 | `enc(EB)` |
| 50 | 12 | nonce |
| 62 | 945 | AES-256-GCM(`k2`, `P2`) incl. tag |

Total 1007 bytes. B discards every `b_j`, `δ_j`, and `eb` immediately after building M2. B keeps
`V_1..7`, `Z_1..7`, `PA`, `lc`, `k3` (below), `th1`, and the M2 bytes.

Why per-slot secrets and masks: `a·V_j − Z_j = b_j·(a·Hg(t_j) − X)`. For a single slot, any pair
`(V_j, Z_j)` is consistent with any guessed cell unless `X = a·Hg(t_j)`, so that is the only
thing A can distinguish, and it is exactly what A proves to B. Each ingredient closes a concrete
attack in which A learns the true answer while proving the opposite (regression tests in
`tests/attack_analysis_test.js`):

- the mask `δ_j·G` defeats building `X` with a scalar other than `log_G(PA)`;
- independent `b_j` per slot stop A combining slots (e.g. `X = λ1·Hg(c) + λ2·Hg(c′)`);
- never publishing `b_j·G` stops A predicting an offset (e.g. `X = a·Hg(c) + x0·G`).

`k3 = HKDF-SHA256(ikm=shared, salt=th1, info="RN1/m3-key" || enc(EB), 32 bytes)`.

### A processes M2

Pre-checks that reject **without** aborting the session (so a mistaken paste doesn't kill it):
wrong version/type/length, `sid` mismatch.

Rejections that abort the session (discarding secrets): session not in the awaiting-M2 state
(**at most one M2 is ever processed per session**), session expired, decryption failure,
`lc > lA`, any invalid or identity point, any non-canonical scalar, `πB` verification failure.

Then `resultA = NEAR` iff `a·V_j == Z_j` for some `j` (compare encodings).

### M3 — finish (A → B)

`ctx3 = sid || u8(lc) || SHA256(M1 || M2)`.

- If NEAR: `proof` = OR-proof (below), plaintext `P3 = u8(0x01) || proof(448 bytes) || 256 zero bytes`.
- If NOT NEAR: `proof` = inequality proof (below), `P3 = u8(0x00) || proof(704 bytes)`.

`P3` is always 705 bytes so the length never reveals the result. A MUST NOT send any `a·V_j`.
A MUST equalise its work so the time between receiving M2 and sending M3 doesn't reveal the
result (compute both proof shapes, the unused one with a throwaway key, and discard it).

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | version `0x01` |
| 1 | 1 | type `0x03` |
| 2 | 16 | `sid` |
| 18 | 12 | nonce |
| 30 | 721 | AES-256-GCM(`k3`, `P3`) incl. tag, AAD = the 18-byte header |

Total 751 bytes. A discards `a` and `ea` after building M3.

### B processes M3

Pre-checks that reject without aborting: wrong version/type/length, `sid` mismatch.

Rejections that abort: not awaiting M3 (**at most one M3 per session**), expired, decryption
failure, result byte not `0x00`/`0x01`, non-zero padding, invalid points/scalars, proof failure.
A rejection is shown as "couldn't verify", never as a result. On success `resultB` = the proven
result.

## Proofs (Fiat–Shamir, all scalars mod L)

`VZ` below means `enc(V_1) || enc(Z_1) || … || enc(V_7) || enc(Z_7)` (448 bytes, P2 order).

### πB — B proves each `Z_j` has the form `b_j·X + δ_j·PA` (`X = X_lc`)

Equivalent per-slot statement: knowledge of `(u_j, v_j)` with `X = u_j·Z_j + v_j·PA`, where
`u_j = b_j⁻¹` and `v_j = −δ_j·b_j⁻¹`.

- Prove: for each `j`, `ru_j, rv_j = randScalar()`, `T_j = ru_j·Z_j + rv_j·PA`;
  `c = Hs("RN1/piB", sid || u8(lc) || th1 || enc(PA) || enc(X) || VZ || enc(T_1..7))`;
  `su_j = ru_j − c·u_j`, `sv_j = rv_j − c·v_j`.
- Verify: for each `j`, `T_j = su_j·Z_j + sv_j·PA + c·X`; recompute `c`, accept iff equal.

Purpose: without it, B could set `V_1 = r·G`, `Z_1 = r·PA` and force A's screen to NEAR. With it,
`Z_j = a·V_j` implies `X = a·(u_j·V_j + v_j·G)`, so B must have built `V_j` from `Hg(cA)`, which
it can only do by guessing A's cell (its ordinary one-bit probe).

### NEAR OR-proof (A proves `PA = a·G` and `Z_k = a·V_k` for some hidden `k`)

- Let `k` = first index with `a·V_k == Z_k`. `r = randScalar()`; `T1_k = r·G`, `T2_k = r·V_k`.
- For `j ≠ k`: random `c_j, s_j`; `T1_j = s_j·G + c_j·PA`, `T2_j = s_j·V_j + c_j·Z_j`.
- `c = Hs("RN1/near", ctx3 || enc(PA) || VZ || enc(T1_1..7) || enc(T2_1..7))`.
- `c_k = c − Σ_{j≠k} c_j`, `s_k = r − c_k·a`.
- Encoding: `le32(c_1..c_7) || le32(s_1..s_7)` (448 bytes).
- Verify: recompute every `T1_j = s_j·G + c_j·PA`, `T2_j = s_j·V_j + c_j·Z_j`, recompute `c`,
  accept iff `Σ c_j == c`.

### NOT-NEAR inequality proof (A proves `PA = a·G` and `Z_j ≠ a·V_j` for all j)

For each `j`:
- `β_j = randScalar()`, `α_j = β_j·a`, `C_j = α_j·V_j − β_j·Z_j` (= `β_j·(a·V_j − Z_j)`, non-identity).
- `ρα_j, ρβ_j = randScalar()`; `T1_j = ρα_j·V_j − ρβ_j·Z_j`; `T2_j = ρα_j·G − ρβ_j·PA`.

Then `c = Hs("RN1/far", ctx3 || enc(PA) || VZ || enc(C_1..7) || enc(T1_1..7) || enc(T2_1..7))`,
`zα_j = ρα_j + c·α_j`, `zβ_j = ρβ_j + c·β_j`.

- Encoding: `le32(c) || for j=1..7: enc(C_j) || le32(zα_j) || le32(zβ_j)` (704 bytes).
- Verify: every `C_j` valid and non-identity; `T1_j = zα_j·V_j − zβ_j·Z_j − c·C_j`;
  `T2_j = zα_j·G − zβ_j·PA`; recompute `c`, accept iff equal.

Why proofs instead of returning `a·V_j`: B knows which cell produced each `V_j`. If B saw the
`a·V_j` list it would learn which neighbor matched (A's exact cell). The proofs reveal only the
bit.

## Transports

The three messages are identical in both transports.

### Codes mode (no server)

Text codes: `rn1-req.` + base64url(M1), `rn1-rep.` + base64url(M2), `rn1-fin.` + base64url(M3).
Parsers strip all whitespace, check that the prefix matches the type byte, and reject anything else.

### Link mode (relay)

- A generates `linkSecret` (32 random bytes). Link: `<origin>/#j=<base64url(linkSecret)>`.
  The fragment never reaches the server. On load, the page reads it and immediately removes it
  with `history.replaceState`.
- `mailbox = base64url(HKDF-SHA256(ikm=linkSecret, salt="RN1/relay", info="mailbox", 16 bytes))`
  (22 chars). `frameKey = HKDF-SHA256(ikm=linkSecret, salt="RN1/relay", info="frame-key", 32 bytes)`.
- Frame for slot `n ∈ {1,2,3}` carrying message `Mn`:
  plaintext = `u16be(len(Mn)) || Mn || zero padding` to exactly 1024 bytes;
  wire = `nonce(12) || AES-256-GCM(frameKey, plaintext, AAD = "RN1/frame" || mailboxBytes(16) || u8(n))`
  = 1052 bytes. Receivers check length, padding, and that the inner message type equals `n`.
- Shape flattening: on session end (success, timeout, cancel, or page close), each client
  best-effort PUTs uniform-random 1052-byte frames to the slots it is responsible for — A: slot 2
  then slot 3; B: slot 3 — so an initiated mailbox always ends with all three slots filled. Dummies
  are indistinguishable from real frames (the server validates length only). Dummy writes ignore
  every response, including `409` (slot holds a real frame) and `412` (prerequisite missing), and
  never surface an error to the user.

### Relay HTTP API

- `PUT /api/relay/<mailbox>/<slot>` — body exactly 1052 bytes (`application/octet-stream`).
  `mailbox` matches `^[A-Za-z0-9_-]{22}$`, `slot ∈ {1,2,3}`.
  Responses: `201` stored · `409` slot already filled · `412` previous slot missing
  (2 needs 1, 3 needs 2) · `413` wrong size · `400` anything else malformed.
  Write-once via a Deno KV atomic check on `versionstamp: null`.
- `GET /api/relay/<mailbox>/<slot>` — `200` with the frame bytes, or `204` (empty body) if the slot is
  empty or expired. (Not `404`: browsers log every 404 as a console error, and clients poll.)
  Unknown `/api/*` routes still return `404`.
- Storage: KV key `["relay", mailbox, slot]`, value `{ exp, data }`. Per frame at write time:
  `ttl = 15 min + U(−3 min, +3 min)` (uniform, CSPRNG); native KV TTL `expireIn = ttl`;
  app-level deadline `exp = ceil((written_at + ttl) / 300_000) · 300_000` (rounded up to a
  5-minute bucket). GET treats `exp < now` as missing. No logging of mailboxes, bodies, or IPs.
- Clients poll GET about every 1.5 s with jitter.

## Timeouts (client-enforced)

| | Link mode | Codes mode |
|---|---|---|
| A accepts M2 within | 10 min of creating M1 | 30 min |
| B accepts M3 within | 3 min of sending M2 | 30 min |

## Secret handling

`a`, `ea`, `b`, `eb`, and `linkSecret` live only in JS memory. Never in storage, URLs (except the
link fragment, which is stripped on load), logs, or the console. Drop references as soon as the
spec says to discard them, and on abort or timeout.
