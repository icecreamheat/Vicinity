# Security model

Vicinity tells two people one thing: are the hex cells they picked the same cell or touching,
measured at the coarser of their two chosen levels? Locations are picked by hand on a map. The app never
asks the device or the network where you are.

The comparison is a two-party protocol (RN1, specified byte for byte in [PROTOCOL.md](PROTOCOL.md)). It
uses blinded private set intersection over ristretto255, with zero-knowledge proofs, and it runs
entirely in the two browsers. The server never computes anything about location. In link mode it is a
blind mailbox, and codes mode doesn't use it at all.

## Who learns what

| Party | Learns | Does not learn |
|---|---|---|
| **Relay / server** | That a mailbox was used: up to three fixed-size (1052-byte) encrypted frames — an initiated session always leaves all three filled, real or dummy — their timing, and the IP addresses involved | Any cell, either level, or the result. Every frame is the same size, and the frame key comes from the link fragment, which browsers never send to servers. A KV dump shows no session shape (always 3 frames), pins write times only to a window of several minutes (bucketed deadlines + jittered TTLs), and deletion times are jittered by ±3 min |
| **B** (responder) | The result bit and A's maximum level `lA`, which is part of the request | A's cell. A's blinded values are fresh per session, and A's final message carries only a zero-knowledge proof of the bit, never the unblinded values |
| **A** (initiator) | The result bit and the common level `lc` (so whether B picked a coarser level) | B's cell, or which of B's 7 neighbor values matched |
| **B + relay together** | The same as B alone | — |

Each person's screen is protected as well as their privacy:

- **B can't fake A's result.** For each of its 7 slots, B proves (πB) that `Z_j = b_j·X_lc + δ_j·PA`
  for secrets it knows. Without that proof, B could plant `V_1 = r·G`, `Z_1 = r·PA` and make A's
  screen say NEAR. With it, making a slot match requires building `V_j` from the hash of A's actual
  cell, which B can only do by guessing the cell. That guess is its ordinary one-bit probe.
- **A can't learn one answer and prove another.** For each slot, B picks fresh secrets `b_j` and
  `δ_j` and sends `V_j = b_j·Hg(t_j) + δ_j·G` and `Z_j = b_j·X + δ_j·PA`. It never publishes
  `b_j·G` or `δ_j·G`. Write `h`, `x` and `a` for the discrete logs of `Hg(t_j)`, `X` and `PA`.
  Within one slot, `(b_j, δ_j) ↦ (V_j, Z_j)` is a linear map with determinant `a·h − x`:
  - If `X ≠ a·Hg(t_j)`, the map is invertible. The pair is then uniformly random and carries no
    information about `t_j`.
  - If `X = a·Hg(t_j)`, then `Z_j = a·V_j`.

  The slots are independent. So, apart from the zero-knowledge πB, A's view of B's reply depends
  only on which slots satisfy `X = a·Hg(t_j)`. That is exactly the statement A must prove to B, with
  an OR-proof for NEAR or an inequality proof for NOT NEAR. This holds whatever `X` and `PA` A sends
  and whatever A computes locally. It closes the three attacks that broke earlier drafts:
  - a blinding key `a' ≠ log PA`
  - mixing two cells into `X`
  - adding a `G` offset to `X`

  `tests/attack_analysis_test.js` re-runs all three as regression tests, checks the linear-algebra
  argument with known discrete logs, and shows why each ingredient is needed. A forged or mismatched
  proof from A is rejected; B then sees "couldn't verify", never a result.
- **Messages are single-use and time-limited.** Each session processes at most one reply. Replies
  that arrive late are refused: in link mode A waits 10 minutes and B waits 3; in codes mode both
  wait 30 minutes. A message with the wrong version, type, length or session ID is rejected and the
  session stays usable, so a mistaken paste doesn't kill it. Any other rejection ends the session and
  wipes its secrets.
- **A's proof takes the same work either way.** A always computes both the NEAR and the NOT NEAR
  proof shapes, so the relay can't read the result from how long A takes to post its final message.

**This is an argument, not a formal proof.** It assumes ristretto255 discrete logs are hard, models
the Fiat–Shamir hashes as random oracles, and treats the proofs as sound and zero-knowledge. It
should be reviewed by a cryptographer before anyone relies on it.

## Either side can choose what it asks

**Each session still answers about one bit, but the question can be shaped:**

- **B** can put any 7 cells at level `lc` into its slots instead of the 7 around its own, for example
  7 scattered cells. It can also disable slots by making them inconsistent. Either way, A's answer
  only tells B whether A's cell is in a set of at most 7 cells.
- **A** can claim any cell, which is just lying. A can no longer combine cells or keys to ask a
  sharper question: any `X` that isn't `a·Hg(one cell)` reveals nothing to A and leaves B shown
  NOT NEAR, so both screens agree.

Both of these are forms of lying about your own cell.

## Out of scope

- **Lying about your own cell.** Anyone can pick a false cell. The protocol checks two picks against
  each other; it can't check either pick against reality.
- **Repeated sessions.** Each run reveals one bit. Many runs against the same person, especially with
  shifted or sharper questions, can narrow down where they are. Only run it with people you choose,
  and don't answer request after request.
- **Abort and fairness.** A learns the result first and may simply never send the final message. B
  then sees "didn't finish". A cannot turn this into a wrong result on B's screen.
- **Relay metadata.** The relay sees IP addresses, timing, and that two parties met through a mailbox.
  It has no rate limiting, so someone could fill storage with junk frames. Frames expire after about
  15 minutes (±3 min jitter); stored deadlines are rounded to 5-minute buckets, and empty slots of an
  initiated session are filled with random dummy frames, so a KV dump reveals neither the write time
  precisely nor whether a session completed (see METADATA-HARDENING.md). A live observer who polls
  continuously can still watch a session progress in real time.
- **Link and codes channel.** Anyone who gets the link, or the request code, can answer in B's place,
  but only the first answer is accepted. In codes mode the request is plaintext: whoever can read your
  chat sees `lA` and the timing of the messages, but not cells or the result. The channel you use to
  share the link or codes is assumed to reach the right person.
- **Malicious served code.** Whoever serves the JavaScript can change it and defeat everything above. As
  a mitigation, `deno task build:standalone` builds `dist/vicinity.html`, a single self-contained
  file that runs codes mode offline (its CSP forbids all network access). The build writes the file's
  SHA-256 to `dist/vicinity.html.sha256`; check a saved copy against that hash (see README.md)
  and open it from disk.
- **Side channels.** JavaScript BigInt arithmetic, used by the vendored noble library, is not
  constant-time. Timing attacks by code running on the same device are not defended against.

## Handling secrets

- The keys `a`, `ea`, `b` and `eb`, the session keys, and the link secret exist only in JavaScript memory.
- They are never written to storage, logs or the console.
- The link secret travels only in the URL fragment, and the page removes it with
  `history.replaceState` as soon as it loads.
- Session secrets are dropped when the protocol is done with them, on any rejection, and on
  `abortSession()`.
- The server logs no mailbox IDs, frame contents or IP addresses.

Cryptographic primitives:

- **Vendored library:** `@noble/curves` and `@noble/hashes` 2.4.0. Exact versions, hashes, and RFC
  known-answer tests are listed in `public/vendor/VERSIONS.md`.
- **From the browser (WebCrypto):** AES-256-GCM, HKDF-SHA256 and SHA-256.
- **Randomness:** only `crypto.getRandomValues`.
