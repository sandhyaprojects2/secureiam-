# SecureIAM — Phase 1 Security Review

This document records the security-relevant decisions made in Phase 1
(Authentication) and the reasoning behind each one. It's written to be
readable on its own — by a reviewer, an interviewer, or future-you six
months from now who's forgotten why a particular choice was made.

---

## Password Security

**Algorithm: Argon2id**, via `argon2-cffi`, configured with:

| Parameter | Value | Meaning |
|---|---|---|
| `time_cost` | 3 | Number of iterations |
| `memory_cost` | 65536 KiB (64 MiB) | Memory required per hash attempt |
| `parallelism` | 4 | Parallel lanes used during hashing |

**Why slow hashing at all:** passwords are low-entropy secrets chosen by
humans. If the password database is ever exfiltrated, the only thing
standing between an attacker and the plaintext passwords is how expensive
it is to try candidate passwords against each hash. Argon2id is deliberately
slow and memory-hard — it resists both CPU-based brute force and GPU/ASIC
parallel cracking, which a fast hash like SHA-256 does nothing to prevent.

**Why Argon2id specifically:** it's the winner of the Password Hashing
Competition and is the current OWASP-recommended default for new systems,
combining Argon2i's side-channel resistance with Argon2d's GPU resistance.

**Verification never raises on mismatch:** `verify_password()` catches
Argon2's internal `VerifyMismatchError`/`VerificationError`/`InvalidHash`
and returns a plain `False` in every case. This means "wrong password" and
"corrupted/invalid hash" are handled identically by every caller, rather
than requiring different exception handling for what should be an
indistinguishable outcome to the end user.

**Password policy:** minimum length 10 characters, no forced composition
rules (no mandatory uppercase/digit/symbol). This follows NIST SP 800-63B
guidance: arbitrary composition rules push users toward predictable
patterns (e.g. `Password1!`) without meaningfully increasing entropy, while
length is the strongest lever available.

---

## Refresh Token Security

**Format: opaque, not a JWT.** Generated via `secrets.token_urlsafe(64)` —
a cryptographically secure random value carrying no embedded claims. There's
no need for a refresh token to be self-describing, since the server always
looks it up by hash in the database anyway; making it a JWT would only
expose an unencrypted, inspectable payload for no benefit.

**Storage: SHA-256 hash only.** The raw token is returned to the client
exactly once, at issuance, and is never persisted, logged, or otherwise
retained server-side. Only `SHA-256(token)` is stored in
`refresh_tokens.token_hash`.

**Why SHA-256 and not Argon2id here:** this is the single most
interview-relevant judgment call in the whole system, so it's worth stating
plainly — **hash cost should match the entropy of what's being hashed, not
default to "as slow as possible."** A password is a low-entropy human
choice; brute-forcing it is exactly the threat Argon2's slowness defends
against. A refresh token is a 64-byte cryptographically random value with
effectively 512 bits of entropy — brute-forcing it is computationally
infeasible regardless of hash speed. Using Argon2id here would add real
latency to every single refresh request (a hot path) while defending
against an attack that isn't the actual threat model for this value. SHA-256
gives a fast, deterministic, collision-resistant lookup key, which is
exactly what's needed.

**Rotation behavior:** every successful `/refresh` call revokes the
presented token and issues a brand-new one, linked via `replaced_by`. A
revoked, expired, or unknown token is rejected with an identical, generic
error.

**Reuse detection (Phase 5):** presenting a token that was already revoked
*via rotation* (i.e. one with `replaced_by` set) is treated as evidence of
a possible stolen-token replay, not merely an ordinary invalid token. The
response walks the `replaced_by` chain forward to the family's current
active leaf and revokes it too — fail-closed, on the assumption that
either the legitimate holder or an attacker could be the one currently
holding the live end of the chain, and the safer default is to kill it
either way. This is recorded internally (`refresh_token.reuse_detected` on
every such presentation; `refresh_token.family_revoked` only when a still-
live leaf was actually killed as a result) but never exposed externally:
the caller still receives the exact same generic rejection as any other
invalid token. A revoked token *without* a successor (`replaced_by` is
`None` — revoked via logout, never rotated) is explicitly **not** treated
as reuse: that's the ordinary, harmless shape of a client using a token
after the user already logged out, not evidence of anything. See
`docs/phases/phase-5.md` for the full design, including why the family-
revocation walk can never revoke an unrelated token (every node reached is
provably part of the same, single-user, strictly linear chain) and why the
walk-and-retry loop against a concurrently-racing legitimate rotation is
bounded, not unbounded.

**Concurrency-safe rotation (Phase 5):** the previous rotation logic
revoked the old token via an unconditional ORM attribute assignment, with
no guard against a second, concurrent caller doing the same thing to the
same row — a genuine lost-update race under Postgres's default READ
COMMITTED isolation, not merely a hypothetical one (it was reproduced
live, intermittently, in this project's own CI). It's fixed now via an
atomic conditional update, `UPDATE refresh_tokens SET revoked_at = now()
WHERE id = :id AND revoked_at IS NULL`, checking rows-affected: Postgres
itself guarantees at most one concurrent caller's update can ever affect
the row, so at most one concurrent rotation of the same token can ever
succeed. This is deterministic, not probabilistic — see
`docs/phases/phase-5.md` for why an atomic conditional update was chosen
over `SELECT ... FOR UPDATE` for this codebase's specific async,
session-per-request architecture, and for the deterministic (non-timing-
dependent) test that proves it directly at the repository layer, alongside
the existing concurrent-HTTP-request integration test.

---

## JWT Security

**Algorithm: HS256.** This was a deliberate simplification: SecureIAM is
the only party that ever decodes an access token (any future client
application forwards the raw `Authorization` header to SecureIAM rather
than verifying the JWT itself), so there is no benefit to RS256's
asymmetric key distribution here — HS256 with a single server-side secret
is simpler and equally secure for this trust model.

**Claims:** `sub` (user id), `type` (`"access"`, self-describing in case
other JWT-based token types are introduced later), `iat`, `exp`, `jti`
(unique token id, unused in Phase 1 but present so Phase 7's
blacklist/rate-limiting work needs no token-format migration), `iss`
(issuer).

**Issuer validation:** `decode_access_token()` explicitly validates `iss`
against the configured issuer. A token signed with the correct secret but a
different (or missing) issuer is rejected.

**Expiration validation:** enforced by PyJWT via the `exp` claim, which
`decode_access_token()` requires be present (via the `require` option,
alongside `sub`, `iat`, `jti`, and `type`) — a token missing any of these
required claims is rejected outright, not silently accepted with a gap.

**Short TTL:** access tokens expire after 15 minutes (configurable). This
bounds the exposure window if an access token is ever intercepted — far
shorter than the refresh token's 14-day lifetime, which is why the two use
different security tradeoffs (fast-expiring bearer token vs. long-lived,
rotatable, revocable refresh credential).

**Uniform rejection:** `TokenValidationError` is raised for expired,
tampered, wrong-issuer, wrong-secret, and missing-claim failures alike —
deliberately not differentiated, so nothing downstream can distinguish
*why* a token was rejected.

---

## Enumeration Prevention

Three distinct flows enforce the same principle — a caller should never be
able to learn information about what exists in the system by observing
different responses for different underlying reasons:

1. **Login:** unknown email and wrong password both raise
   `InvalidCredentialsError` with the identical message
   (`"Invalid email or password."`). Tested directly at both the service
   layer (`test_login_unknown_email_and_wrong_password_give_identical_message`)
   and the HTTP layer (`test_login_unknown_email_returns_identical_response_to_wrong_password`),
   comparing full response bodies, not just status codes.

2. **Refresh:** unknown, expired, revoked, and inactive-account-owner
   tokens all raise `InvalidRefreshTokenError` with the identical message
   (`"Invalid or expired refresh token."`). Tested directly
   (`test_refresh_failure_reasons_are_indistinguishable`).

3. **Registration:** a duplicate email returns a generic 409
   (`"Unable to register with the provided details."`) rather than an
   explicit "email already exists" — though note this is a softer
   guarantee than login/refresh, since registration inherently must reject
   *something* distinguishable from success; the message itself just avoids
   being needlessly specific.

**One known, accepted exception to this principle:** `InactiveUserError` is
a *distinct* exception from `InvalidCredentialsError` in the login flow (per
explicit Phase 1 spec). This means a caller who supplies a *correct* email
tied to a deactivated account receives a different response (403, "Account
is inactive") than one who supplies a wrong password or unknown email (401).
This does leak "this email is registered and deactivated" — a narrower
leak than the login-oracle problem the rest of this design closes, but a
real one. It's implemented this way deliberately per specification rather
than an oversight; collapsing it into `InvalidCredentialsError` would be a
one-line change in `AuthService.login()` if this tradeoff is reconsidered
later.

---

## Secrets Management

- All configuration is loaded through `pydantic-settings`'
  `BaseSettings`, sourced from a `.env` file that is git-ignored.
- `.env.example` documents every required variable with placeholder values
  and is the only environment file committed to version control.
- `Settings` fails fast (`ValidationError`) at process startup if a required
  variable (`DATABASE_URL`, `JWT_SECRET_KEY`) is missing — this surfaces a
  misconfiguration immediately rather than allowing the app to boot into a
  broken or insecure state.
- `.gitignore` excludes `.env` and all `.env.*` variants (explicitly
  excepting `.env.example`) and was created *before* any other project file,
  specifically to prevent a real secret from ever entering git history via
  an early `git add .`.
- No secret, password, password hash, or token appears in any log statement
  anywhere in the codebase (verified by inspection, and indirectly by the
  API-layer tests confirming no password/hash material ever appears in a
  response body either).
