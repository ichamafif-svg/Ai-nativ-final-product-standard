# Hardening the blocks

The standards (OWASP ASVS 5.0, CWE Top 25, NIST SSDF) list what to verify. A block can do more: it removes the way a
mistake is made instead of checking that nobody made it. Because every product uses the same blocks, one hardening
protects all of them. This page lists what the blocks do beyond the checklists, on both stacks (FastAPI,
`blocks/python/standard_blocks`; Next.js, `blocks/js/nextjs`), and what is still left to do.

## Principles

1. **Make the unsafe version impossible to write.** Typed values (`Secret`, `SafeHtml`, `TrustedUrl`), filters
   that SQLAlchemy applies itself, routes that cannot start without an access id.
2. **Bound everything by default.** URL, headers, body, JSON depth, text, items, numbers, time to first byte,
   outbound responses, child processes, archives, logs.
3. **Close the bypasses, not only the front door.** Attacks that get around a correct-looking check: DNS rebinding,
   parser differentials, leftmost X-Forwarded-For, decompression bombs, PDF name escapes, Unicode controls,
   embedded JWT keys, a rate-limit table an attacker can flush.
4. **Fail closed.** A missing or ill-typed value keeps its strict default; a broken values file stops the product; a
   hook or predicate that throws refuses; an unknown `@mfa` requires a second factor of everyone.
5. **Extend only towards strictness.** Product hooks (`refuse=` on the guard, `also=` on access) can only refuse.
   Loosening is a signed named value, never code.
6. **Last.** Every stored output names its version and parameters (`sv1.<kid>.…`, `scrypt$n$r$p$…`, `tk1.…`), so
   algorithms and costs can change without breaking stored data.

## Shared core

| | |
|---|---|
| `Values` | type-checked against `values.toml` (`TYPES`, `types.json`); a wrong type keeps the strict default and is reported once; an unreadable values file or invalid `STANDARD_VALUES` stops the product |
| `types` | `Secret` hides itself from `str`, `repr`, f-strings, logs, pickling and concatenation (`.reveal()` is the explicit act); `SafeHtml` is printed as is by templates, everything else escaped; `TrustedUrl` is built or checked against an allow-list |
| `store` | sessions and rate limits in one interface; memory (bounded, least-recently-used eviction) or Redis (TLS outside localhost, atomic token bucket in Lua); refused in production when several workers would each have their own memory |
| new values | `@body_max_bytes`, `@json_max_depth`, `@request_timeout_s`, `@outbound_max_bytes`, `@hosts`, `@trusted_types` |

## Per block

| Block | Beyond the checklists |
|---|---|
| **web** | body bounded before parsing (declared or streamed, 413), URL (414) and headers (431) bounded, security-relevant headers not repeatable; JSON bodies read once and strictly (UTF-8, no BOM, no duplicate key, no NaN, no lone surrogate, depth); **Fetch Metadata resource isolation** (cross-site non-navigation requests refused unless the origin is in `@origins`), besides the CSRF token; **`@hosts`** (421 otherwise); time until the response starts bounded (503); X-Forwarded-For read from the right behind `@trusted_proxies` only; limits per address and route and per address overall, in the shared store; HSTS two years, `Permissions-Policy` denying every powerful feature, CORP, `Origin-Agent-Cluster`, **Trusted Types** (`@trusted_types`), `upgrade-insecure-requests`; CSP sources limited to hosts and hashes (never `'unsafe-*'`, `data:`, `*`); `SameSite=None` rewritten; refuse-only hooks |
| **input** | every string, collection and number bounded even where a field forgot; NFC; invisible controls and bidi overrides refused (Trojan Source, spoofed names); frozen after validation; ready types (`Text[n]`, `Name`, `Id`, `Slug`, `Email`, `Count`, `Money` in minor units); in JS, `__proto__`/`constructor` keys refused |
| **access** | a FastAPI app with a route that names no id does not start in production; `also=` predicates (owner, tenant, amount) can only refuse, a throwing predicate refuses; every refusal is the same 403 |
| **session** | the store holds SHA-256 of session ids, never ids; a session presented by another client is ended; JWKS cached at most an hour, refreshed for an unknown key at most once a minute; tokens naming or carrying their own key (`jku`, `jwk`, `x5u`, `x5c`) or declaring `crit` refused; key type and `alg` must match; ID, access and logout tokens not interchangeable; `azp` for several audiences; `iat` in the future refused; token size bounded; **`@mfa` enforced from `amr`** (`provider` delegates explicitly); **back-channel logout** with replay protection; pending sign-ins bounded; provider endpoints must be https |
| **crypto** | per-message key (HKDF-SHA-256, 256-bit salt) before AES-256-GCM, so the GCM nonce limit never binds; versioned boxes with key ids and a `Keyring` for rotation (`needs_reseal`); scrypt parameters stored with the hash, bounded when read, `needs_rehash`; purpose-bound expiring signed tokens (`sign_token`, `verify_token`) |
| **outbound** | addresses checked **when the connection is made**, on every resolved address, and the checked address is the one connected to (DNS rebinding); link-local, metadata, multicast, reserved refused always; loopback and private only for a `host:port` in `@destinations`; no proxy from the environment; TLS ≥ 1.2; response size bounded on decoded bytes (gzip bombs); one deadline for the whole call; path traversal and `@` in paths refused |
| **files** | archives measured by decompressing (bounded, ratio ≤ 100, encrypted entries refused, odd names refused); PDFs with active content refused (names decoded first); WebP dimensions read; downloads sandboxed (`CSP: sandbox`), `no-store`; files opened without following links |
| **parse** | `strict_json`; YAML anchors, aliases and tags refused; size bounds on XML and YAML; overlapping repetition and backreferences refused in patterns, a time limit per match with the `regex` package; CSV neutralisation behind spaces and full-width signs, numbers kept; RFC 4514 DN escaping |
| **process** | program by absolute path or a fixed PATH; clean environment (no inherited secrets, no `LD_*`, `NODE_OPTIONS`…); own process group (a timeout kills grandchildren); limits on CPU, memory, file size, open files, no core dumps; output bounded while read; `arg()` refuses user values that would be read as options (CWE-88) |
| **render** | `clean_html` returns `SafeHtml`, `url` returns `TrustedUrl`; templates in Jinja's immutable sandbox; `json_for_script` (no `</script>`, no U+2028); `one_line` removes every line and control separator; `..` refused as a URL path part |
| **log** | `Secret` redacted by type, credentials by shape (JWT, AWS, GitHub, Slack, Stripe, Google, OpenAI-style, GitLab, bearer headers, private keys); control characters, ANSI escapes and bidi overrides neutralised; records bounded; **hash chain** (`seq`, `chain`, `verify_chain`) makes edits, deletions and reordering visible |
| **runtime** | `secret()` returns a `Secret`, refuses empty secrets, secrets others can write, and links out of the vault; `/health` says only ok or down in production; a check must answer exactly `True` |
| **data** | **`for_user(session, user)`**: SQLAlchemy adds the owner and tenant filters to every SELECT, UPDATE and DELETE of the session, and stamps new rows, refusing rows that name someone else; a model with neither column must be declared shared (`__standard_shared__ = True`) |

## Out of reach of a block

Some protections live in the identity provider or the platform, not in product code; the blocks rely on them and the
probes or the human check them:

- passwords, passkeys, MFA enrolment, brute-force protection, account recovery: the identity provider (Keycloak
  first); the session block refuses sign-ins without a second factor in `amr`;
- TLS termination, certificates, HTTP/2 and HTTP/3 limits, request smuggling between proxies: the platform;
- WAF, DDoS absorption at the edge: the platform; the guard's limits are the last line, not the first.

## The next three years

What the blocks are built to absorb without breaking products:

- **Post-quantum signatures.** The only asymmetric cryptography a product verifies is its provider's JWT signatures.
  When providers issue ML-DSA (FIPS 204) JOSE algorithms, they are added to the session block's allow-list; the
  symmetric primitives (AES-256, SHA-256, HMAC) keep their margin.
- **Device-bound sessions** (DBSC). The session record already carries a client binding; a key-bound proof replaces
  the user-agent hash when browsers ship it widely.
- **Passkeys everywhere.** Comes through the provider (`amr` `hwk`, `user`); nothing to change in products.
- **Stricter browser isolation.** Trusted Types is on by default; COEP (`require-corp`) is the next step when
  third-party resources allow it.
- **Rotation.** Keys rotate through `Keyring`, password-like hashes through `needs_rehash`, provider keys through the
  JWKS lifetime.

## Still to do

- The verification part (agreed for later): one probe suite run against both stacks, fuzzing every block,
  mutation testing, a minimum and pinned dependency set.
- Next.js blocks for crypto, files, outbound, log and data (their bans already hold).
- Probes for the new behaviour (Fetch Metadata, `@hosts`, body limits, back-channel logout, `for_user`).
