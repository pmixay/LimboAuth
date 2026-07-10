# Account Protection — Tuning & Improvement Plan

Status: proposed (not yet implemented). Written after the first monitor-mode data
from production. Branch: `claude/account-protection-system-3ojjmd` (PR #3).

This document describes concrete fixes and improvements the live data revealed. It does
**not** change behavior on its own — it is the work list for the next change.

---

## 1. Background — two findings from production monitor data

Both came from real `PROTECTION_EVENTS` on the running server, one hour apart. They are
**opposite** miscalibrations, which is the useful part: it tells us the current thresholds
are not yet fitted to this server's traffic (the whole point of the monitor-only phase).

### Finding A — False positive: same-IP alt "spray" (`dnecek2014`)

```
severity=CRITICAL score=100 outcome=LOGIN_SUCCESS nick=dnecek2014 ip=217.114.146.6
cluster=account:dnecek2014 brand="optifine"
factors=[PASSWORD_SPRAY:+20(same password vs 3 distinct accounts),
         CONFIRM_SPRAYED_PASSWORD_SUCCESS:+80(successful password sprayed vs 3 accounts)]
```

- All activity on `217.114.146.6` is a **name-family**: `danecek2014` (7 sessions) and
  `Dnecek2014` (3), i.e. typo-variants of one person, sharing one password.
- The flagged in-game behavior (teleport to AFK zone, then trade) was later confirmed
  **benign**: a *friendly* trade in which `dnecek2014` *received* resources from a friend.
  A compromised account being liquidated moves items **out**; receiving them is
  owner-shaped.
- **Verdict: almost certainly a false positive.** One person reusing one password across
  their own typo-alts satisfies every condition of `PASSWORD_SPRAY` +
  `CONFIRM_SPRAYED_PASSWORD_SUCCESS`, because those factors count *distinct accounts a
  password was tried against* without asking **whose** accounts they are.

### Finding B — False negative: checker hit under-scored (`finsterry` on `185.159.162.53`)

From `/limboauth protection recent` (newest first; all within ~1h):

```
SUSPICIOUS 45 loool_000       185.159.162.53 LOGIN_FAIL
INFO       20 pipka2282282    185.159.162.53 LOGIN_FAIL
INFO       20 fl0paaaaaaaaa   185.159.162.53 LOGIN_FAIL   (x3)
INFO       20 finsterry       185.159.162.53 LOGIN_SUCCESS   <-- oldest of the group
```

- One IP, ~1 hour, **≥4 distinct unrelated usernames** (not a name-family), mixed
  fail/success — the textbook credential-stuffing / checker signature.
- Reading oldest-first, **`finsterry` succeeded first**, then the same IP kept grinding
  other accounts and failing. That is a checker that found a working credential and
  continued down its list.
- **The actual takeover (`finsterry`) logged only `INFO 20` — no alert.** This is a
  false **negative**, and operationally worse than Finding A: it costs an account.

Why the real hit slipped through — three structural gaps:

1. **The success came first.** At `finsterry`'s success the IP had no distinct-target
   volume yet, so the volume factors that later lifted `loool_000` to SUSPICIOUS hadn't
   happened.
2. **The source never crossed HIGH.** It peaked at 45 (< 50), so it was never "flagged,"
   and flagging only elevates *future* successes anyway.
3. **Combo lists defeat the spray factor.** Credential stuffing uses a *different*
   password per username, so the fingerprint-based `CONFIRM_SPRAYED_PASSWORD_SUCCESS`
   never groups the attempts, and `CONFIRM_SUCCESS_AFTER_DISTRIBUTED_FAILURES` keys on
   failures against *the same account* from other IPs — `finsterry` had none on itself.

---

## 2. Root cause (shared by both findings)

The confirmation factors classify on **how many distinct accounts / passwords** are
involved, but never on **whether those accounts belong to the source**. That single
missing signal produces both errors:

- Finding A fires CRITICAL because it can't tell "3 accounts" are one owner's alts.
- Finding B stays INFO because "this source has been failing against many accounts that
  are *not* its own" is not expressed as a confirmation factor at all.

The fix is one concept, reused: the **foreign target**.

---

## 3. Proposed code changes

### 3.1 Backbone: the "foreign target" flag

A target is *foreign* to the current source when the account exists and its stored
`LOGINIP` is on a **different /24 (or /64) subnet** than the current attempt's source.
Subnet-level (not exact-IP) so a returning player on a rotated dynamic address inside
their usual ISP block is **not** counted foreign — mirrors the existing
`DORMANT_ACCOUNT_TAKEOVER` comparison.

Implementation:

- `ProtectionAggregator#update` already has `AttemptObservation.getStoredLoginIp()` and the
  current subnet. Compute `foreignTarget = accountExists && stored present &&
  SubnetKey.ofLiteral(stored) != currentSubnet` and store it on
  `ActivityWindow.AttemptEvent` (new boolean, alongside `churn`/`newSource`).
- The same `AttemptEvent` instance is shared across the ip/subnet/account/fingerprint
  windows, so the flag becomes available to every factor for free.
- Add `ActivityWindow` distinct-count queries built on the existing `distinctCount(since,
  predicate, key)` helper:
  - `distinctForeignFingerprintTargets(since)` — foreign targets a fingerprint was tried
    against.
  - `distinctForeignFailedTargets(since)` — foreign existing accounts an IP *failed*
    against.
- Add the two counts to `AggregateSnapshot` (append at the end — never insert mid-record;
  the constructor is positional and tests wire it by position).

Note: `newSource` (used by `MULTI_ACCOUNT_NEW_SOURCE_SUCCESS`) is the success-only,
exact-IP flavor of this same idea. Keep it as-is (spec-blessed, exact-IP by design) but
document that `foreignTarget` is the subnet-level, any-outcome generalization so a future
maintainer doesn't invent a third variant.

### 3.2 Fix Finding A — gate the spray confirmation on foreign targets

`RiskScorer` confirmation block, currently:

```java
if (snapshot.fingerprintDistinctTargets() >= 3) {
  confirmation += add(CONFIRM_SPRAYED_PASSWORD_SUCCESS, 80, ...);   // -> CRITICAL
}
```

Change the trigger to require **foreign** targets:

```java
if (snapshot.foreignFingerprintTargets() >= 2) {
  confirmation += add(CONFIRM_SPRAYED_PASSWORD_SUCCESS, 80, ...);
}
```

- Same-owner alt clusters (`dnecek`) have **0 foreign targets** → confirmation never
  fires → the event drops from `CRITICAL 100` to `PASSWORD_SPRAY 20` = **INFO**.
  Acceptable: "one person reusing a password across their alts" is INFO-worthy at most.
- A genuine spray reaches accounts stored elsewhere → foreign targets ≥ 2 → still
  CRITICAL. Detection of real sprays is preserved.
- Optionally also switch the base `PASSWORD_SPRAY` tiers to foreign-target counts for
  consistency; lower priority since 20 = INFO is already quiet.

### 3.3 Fix Finding B (part 1) — new confirmation factor for multi-target sources

New factor `CONFIRM_SUCCESS_FROM_MULTI_TARGET_SOURCE` (CONFIRMATION category). On a
`LOGIN_SUCCESS`, read `snapshot.foreignFailedTargets()` (distinct foreign existing
accounts this IP has **failed** against in the distribution window) and score tiered:

| foreign failed targets | points | resulting severity (alone) |
|---|---|---|
| ≥ 3 | 50 | HIGH |
| ≥ 6 | 80 | CRITICAL |

- Catches the checker-with-a-hit pattern when the success lands **after** the failures.
- FP guard: counts only *foreign* *existing* accounts, so a shared-IP household where
  several people fail on their **own** accounts (non-foreign) then someone succeeds does
  **not** trip it.

### 3.4 Fix Finding B (part 2) — retroactive elevation for "success-first" hits

`finsterry` succeeded *before* any failures, so no real-time check can catch it. Needed: a
lightweight retroactive pass that piggybacks the existing pipeline (no new persistence).

- The successful attempt is still in the source's `ipWindow` (bounded ArrayDeque).
- When processing any attempt, if the source **crosses** the multi-target threshold
  (`foreignFailedTargets` just reached the ≥3 tier), scan the same `ipWindow` for a recent
  `LOGIN_SUCCESS` on a foreign target that has **not** already been alerted at
  confirmation severity, and emit a delayed `ProtectionAlertEvent` /
  `PROTECTION_EVENTS` row for it (reusing `CONFIRM_SUCCESS_FROM_MULTI_TARGET_SOURCE`,
  cluster key `account:<nick>`).
- Dedup with the existing `AlertDispatcher` cooldown so the retroactive alert doesn't
  double-fire with the live one.
- **This is the one architecturally significant piece** (touches the manager's
  process loop, not just the pure scorer). Keep it behind the same single executor thread;
  no locking needed.

### 3.5 Config additions (auto-append on upgrade, same as before)

- `scoring.weights.confirm-success-from-multi-target-source-3: 50`
- `scoring.weights.confirm-success-from-multi-target-source-6: 80`
- `scoring.spray-foreign-target-min: 2` (threshold for 3.2)
- Everything else reuses existing windows. No DB schema change.

### 3.6 Tests (must accompany the change)

- **FP regression:** `dnecek`-shaped scenario — one IP, one password, 3 same-owner alts
  (stored LOGINIP == source) relogged → must stay **≤ SUSPICIOUS** (assert not CRITICAL).
- **Detection preserved:** real spray across 3 foreign accounts → still CRITICAL.
- **FN fix (after):** checker fails vs 4 foreign accounts, then succeeds on a 5th →
  success must be **≥ HIGH**.
- **FN fix (success-first / retroactive):** `finsterry`-shaped — success first, then ≥3
  foreign failures from the same IP → a retroactive confirmation event is emitted for the
  earlier success.
- All existing FPR scenarios (`forgottenPassword…`, `sharedIpMistypes…`,
  `ownAltsAfterIspAddressChange…`) must pass **unchanged**.
- `SettingsUpgradeTest`: assert the new weight keys auto-append.

---

## 4. Non-code / operational improvements

### 4.1 Enable GeoIP (highest-value lever, no code)

`finsterry` from a checker IP in another country would have added
`GEO_COUNTRY_MISMATCH (20)` (+ possibly `GEO_HOSTING_ASN (10)` — `185.159.162.53` looks
like a hosting/VPN range), lifting it from 20 to 40–50 **on its own**, likely into
SUSPICIOUS/HIGH before any of the above code changes. Set a free MaxMind key in
`protection.geoip`. For first-try manual takeovers this is the single strongest signal.

### 4.2 Enforcement thresholds

At SUSPICIOUS-45 the checker IP would **not** be auto-blocked (default
`block-source-on: HIGH`). Once §3.3 lands, real checkers reach HIGH and the default block
works. Until then, do **not** lower `block-source-on` to SUSPICIOUS — the `dnecek` FP sat
at CRITICAL, so a naive lowering would block legitimate players. Keep enforcement in
MONITOR for now; revisit after §3 is deployed and the events table is re-checked.

### 4.3 Triage ergonomics

- `/limboauth protection recent` shows only severity/score/nick/ip/outcome. Add an
  `inspect <nick>` (or include the `factors=[...]` string) so an admin can see *why*
  without grepping the server log. Small, optional.

---

## 5. Sequencing & risk

1. **§3.1 + §3.2 (foreign-target backbone + spray FP fix)** — highest confidence, smallest
   blast radius, directly kills the `dnecek` false positive. Ship first.
2. **§3.3 (multi-target-source confirmation)** — closes most of the `finsterry` gap
   (successes that follow failures). Medium size, low FP if gated on foreign+existing.
3. **§4.1 GeoIP** — parallel, no code, do immediately.
4. **§3.4 (retroactive elevation)** — largest/most invasive; do last, only if success-first
   misses remain after §3.3 + GeoIP. Reassess with fresh data before building it.

Each step is independently shippable and independently testable. None changes the DB
schema; all new config keys auto-append; monitor-mode remains the default throughout.

---

## 6. Open questions for the server owner

- Confirm the §3.2 foreign-target threshold (`≥2`) against real alt behavior — do players
  routinely share one password across **3+** alts on **different** networks? If so, raise
  it or add a same-owner allowance.
- Is GeoIP acceptable to enable (privacy/ops)? It materially changes the FN picture.
- After §3 ships and a week of fresh monitor data: are HIGH events on known-legit players
  rare enough to turn on enforcement?
