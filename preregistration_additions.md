# Pre-registration additions

## 2026-11-27T10:39:55Z 644-evasion proposal:65dd2e614465c66890b00e6f5ac9ff08d2aba53675723ed45619c19d8d97f8ca

Hypothesis: on the shell-and-filesystem catalog with seed 7 and 1000 seeded
renderings per encoding, an exact-match tier resolver blocks under 0.5 of
mixed-encoding Dangerous calls (allow-all blocks 0.0, block-all 1.0), while a
normalise-then-match resolver raises the mixed block rate to at least 0.9 with
a benign false-block rate of at most 0.01.

Metric: /evasion/mixed/block_rate (exact-match resolver).
Expected: below 0.5 (range 0.0 to 0.5).
Falsifier: the exact-match resolver blocks 0.5 or more of mixed-encoding
Dangerous calls, or the normalising resolver blocks under 0.9 or false-blocks
more than 0.01 of benign calls.

## 2026-11-27T11:09:23Z 650-spoof proposal:215c7bce72cf6dc74044c5556165ffe4365fd7bb92cc49336d8fe0b5a433cedd

Hypothesis: on the shell-and-filesystem catalog with seed 7 and 1000 seeded
trials per policy, where a spoofing server registers a Benign-tier tool under
a Dangerous tool's name before or after the genuine server with equal
probability, first-match and last-match resolution each let between 0.4 and
0.6 of spoofed Dangerous calls through as Benign, reject-on-collision lets 0.0
through, and reject-on-collision false-blocks a positive share of benign
same-tier duplicate registrations that first-match allows.

Metric: /policies/first_match/spoof_success_rate.
Expected: between 0.4 and 0.6; reject-on-collision 0.0.
Falsifier: first-match spoof success outside 0.4 to 0.6, or reject-on-collision
spoof success above 0.0, or reject-on-collision false-block rate on benign
duplicates equal to 0.0.

## 2026-11-27T11:13:30Z 651-spoof-rules proposal:5b84f3b50519663b6121beeefc0db0d12728c9b1a2910210df839e1d02242519

Hypothesis: on the shell-and-filesystem catalog with seed 7 and 1000 seeded
trials per rule, where a spoofing server registers a Benign tool under a
Dangerous tool's name before or after the genuine server with equal
probability, bare-name first-registered-wins assigns the wrong tier to between
0.4 and 0.6 of Dangerous calls, server-prefixed names with an exact catalog
lookup assign the wrong tier to 1.0 of them (unknown names fail open as
Benign), and prefix-stripping lookup assigns the wrong tier to 0.0 of genuine
calls but false-blocks the spoofing server's Benign calls at a rate of 1.0.

Metric: /by_rule/server_prefix_exact/misresolved_share.
Expected: 1.0 (range 0.99 to 1.0); first_registered_wins between 0.4 and 0.6;
prefix_strip 0.0.
Falsifier: server_prefix_exact misresolved share below 0.99, or
first_registered_wins outside 0.4 to 0.6, or prefix_strip misresolved share
above 0.0.

## 2026-11-27T15:23:00Z 652-rewrite proposal:9c038a5ebc81d250ef9ee943e993c012aca8b3769ed8a83007336ba755d290a5

Hypothesis: on the shell-and-filesystem catalog with seed 7 and 1000 seeded
trials, where each trial draws a tool uniformly from the catalog and a
manifest rewrites its path argument to a protected location, a gate keyed on
tool-name tier passes the share of rewritten calls whose tool is not
Dangerous-tier (11 of 16 tools), between 0.60 and 0.78, while an
argument-aware protected-path rule passes 0.0 of them and false-blocks 0.0 of
unrewritten calls.

Metric: /rewrite/name_gate_pass_share.
Expected: between 0.60 and 0.78; argument-aware pass share 0.0.
Falsifier: name_gate_pass_share outside 0.60 to 0.78, or the argument-aware
rule passing any rewritten call or false-blocking any unrewritten call.

## 2026-11-27T15:31:30Z 654-rugpull proposal:f836f7c3b78a46d6491db633413e26d7507eb85869178fe8827f83162b089f74

Hypothesis: on the shell-and-filesystem catalog with seed 7 and 1000 seeded
mutated-tool calls, a gate that approved tools at time zero and looks up tiers
by name alone passes at least 0.95 of calls to Dangerous tools whose
definition was mutated after approval (the name is unchanged), while a gate
that pins a SHA-256 of each tool definition passes 0.0 of them; the pinned
gate's false-block rate on unmutated calls is 0.0.

Metric: /arms/unpinned/pass_through_rate.
Expected: at least 0.95 (range 0.95 to 1.0); pinned pass_through_rate 0.0.
Falsifier: unpinned pass_through_rate below 0.95, or pinned
pass_through_rate above 0.0 on the seeded run.

## 2026-11-27T16:22:00Z 663-scanner-floor proposal:f3f0cd90383f89631257efd3417a2feb3cd24180b9596ca40641bcfe94c3ce9b

Hypothesis: on a seeded synthetic corpus of 1000 server descriptions (seed 7,
malicious prevalence 0.30, 40% of malicious descriptions author-obfuscated so
the keyword scanner cannot match, 5% of benign descriptions containing a
trigger word), the author-written keyword description scanner's precision
exceeds the flag-all floor (which equals the prevalence) by between 0.45 and
0.62, while flag-none has recall 0.0 and the scanner's recall stays below 0.70.

Metric: /scanners/regex/precision_gap_vs_flag_all.
Expected: between 0.45 and 0.62; scanner recall below 0.70.
Falsifier: precision_gap_vs_flag_all outside 0.45 to 0.62, or scanner recall
at or above 0.70, or flag-none recall above 0.0 on the seeded run.

## 2026-11-27T22:28:46Z 727-harnessnorm proposal:ea692f6ceeb4dd43e1e1671b4a7cf65ebeae6f8928983644968a55180638b946

Hypothesis: on 1000 seeded synthetic shell-and-filesystem calls (seed 7, 70%
of arguments containing backslashes), an author-written unescape-and-trim
normaliser changes the string the tool receives for some calls, and reports
no warning for at least 0.5 of those changes (silent_semantic_change_rate
>= 0.5), while a strict pass-through harness changes 0.0.

Metric: /transform/silent_semantic_change_rate.
Expected: at least 0.5 (range 0.5 to 1.0); pass-through change rate 0.0.
Falsifier: silent_semantic_change_rate below 0.5 on the seeded run, or a
non-zero pass-through change rate.

## 2026-11-27T22:41:01Z 730-retryfloor proposal:bbd1790f73e26102267202949f961212c4a9c2ea9d8ca7413aa337782ebfb600

Hypothesis: with injected errors drawn uniformly over four types (missing
required argument, wrong argument type, unknown tool, transient timeout) and
transient errors clearing with probability 0.5 per attempt, a bounded
identical-resend policy (3 retries) recovers a share of injected errors near
0.219 overall, all of it from the transient type, while recovering 0.0 of the
three deterministic schema error types; never-retry recovers 0.0.

Metric: /retry_floor/recovery_rate_bounded.
Expected: between 0.18 and 0.26 at n=1000 seed 7; deterministic-type
recovery exactly 0.0.
Falsifier: recovery_rate_bounded outside 0.18 to 0.26, or any deterministic
schema error type recovered by identical resend at a rate above 0.0.

## 2026-11-27T23:00:05Z 735-repairpolicy proposal:97611852154178134dc6900abff9abe1bb23e1261776cdbe6697060a1503e094

Hypothesis: on 1000 seeded synthetic shell-and-filesystem calls (seed 7), of
which a fixed author-written share are valid and the rest are near-valid in
one of four ways (string for integer, extra unknown argument, missing
required argument, wrong-case tool name), an author-written permissive repair
policy executes malformed calls (coerced, dropped or defaulted, altering
intent) at a rate of at least 0.5 of malformed calls, while the strict policy
executes 0.0 of them and its valid-call false-reject rate is 0.0. A
retry-once-then-strict policy is also scored; identical resend of a
deterministic malformation cannot succeed.

Metric: /policies/permissive/executed_malformed_rate.
Expected: at least 0.5 (range 0.5 to 1.0); strict exactly 0.0.
Falsifier: permissive executed_malformed_rate below 0.5 on the seeded run, or
strict executing any malformed call, or strict false-rejecting any valid call.

## 2026-11-28T01:09:39Z 763-pinsim proposal:bf907eadc5e56b7def3d8bd024b049803c5da5fc820863192d61434faa8c6af5

Hypothesis: in a synthetic population of 1000 servers (seed 7) where 30% are
poisoned, half of those from first listing and half at a later update, with a
per-period update probability of 0.5 over 8 periods, a pin-on-first-approval
scanner leaves between 0.50 and 0.60 of poisoned servers undetected (all
from-start poisoned plus late-poisoned servers that never update), flags 0.0
of from-start poisoned servers, and has a false-flag rate of 0.0 on clean
servers that do not change. Poisoned counts are fixed by rounding (not drawn),
so only the late servers' update draws vary with the seed.

Metric: /pin_scanner/undetectable_fraction_at_half_poisoned_from_start.
Expected: between 0.50 and 0.60; from-start detection exactly 0.0.
Falsifier: undetectable fraction outside 0.50 to 0.60 at seed 7 n=1000, or any
from-start poisoned server flagged, or any unchanged clean server flagged.

## 2026-11-28T01:15:30Z 764-ppvsweep proposal:d29e71c804f6c89c3e89e4d903901b165a5ef8ff631ba61c865a11a8cd50e26b

Hypothesis: in a seeded synthetic population of 100000 servers (seed 7)
scanned by a scanner with fixed sensitivity 0.8 and false-positive rate 0.1
per server, the positive predictive value at poisoned prevalence 0.01 is
between 0.05 and 0.10 (analytic value 0.0748), alerts per true finding exceed
10, and PPV falls below 0.5 at every swept prevalence under 0.1; the same
scanner has PPV above 0.8 at prevalence 0.5. Poisoned status and scanner
alerts are independent seeded Bernoulli draws.

Metric: /ppv_by_prevalence/0/ppv.
Expected: between 0.05 and 0.10.
Falsifier: PPV at prevalence 0.01 outside 0.05 to 0.10 at seed 7 n=100000, or
PPV at prevalence 0.05 or lower at or above 0.5, or PPV at prevalence 0.5 at
or below 0.8.

## 2026-11-28T02:19:05Z 781-pincoverage proposal:4a577364d4e4b3cb89cfa620b3ab02e33bb0d590d882cbc2273d90cc2c5c11a1

Hypothesis: on 1000 seeded synthetic tool definitions (seed 7) with one
mutation drawn uniformly over four fields (description, parameter name,
parameter type in the input schema, annotations), a description-only pin
detects between 0.20 and 0.30 of mutations, a name-only pin detects exactly
0.0, a full-definition SHA-256 pin detects exactly 1.0, and the full pin's
false-flag rate on unmutated definitions is exactly 0.0. Every mutation
changes its field's value, so the full-pin result follows from hashing; the
measured quantity is the field-coverage split, which is set by the uniform
field draw.

Metric: /coverage/detect_rate_description_only_pin.
Expected: between 0.20 and 0.30; name-only 0.0; full pin 1.0.
Falsifier: description-only detect rate outside 0.20 to 0.30 at seed 7 n=1000,
or name-only above 0.0, or full-definition pin below 1.0, or any unmutated
definition flagged by the full pin.

## 2026-11-28T02:59:02Z 791-labelnoise proposal:354369fbe2b90d4028fa4b8bdcdb293579490c4850f0a67bb5cdc97fef452699

Hypothesis: on the shell-and-filesystem catalog with seed 7 and 1000 trials,
adjacent-tier label flips with p=0.4 (the raw disagreement implied by 60%
agreement) leave a measurable share of Dangerous tools labelled below
Dangerous: the mean fraction of Dangerous tools mislabelled below the gate
threshold is between 0.35 and 0.45, because Dangerous has a single adjacent
tier (Caution), so every adjacent flip demotes it. A second arm replaces a
label with a uniform random tier with probability q=0.1 and is reported
without a pre-registered range. Flips are seeded Bernoulli draws, so the
result follows from p and the catalog; this bounds the harness, not any
deployed gate.

Metric: /label_noise/dangerous_below_threshold_fraction_adjacent.
Expected: between 0.35 and 0.45.
Falsifier: the measured mean fraction of Dangerous tools labelled below
Dangerous at p=0.4 falls outside 0.35 to 0.45.
