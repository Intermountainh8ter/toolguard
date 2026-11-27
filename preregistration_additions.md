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
