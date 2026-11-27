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
