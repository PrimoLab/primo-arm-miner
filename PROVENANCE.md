# Provenance

This repository contains substantial original work by primo-arm-miner
contributors. It also has known development ancestry from earlier
GPL-licensed mining software used as references and integration harnesses
during the project bootstrap phase.

This document is a release-compliance record. It is intentionally
conservative: listing a file or subsystem here does not assert that every
current line remains derivative, only that the subsystem has known ancestry
that should be disclosed when distributing releases.

## Release posture

- Distribute this repository under `GPL-3.0-or-later`.
- Preserve third-party copyright and license notices that still appear in
  the tree.
- Do not market the repository as wholly independent of prior GPL-licensed
  mining software unless you have a separate clean-room record or legal
  review supporting that claim.

## Known source ancestry

- `ccminer_arm_cc1`
  - Used as the ARM-native Verus development harness and as the starting
    point for earlier coordinator, config, and stratum scaffolding.
  - Files substantially rewritten during ownership and compliance passes
    include:
    - `src/miner.cpp`
    - `src/config.cpp`
    - `src/stratum.cpp`
    - `include/miner.h`
    - `src/main.cpp`
    - `src/algorithm/verus.cpp`

- `ccminer_oink70_source`
  - Kept as a historical portable reference for behavior and comparison
    during the Verus bring-up and validation work.

- `cpuminer-opt-26.1`
  - Used as a reference for SHA256d and Scrypt integration patterns and
    selected utility behavior.

## Third-party notices retained in-tree

- `src/algorithm/scrypt.h`
  - Retains Colin Percival copyright and redistribution terms and must be
    preserved in redistribution.

## Compliance note

The files listed above were substantially rewritten, but the repository was
not developed under a documented clean-room process. For release purposes,
the safest posture is to treat the combined work as GPL-covered and preserve
this provenance record alongside the project license.
