---
slug: 14
title: |
  14. Choosing a TUI crate for setup command
authors:
  - name: Mithril Team
tags: [Proposed]
date: 2026-10-12
---

## Status

Proposed

## Context

With the goal of increasing Mithril adoption, we want to simplify the installation of the Mithril Signer for SPOs.
At present, following the Mithril signer node documentation and installing the signer takes around one hour.

We want to simplify this installation process by using a terminal user interface (TUI) to guide users through the signer installation flow.
We also need to choose a Rust TUI crate that will help us develop a smooth, one-command setup experience for users while remaining easy to maintain.

### Requirements

The selected crate must:

- be easy to test and maintain
- be robust enough to support future developments
- allow us to maintain our quality standards

#### Types of inputs

Two interaction modes were considered:

- **Q&A mode**: a sequence of prompts supporting:
  - string, with a default value
  - integer (prevent non-numeric characters or validate after input), with a default value
  - multiple-choice selection
- **Grid edit mode**: a grid showing all prefilled values, with row selection (mouse and arrow keys) to edit a value

#### Render

- progress bar for installation progress
- key-value summary

### Options considered

The following candidates were evaluated:

- [Ratatui](https://crates.io/crates/ratatui) with [crossterm](https://crates.io/crates/crossterm)
- [inquire](https://crates.io/crates/inquire)
- [dialoguer](https://crates.io/crates/dialoguer)
- [cliclack](https://crates.io/crates/cliclack)

For prompt-based crates (inquire, dialoguer, cliclack), the progress bar can be provided by [indicatif](https://crates.io/crates/indicatif).
Ratatui provides it natively with the `Gauge` widget.

### Crate comparison

#### Ratatui (core, widgets, crossterm)

- Downloads¹: 59 106 231
- Size²: 70.7 + 18.4 KiB
- Dependencies³: 207 (including color-eyre)
- Testable: ✅ [UI output unit test](https://ratatui.rs/tutorials/counter-app/basic-app/#testing-the-ui-output)
- Q&A mode: ✅
- Grid edit mode: ✅ Offer widgets Row and Cell structure to design tables
- Mouse support: ✅
- Ease of development : **Medium**. Lot of things are possible with Ratatui so it offer a lot of options and can bring complexity. ([Q&A Prototype](https://github.com/IntersectMBO/mithril/blob/ctl/3618-identify-a-TUI-crate-for-setup-command/ratatui-question-answer/src/main.rs), [Grid Edit Prototype](https://github.com/IntersectMBO/mithril/blob/ctl/3618-identify-a-TUI-crate-for-setup-command/ratatui-grid-edit-mode/src/main.rs))

#### dialoguer

- Downloads¹: 87 789 311
- Size²: 30.5 KiB
- Dependencies³: 22
- Testable: no specific tooling
- Q&A mode: ✅
- Grid edit mode: ❌ no real support, can be done manually with row formatting and/or by using the FuzzySelect feature
- Mouse support: ❌
- Ease of development : **Easy** for basic Q&A. Can be complex for implementing a custom Grid/table edit view ([Grid edit Prototype](https://github.com/IntersectMBO/mithril/blob/ctl/3618-identify-a-TUI-crate-for-setup-command/dialoguer-example/src/main.rs))

#### inquire

- Downloads¹: 21 997 939
- Size²: 98.9 KiB
- Dependencies³: 6
- Testable: no specific tooling
- Q&A mode: ✅
- Grid edit mode: ❌ no real support
- Mouse support: ❌
- Ease of development : **Easy** for basic Q&A. Can be complex for implementing a custom Grid/table edit view ([Documentation](https://docs.rs/inquire/latest/inquire/index.html))

#### cliclack

- Downloads¹: 3 863 258
- Size²: 37.2 KiB
- Dependencies³: 8
- Testable: no specific tooling
- Q&A mode: ✅
- Grid edit mode: ❌ no real support
- Mouse support: ❌
- Ease of development : **Easy** for basic Q&A. Can be complex for implementing a custom Grid/table edit view ([Documentation](https://docs.rs/cliclack/latest/cliclack/))

**Notes:**

1. Total downloads on crates.io as of 2026-10-12.
2. Crate size as displayed on crates.io.
3. Number of packages in the `Cargo.lock` of a minimal project using the crate (`grep -c '^\[\[package\]\]$' Cargo.lock`).

## Decision

We will use **Ratatui** (with the crossterm backend) for the signer setup command and other future TUI developments.

We will use a grid edit mode where all prefilled values are displayed and can be edited by row selection (keyboard and mouse).
Ratatui is the only evaluated crate that natively supports this layout, it provides first-class UI testing via `TestBackend`, and it has a large, active community with extensive documentation.

Given the number of dependencies, we will create a specific crate for the setup command instead of adding a sub-command for that purpose on the signer CLI.

## Consequences

- The dependency footprint is significantly larger (~200 crates vs ~10-20 for prompt-based crates).
- Input widgets (text, integer validation, defaults, selection) must be implemented or pulled from companion crates (e.g. `tui-input`).
- UI rendering can be covered by unit tests using Ratatui's `TestBackend`.
