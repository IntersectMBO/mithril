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

| Name                               | Downloads¹ | Size (KiB)² | Dependencies³ | Testable                                                                                            | Q&A mode | Grid edit mode                                               | Mouse support |
| ---------------------------------- | ---------- | ----------- | ------------- | --------------------------------------------------------------------------------------------------- | -------- | ------------------------------------------------------------ | ------------- |
| Ratatui (core, widgets, crossterm) | 59 106 231 | 70.7 + 18.4 | 207⁴          | ✅ [UI output unit test](https://ratatui.rs/tutorials/counter-app/basic-app/#testing-the-ui-output) | ✅       | ✅ (grid and cell)                                           | ✅            |
| inquire                            | 21 997 939 | 98.9        | 6             | no specific tooling                                                                                 | ✅       | ❌ no real support                                           | ❌            |
| dialoguer                          | 87 789 311 | 30.5        | 22            | no specific tooling                                                                                 | ✅       | ❌ no real support, can be done manually with row formatting | ❌            |
| cliclack                           | 3 863 258  | 37.2        | 8             | no specific tooling                                                                                 | ✅       | ❌ no real support                                           | ❌            |

1. Total downloads on crates.io as of 2026-10-12.
2. Crate size as displayed on crates.io.
3. Number of packages in the `Cargo.lock` of a minimal project using the crate (`grep -c '^\[\[package\]\]$' Cargo.lock`).
4. Includes `color-eyre`, used in the proof of concept.

## Decision

We will use **Ratatui** (with the crossterm backend) for the signer setup command and other future TUI developments.

We will use a grid edit mode where all prefilled values are displayed and can be edited by row selection (keyboard and mouse).
Ratatui is the only evaluated crate that natively supports this layout, it provides first-class UI testing via `TestBackend`, and it has a large, active community with extensive documentation.

Given the number of dependencies, we will create a specific crate for the setup command instead of adding a sub-command for that purpose on the signer CLI.

## Consequences

- The dependency footprint is significantly larger (~200 crates vs ~10-20 for prompt-based crates).
- Input widgets (text, integer validation, defaults, selection) must be implemented or pulled from companion crates (e.g. `tui-input`).
- UI rendering can be covered by unit tests using Ratatui's `TestBackend`.
