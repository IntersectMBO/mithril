# Mithril Setup

## Documentation

:construction: This is a work in progress and unstable crate :construction:

:rocket: The documentation is available at [`Mithril Setup Node`](https://mithril.network/doc/manual/develop/nodes/mithril-setup)

:mag: The architecture of the node is explained [here](https://mithril.network/doc/mithril/mithril-network/setup)

## Set up a Mithril signer

The `signer` command guides the setup of a Mithril signer in the terminal.
It is unstable for now and needs the `--unstable` flag:

```bash
mithril-setup --unstable signer
```

The command prefills the configuration values of the signer, lets you review and edit them, then generates the setup script and shows the command to run it.

:construction: For now the values are hardcoded and the setup script is not generated.

### Review screen

The values are listed in a table:

- **Label**: name of the value
- **Value**: the value, ending with `…` when it is longer than the column
- **Origin**: `Discovered` (read on the machine), `Guessed` (deduced from other values) or `User` (entered by you)
- **Status**: `OK`, `Not set` (optional value left unset), `Missing` (required value not set) or `Invalid` (value with errors)

The footer shows the description of the selected value, its errors and the keys available.

| Where        | Keys                                           | Action                                   |
| ------------ | ---------------------------------------------- | ---------------------------------------- |
| Table        | `↑`/`↓` or mouse wheel                         | Select a value                           |
| Table        | `Enter`                                        | Edit the selected value                  |
| Table        | `Ctrl+S`                                       | Go to the `Continue` button              |
| Table        | `Esc`                                          | Go to the `Abort` button                 |
| Edited value | `Enter`                                        | Save the value, an empty value unsets it |
| Edited value | `Esc`                                          | Cancel the edition                       |
| Edited value | `←`/`→`, `Home`/`End`                          | Move the cursor                          |
| Edited value | `Ctrl+←`/`Ctrl+→` (or with `Alt`)              | Move the cursor by word                  |
| Edited value | `Backspace`/`Delete`                           | Delete a character                       |
| Edited value | `Ctrl+Backspace`/`Ctrl+Delete` (or with `Alt`) | Delete a word                            |
| Edited value | Paste shortcut of the terminal                 | Paste a text, without its line breaks    |
| Buttons      | `←`/`→`                                        | Choose a button                          |
| Buttons      | `↑` or mouse wheel up                          | Go back to the table                     |
| Buttons      | `Enter`                                        | Press the button                         |
| Anywhere     | `Ctrl+C`                                       | Abort the setup                          |

`Abort` quits the setup without saving the values.
`Continue` checks the values.
When some values are in error, a popup lists them instead of going to the next step:

| Keys                   | Action                               |
| ---------------------- | ------------------------------------ |
| `↑`/`↓` or mouse wheel | Choose a value                       |
| `Enter`                | Close the popup and select the value |
| `Esc`                  | Close the popup, back on `Continue`  |

### Result screen

When the values are valid, the setup script is generated and the result screen shows the command to run to finish the setup.

- `Exit` closes the screen and prints the command in the terminal.
- `Back` goes back to the review with the confirmed values, `Continue` then generates the script again.
- `←`/`→` choose a button, `Enter` presses it, `Esc` or `Ctrl+C` exits.

When the script can't be generated, the screen shows the error instead.
`Back` goes back to the review, and `Exit` ends the command with the error.
