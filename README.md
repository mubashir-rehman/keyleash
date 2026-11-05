# keyleash

Let a coding agent use your API keys and passwords without ever seeing them.

You type a secret into a desktop popup. It is stored in your system keyring. The agent uses it
by name, one command at a time, and each use needs your approval in a popup. The value is masked
in the command's output, so it never lands in the conversation or the transcript.

Linux only, on any desktop with a Secret Service keyring (GNOME Keyring, KWallet, KeePassXC).

```
agent:  keyleash run STRIPE_TEST_KEY -- curl -s -u "$STRIPE_TEST_KEY:" https://api.stripe.com/v1/balance
you:    [popup]  An agent wants to use: STRIPE_TEST_KEY
                 Command: curl -s -u ... https://api.stripe.com/v1/balance
                 [ Deny ]  [ Allow 30 min ]  [ Allow this session ]  [ Allow once ]
agent sees the response, with the key shown as [secret:STRIPE_TEST_KEY] wherever it appears
```

## Install

Requirements: `python3-secretstorage` and `zenity` (both ship with Ubuntu desktop).

```
/plugin marketplace add mubashir-rehman/keyleash
/plugin install keyleash@keyleash
```

Inside Claude Code the `keyleash` command is on PATH once the plugin is enabled. To use it from
your own terminal as well, link `bin/keyleash` into a directory on your PATH.

## Commands

| Command | What it does |
|---|---|
| `keyleash add NAME` | Opens a popup for the value and stores it. |
| `keyleash list` | Names, where each is stored, and whether it is approved right now. Never values. |
| `keyleash run NAME... -- command` | Runs the command with `$NAME` set. `NAME=VAR` exposes it as `$VAR`. |
| `keyleash grants` | What is approved right now. |
| `keyleash revoke [NAME]` | Withdraws approvals (all of them without a name). |
| `keyleash rm NAME` | Deletes a secret, after a confirmation popup. |
| `keyleash setup login\|dedicated` | Where new secrets go (see below). |
| `keyleash lock` | Locks the dedicated keyring now. |
| `keyleash hooks [on\|off [DIR]]` | Switches the guard hooks off (or back on) for one project. |

There is no command that prints a value. To see or edit one, use your desktop's password
manager (Passwords and Keys on GNOME); keyleash's items are labelled `keyleash: NAME`.

## Approvals

The first use of a secret shows a popup with the secret's name, the exact command, the
directory and the agent session. You choose:

- **Allow once**: this command only.
- **Allow 30 min**: any command using that secret until the time is up. Change the length with
  `"grant_minutes"` in `~/.config/keyleash/config.json`.
- **Allow this session**: until that agent session ends. Other sessions still have to ask.
- **Deny**: the command is not run and exits with code 77.

Closing the popup, or leaving it for two minutes, is a deny. Approvals live in
`$XDG_RUNTIME_DIR/keyleash/grants.json`, which is in memory and gone when you log out.

## Where secrets are stored

- **login** (default): your login keyring. Encrypted on disk with your login password and
  unlocked while you are logged in. Nothing to set up.
- **dedicated**: a separate keyring called `keyleash` with its own password, which your keyring
  asks you for. keyleash never sees that password. The keyring is locked again when no approval
  is active, so using a secret after that asks for the password as well as the approval.

`keyleash setup dedicated` switches new secrets to the dedicated keyring. Existing ones stay
where they are and keep working.

## What this protects against, and what it does not

keyleash keeps secrets out of conversations, transcripts, shell history and files, and makes
every use something you agreed to. It is not a sandbox.

- A command you approve receives the real value. Masking covers the value itself and its
  base64, hex and URL-encoded forms in the output; a command that transforms the value some
  other way, or sends it over the network, is not stopped. Read the command in the popup.
- Any program running as you can read an unlocked keyring, write the approvals file, or drive
  the desktop to press the approval button. The bundled hook blocks an agent from doing these
  by accident, but it is a fence, not a wall. It reads command text only, so a script written
  to disk and then run is not inspected.
- "Allow this session" is tied to the session id the agent's environment reports
  (`CLAUDE_CODE_SESSION_ID`). A program can set that variable, so treat a session approval as
  "until that session ends", not as proof of who is asking.
- The dedicated keyring, while locked, is the one real boundary: nothing reads it without the
  password you type into the keyring's own prompt.

## Switching the guard off for one project

Some projects already keep credentials in files the agent is meant to read and write. There the
guard gets in the way: it asks before every write that contains something key-shaped.

```
keyleash hooks off            # this project (for a git checkout: the repository and all its worktrees)
keyleash hooks off ~/work/x   # another one
keyleash hooks on
keyleash hooks                # show where they are off
```

Switching off asks you to confirm in a popup, so an agent cannot do it on its own. Only the
guard is switched off; `keyleash add` and `keyleash run`, with their approval popup, work as before.

## Development

```
/usr/bin/python3 -B -m unittest discover -s tests -v
```

The tests show no popups. They replace the keyring and the approval popup, except for one
round trip that writes and deletes a dummy value in the login keyring.

## License

MIT
