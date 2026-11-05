---
name: keyleash
description: Use when a task needs an API key, token, password or other credential (calling an authenticated API, logging in to a service, running a deploy or test that needs secrets), or when the user wants to store, list, approve or revoke secrets. Secrets are entered by the user in a desktop popup and used by name; never ask for a secret in chat.
---

# keyleash

`keyleash` keeps credentials out of the conversation. The user types a value into a desktop
popup, it is stored in the system keyring, and you use it by name. You never see the value.

## Rules

- Never ask the user to paste a secret into chat, and never write one into a file or a command line.
- Never try to print, read or decode a secret's value. There is no command for it, and reading
  the keyring or the approvals file directly is blocked.
- If a secret is missing, add it with the popup (below) or tell the user which name is needed.

## Using a secret

```bash
keyleash list                                   # names you can use
keyleash run STRIPE_TEST_KEY -- curl -s -u "$STRIPE_TEST_KEY:" https://api.stripe.com/v1/balance
```

`keyleash run NAME... -- command` sets `$NAME` in that command's environment only.

- Quote the command so your shell does not expand `$NAME` before keyleash runs. Either pass a
  program that reads the variable itself, or wrap it: `keyleash run NAME -- sh -c 'curl -H "Authorization: Bearer $NAME" …'`
- `NAME=OTHER` exposes the secret under a different variable: `keyleash run MYAPP_DB_URL=DATABASE_URL -- npm test`
- Several secrets: `keyleash run A B C -- command`
- Output is masked: the value (also base64, hex and URL-encoded) appears as `[secret:NAME]`.
- The command's exit code is passed through. Exit code 77 means the user denied the request:
  stop and tell them, do not retry or look for another way to get the credential.

The first use of a secret shows the user a popup with the exact command. They choose allow once,
allow for a while, allow for this session, or deny. Keep the command short and readable so
they can judge it, and do not bundle unrelated work into it.

## Adding a secret

```bash
keyleash add STRIPE_TEST_KEY
```

This opens a popup on the user's screen; tell them it is coming and what to enter. Run it with
a long timeout (5 minutes). Names use letters, digits and `_`, and become the environment
variable name. Use descriptive, project-scoped names such as `MYAPP_STRIPE_TEST_KEY`.

## Other commands

- `keyleash grants` shows what is approved right now, `keyleash revoke [NAME]` withdraws it.
- `keyleash rm NAME` deletes a secret (the user confirms in a popup).
- `keyleash setup login|dedicated` chooses where new secrets go: the login keyring, or a separate
  keyring with its own password that stays locked between uses. This is the user's decision; ask.
