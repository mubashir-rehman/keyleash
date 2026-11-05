#!/usr/bin/python3
"""keyleash hooks.

PreToolUse     keeps the agent from going around keyleash: reading the keyring directly
               or editing the approvals file (blocked); desktop automation tools need the user's OK (ask). A fence against accidents, not a sandbox.
UserPromptSubmit  notices when something that looks like a credential was pasted into chat.
SessionEnd     forgets the approvals given to that session.
"""
import json, os, re, subprocess, sys

HERE = os.path.dirname(os.path.realpath(__file__))
KEYLEASH = os.path.join(os.path.dirname(HERE), "bin", "keyleash")

BYPASS = [
    (r"keyleash/grants", "the keyleash approvals file"),
    (r"keyleash/config\.json", "the keyleash settings file"),
    (r"\bsecret-tool\b", "secret-tool"),
    (r"(import|from)\s+secretstorage|secretstorage\.", "the secretstorage library"),
    (r"org\.freedesktop\.secrets?", "the Secret Service bus"),
    (r"\bkeyring\s+(get|set|del)\b", "the keyring CLI"),
    (r"\bseahorse\b", "seahorse"),
    (r"gi\.repository.*\bSecret\b", "libsecret"),
]
# Not a secret path, but the same tools could click the approval popup: the user decides each time.
ASK = [
    (r"\bAtspi\b|\bpyatspi\b|\bdogtail\b|\bxdotool\b|\bydotool\b", "desktop automation that could press the approval popup"),
]
KEY_SHAPES = [
    r"\bsk-[A-Za-z0-9_-]{20,}", r"\bgh[pousr]_[A-Za-z0-9]{30,}", r"\bgithub_pat_[A-Za-z0-9_]{40,}",
    r"\bAKIA[0-9A-Z]{16}\b", r"\bxox[abprs]-[A-Za-z0-9-]{20,}", r"\b[rs]k_(live|test)_[A-Za-z0-9]{20,}",
    r"\beyJ[A-Za-z0-9_-]{15,}\.eyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{10,}",
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----", r"\bAIza[0-9A-Za-z_-]{35}\b",
]


def hooks_off(cwd):
    """True when the user switched the guard off for this project (keyleash hooks off)."""
    cfg = os.path.join(os.environ.get("XDG_CONFIG_HOME", os.path.expanduser("~/.config")), "keyleash", "config.json")
    try:
        with open(cfg) as f:
            dirs = json.load(f).get("hooks_off", [])
    except (OSError, ValueError):
        return False
    here = os.path.realpath(cwd or os.getcwd())
    return any(isinstance(d, str) and (here == d or here.startswith(d + os.sep)) for d in dirs)


def main():
    try:
        data = json.load(sys.stdin)
    except ValueError:
        return 0
    event = data.get("hook_event_name")
    if event != "SessionEnd" and hooks_off(data.get("cwd")):
        return 0

    if event == "PreToolUse":
        ti = data.get("tool_input") or {}
        text = " ".join(str(ti.get(k, "")) for k in ("command", "file_path"))
        for pattern, what in BYPASS:
            if re.search(pattern, text):
                print(f"keyleash: blocked, this touches {what} directly. Secrets are only used through "
                      f"`keyleash run NAME -- command`, which asks the user for approval.", file=sys.stderr)
                return 2
        for pattern, what in ASK:
            if re.search(pattern, text):
                print(json.dumps({"hookSpecificOutput": {
                    "hookEventName": "PreToolUse", "permissionDecision": "ask",
                    "permissionDecisionReason": f"keyleash: this uses {what}. Approve only if you want the agent "
                                                "to drive the desktop; it must never be used on a keyleash popup."}}))
                return 0
        # a credential about to be written into a file: let the user decide
        written = " ".join(str(ti.get(k, "")) for k in ("content", "new_string"))
        if any(re.search(p, written) for p in KEY_SHAPES):
            print(json.dumps({"hookSpecificOutput": {
                "hookEventName": "PreToolUse", "permissionDecision": "ask",
                "permissionDecisionReason": "keyleash: this writes something that looks like a credential into "
                                            "a file. Store it with `keyleash add NAME` instead."}}))
        return 0

    if event == "UserPromptSubmit":
        prompt = data.get("prompt") or data.get("user_prompt") or ""
        if any(re.search(p, prompt) for p in KEY_SHAPES):
            print("keyleash: the user's message appears to contain a credential. Do not repeat it or write it "
                  "to any file. Suggest storing it with `keyleash add NAME` (a popup, so it stays out of the "
                  "conversation) and rotating it if it is a real key, since it is now in this transcript.")
        return 0

    if event == "SessionEnd":
        sid = data.get("session_id") or ""
        if sid:
            subprocess.run([KEYLEASH, "session-end", sid], capture_output=True, timeout=10)
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
