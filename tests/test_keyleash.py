#!/usr/bin/python3
"""Run with: /usr/bin/python3 -m unittest discover -s tests -v

Nothing here shows a popup. The keyring round trip uses a dummy value in the login keyring
and is skipped when no unlocked keyring is available.
"""
import base64, importlib.machinery, importlib.util, io, json, os, shutil, subprocess, sys, tempfile, time, unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
_runtime = tempfile.mkdtemp()
_loader = importlib.machinery.SourceFileLoader("keyleash", os.path.join(ROOT, "bin", "keyleash"))
kg = importlib.util.module_from_spec(importlib.util.spec_from_loader("keyleash", _loader))
sys.dont_write_bytecode = True
_loader.exec_module(kg)
REAL_RUNTIME = kg.RUNTIME
kg.RUNTIME, kg.GRANTS = _runtime, os.path.join(_runtime, "grants.json")  # never touch the real approvals

DUMMY = b"dummy-value-0123456789/+=&"


class Masking(unittest.TestCase):
    def test_plain_and_encoded_forms_are_masked(self):
        mask = kg.masker({"K": DUMMY})
        for form in (DUMMY, base64.b64encode(DUMMY), DUMMY.hex().encode(), b"dummy-value-0123456789%2F%2B%3D%26"):
            out = mask(b"Authorization: " + form + b"\n")
            self.assertEqual(out, b"Authorization: [secret:K]\n", form)

    def test_other_text_untouched_and_longest_first(self):
        mask = kg.masker({"A": b"abcdef123456", "B": b"abcdef"})
        self.assertEqual(mask(b"x abcdef123456 y abcdef z hello"), b"x [secret:A] y [secret:B] z hello")

    def test_each_line_of_a_multiline_value(self):
        mask = kg.masker({"PEM": b"-----BEGIN-----\nMIIabcdefgh\n-----END-----"})
        self.assertEqual(mask(b"got MIIabcdefgh here"), b"got [secret:PEM] here")

    def test_tiny_values_are_not_used_as_needles(self):
        self.assertEqual(kg.masker({"S": b"ab"})(b"about a cab"), b"about a cab")


class Grants(unittest.TestCase):
    def setUp(self):
        kg.save_grants({})

    def test_location_cannot_be_moved_by_the_caller(self):
        self.assertEqual(REAL_RUNTIME, f"/run/user/{os.getuid()}/keyleash")
        env = dict(os.environ, XDG_RUNTIME_DIR="/tmp/elsewhere")
        r = subprocess.run([sys.executable, "-B", "-c", "import importlib.machinery as m, importlib.util as u, sys;"
                            "l = m.SourceFileLoader('k', sys.argv[1]); k = u.module_from_spec(u.spec_from_loader('k', l));"
                            "l.exec_module(k); print(k.GRANTS)", os.path.join(ROOT, "bin", "keyleash")],
                           capture_output=True, text=True, env=env)
        self.assertEqual(r.stdout.strip(), REAL_RUNTIME + "/grants.json")

    def test_timed_grant_expires(self):
        now = time.time()
        kg.save_grants({"K": [{"until": now + 60}]})
        self.assertTrue(kg.granted("K", kg.load_grants(now), "s1", now))
        self.assertEqual(kg.load_grants(now + 61), {})
        self.assertFalse(kg.granted("K", kg.load_grants(now + 61), "s1", now + 61))

    def test_session_grant_only_for_that_session(self):
        kg.save_grants({"K": [{"session": "s1"}]})
        g = kg.load_grants()
        self.assertTrue(kg.granted("K", g, "s1"))
        self.assertFalse(kg.granted("K", g, "s2"))
        self.assertFalse(kg.granted("K", g, ""))
        self.assertFalse(kg.granted("OTHER", g, "s1"))

    def test_session_end_drops_only_that_session(self):
        kg.save_grants({"K": [{"session": "s1"}, {"session": "s2"}], "L": [{"session": "s1"}]})
        with mock.patch.object(kg, "lock_dedicated"):
            kg.cmd_session_end(["s1"])
        self.assertEqual(kg.load_grants(), {"K": [{"session": "s2"}]})

    def test_file_is_private(self):
        kg.save_grants({"K": [{"session": "s1"}]})
        self.assertEqual(os.stat(kg.GRANTS).st_mode & 0o777, 0o600)


class Run(unittest.TestCase):
    """cmd_run with the keyring and the popup replaced; the child process is real."""

    CHOICE = {kg.ONCE: "once", kg.SESSION: "any-session", kg.TIMED: "any-timed", kg.DENY: None}

    def run_it(self, argv, decision, session="s1", choice=None, keep=False):
        if not keep:
            kg.save_grants({})
        out, err = tempfile.TemporaryFile(), tempfile.TemporaryFile()
        asked = []

        def approve(names, cmd, minutes, default=None):
            asked.append(list(names))
            return decision, choice or self.CHOICE[decision]

        fake_out = mock.Mock(buffer=out)
        fake_err = mock.Mock(buffer=err, write=lambda s: None)
        with mock.patch.object(kg, "find", return_value=("login", None, object())), \
             mock.patch.object(kg, "lookup", return_value=DUMMY), \
             mock.patch.object(kg, "ask_approval", side_effect=approve), \
             mock.patch.object(kg, "session_id", return_value=session), \
             mock.patch.object(sys, "stdout", fake_out), mock.patch.object(sys, "stderr", fake_err):
            with self.assertRaises(SystemExit) as cm:
                kg.cmd_run(argv)
        out.seek(0), err.seek(0)
        result = cm.exception.code, out.read(), err.read(), asked
        out.close(), err.close()
        return result

    def test_value_reaches_the_command_and_is_masked(self):
        code, out, err, asked = self.run_it(["K", "--", "sh", "-c", 'echo "v=$K"; echo "e=$K" >&2; exit 3'], kg.ONCE)
        self.assertEqual((code, out, err), (3, b"v=[secret:K]\n", b"e=[secret:K]\n"))
        self.assertEqual(asked, [["K"]])
        self.assertEqual(kg.load_grants(), {})  # "once" leaves nothing behind

    def test_rename_variable(self):
        code, out, _, _ = self.run_it(["K=TOKEN", "--", "sh", "-c", 'echo "${#TOKEN} ${K:-unset}"'], kg.ONCE)
        self.assertEqual((code, out), (0, f"{len(DUMMY)} unset\n".encode()))

    def test_deny_runs_nothing(self):
        marker = os.path.join(_runtime, "ran")
        code, out, _, _ = self.run_it(["K", "--", "touch", marker], kg.DENY)
        self.assertEqual(code, 77)
        self.assertFalse(os.path.exists(marker))

    def test_session_grant_is_recorded_and_not_asked_again(self):
        self.run_it(["K", "--", "true"], kg.SESSION)
        self.assertEqual(kg.load_grants(), {"K": [{"session": "s1"}]})
        with mock.patch.object(kg, "find", return_value=("login", None, object())), \
             mock.patch.object(kg, "lookup", return_value=DUMMY), \
             mock.patch.object(kg, "session_id", return_value="s1"), \
             mock.patch.object(kg, "ask_approval", side_effect=AssertionError("asked again")):
            with self.assertRaises(SystemExit) as cm:
                kg.cmd_run(["K", "--", "true"])
        self.assertEqual(cm.exception.code, 0)

    def test_timed_grant_is_recorded(self):
        self.run_it(["K", "--", "true"], kg.TIMED)
        (g,) = kg.load_grants()["K"]
        self.assertAlmostEqual(g["until"], time.time() + 30 * 60, delta=5)

    def test_program_grant_covers_that_program_only(self):
        self.run_it(["K", "--", "true"], kg.SESSION, choice="prog-session")
        (g,) = kg.load_grants()["K"]
        self.assertEqual(g["scope"], {"prog": os.path.realpath(shutil.which("true"))})
        _, _, _, asked = self.run_it(["K", "--", "true"], kg.SESSION, choice="prog-session", keep=True)
        self.assertEqual(asked, [])                                   # same program: no popup
        _, _, _, asked = self.run_it(["K", "--", "echo", "x"], kg.ONCE, keep=True)
        self.assertEqual(asked, [["K"]])                              # another program: asked

    def test_a_lookalike_program_is_not_the_approved_one(self):
        self.run_it(["K", "--", "true"], kg.SESSION, choice="prog-session")
        fake = os.path.join(tempfile.mkdtemp(), "true")
        with open(fake, "w") as f:
            f.write("#!/bin/sh\nexit 0\n")
        os.chmod(fake, 0o755)
        _, _, _, asked = self.run_it(["K", "--", fake], kg.ONCE, keep=True)
        self.assertEqual(asked, [["K"]])

    def test_shells_get_exact_command_approvals(self):
        self.run_it(["K", "--", "sh", "-c", "true"], kg.SESSION, choice="prog-session")
        (g,) = kg.load_grants()["K"]
        self.assertEqual(g["scope"], {"cmd": ["sh", "-c", "true"]})
        _, _, _, asked = self.run_it(["K", "--", "sh", "-c", "true"], kg.ONCE, keep=True)
        self.assertEqual(asked, [])
        _, _, _, asked = self.run_it(["K", "--", "sh", "-c", 'printf %s "$K" | rev'], kg.ONCE, keep=True)
        self.assertEqual(asked, [["K"]])

    def test_any_command_grant_still_available(self):
        self.run_it(["K", "--", "true"], kg.TIMED, choice="any-timed")
        _, _, _, asked = self.run_it(["K", "--", "sh", "-c", "true"], kg.ONCE, keep=True)
        self.assertEqual(asked, [])


class Popup(unittest.TestCase):
    def test_long_commands_show_start_and_end(self):
        shown, warning = kg.shorten("a" * 500 + "MIDDLE" + "b" * 300)
        self.assertTrue(shown.startswith("a" * 450) and shown.endswith("b" * 200))
        self.assertIn("characters not shown", shown)
        self.assertIn("too long", warning)
        self.assertEqual(kg.shorten("curl x"), ("curl x", ""))

    def zenity_args(self, cmd, sid="s1", default="prog-session"):
        seen = {}

        def fake(*args, **kw):
            seen["args"] = args
            return 0, "prog-session"
        with mock.patch.object(kg, "zenity", side_effect=fake), mock.patch.object(kg, "session_id", return_value=sid):
            result = kg.ask_approval(["K"], cmd, 30, default)
        return result, seen["args"]

    def test_one_list_one_row_of_buttons(self):
        (kind, choice), args = self.zenity_args(["curl", "https://example.com"])
        self.assertEqual((kind, choice), (kg.SESSION, "prog-session"))
        self.assertIn("Allow curl commands this session", args)
        self.assertNotIn("--extra-button", " ".join(args))
        self.assertEqual(args[args.index("Allow curl commands this session") - 1], "TRUE")  # the default

    def test_shell_rows_say_exact_command_and_no_session_rows_outside_agents(self):
        _, args = self.zenity_args(["sh", "-c", "true"], sid="")
        self.assertIn("Allow this exact command for 30 min", args)
        self.assertFalse(any(isinstance(a, str) and a.endswith("this session") for a in args))

    def test_anything_but_allow_is_deny(self):
        with mock.patch.object(kg, "zenity", return_value=(1, "")), mock.patch.object(kg, "session_id", return_value="s"):
            self.assertEqual(kg.ask_approval(["K"], ["true"], 30)[0], kg.DENY)
        with mock.patch.object(kg, "zenity", return_value=(0, "made-up")), mock.patch.object(kg, "session_id", return_value="s"):
            self.assertEqual(kg.ask_approval(["K"], ["true"], 30)[0], kg.DENY)


class Guard(unittest.TestCase):
    def hook(self, payload):
        # an empty settings folder, so the developer's own "hooks off" choices never change the result
        env = dict(os.environ, XDG_CONFIG_HOME=tempfile.mkdtemp())
        return subprocess.run([sys.executable, os.path.join(ROOT, "hooks", "guard.py")], input=json.dumps(payload),
                              capture_output=True, text=True, env=env)

    def test_blocks_going_around(self):
        for cmd in ("cat /run/user/1000/keyleash/grants.json", "secret-tool lookup application keyleash",
                    "python3 -c 'import secretstorage'", "busctl --user call org.freedesktop.secrets /x",
                    ):
            r = self.hook({"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": cmd}})
            self.assertEqual(r.returncode, 2, cmd)
        r = self.hook({"hook_event_name": "PreToolUse", "tool_name": "Write",
                       "tool_input": {"file_path": "/run/user/1000/keyleash/grants.json", "content": "{}"}})
        self.assertEqual(r.returncode, 2)

    def test_asks_before_desktop_automation(self):
        for cmd in ("python3 -c 'from gi.repository import Atspi'", "xdotool key Return", "which ydotool"):
            r = self.hook({"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": cmd}})
            self.assertEqual(r.returncode, 0, cmd)
            self.assertEqual(json.loads(r.stdout)["hookSpecificOutput"]["permissionDecision"], "ask", cmd)

    def test_asks_before_writing_a_credential_into_a_file(self):
        r = self.hook({"hook_event_name": "PreToolUse", "tool_name": "Write",
                       "tool_input": {"file_path": "/tmp/.env", "content": "KEY=sk-" + "a1B2" * 8}})
        self.assertEqual(r.returncode, 0)
        self.assertEqual(json.loads(r.stdout)["hookSpecificOutput"]["permissionDecision"], "ask")
        r = self.hook({"hook_event_name": "PreToolUse", "tool_name": "Write",
                       "tool_input": {"file_path": "/tmp/a.txt", "content": "nothing secret here"}})
        self.assertEqual((r.returncode, r.stdout), (0, ""))

    def test_can_be_switched_off_per_project(self):
        home = tempfile.mkdtemp()
        proj = os.path.join(home, "proj")
        os.makedirs(os.path.join(home, "keyleash")), os.makedirs(os.path.join(proj, "sub"))
        with open(os.path.join(home, "keyleash", "config.json"), "w") as f:
            json.dump({"hooks_off": [os.path.realpath(proj)]}, f)
        env = dict(os.environ, XDG_CONFIG_HOME=home)

        def hook(cwd):
            return subprocess.run([sys.executable, os.path.join(ROOT, "hooks", "guard.py")], capture_output=True,
                                  text=True, env=env, input=json.dumps({
                                      "hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": cwd,
                                      "tool_input": {"command": "secret-tool lookup a b"}})).returncode
        self.assertEqual(hook(os.path.join(proj, "sub")), 0)   # inside the project: guard is silent
        self.assertEqual(hook(home), 2)                        # anywhere else: still blocked
        self.assertEqual(hook(proj + "-other"), 2)             # a sibling with the same prefix is not the project

    def test_agent_cannot_edit_the_settings_file(self):
        r = self.hook({"hook_event_name": "PreToolUse", "tool_name": "Edit",
                       "tool_input": {"file_path": "/home/u/.config/keyleash/config.json", "new_string": "x"}})
        self.assertEqual(r.returncode, 2)

    def test_allows_normal_use(self):
        for cmd in ("keyleash run K -- curl https://example.com", "keyleash list", "ls -la", "git status",
                    "sudo apt install python3-secretstorage"):
            r = self.hook({"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": cmd}})
            self.assertEqual(r.returncode, 0, cmd)

    def test_holds_back_a_pasted_credential(self):
        r = self.hook({"hook_event_name": "UserPromptSubmit", "prompt": "use sk-" + "a1B2" * 8 + " for the call"})
        self.assertEqual(json.loads(r.stdout)["decision"], "block")
        r = self.hook({"hook_event_name": "UserPromptSubmit", "prompt": "what does the sk- prefix mean?"})
        self.assertEqual(r.stdout, "")

    def test_blocks_reading_a_running_commands_environment_and_side_routes(self):
        for cmd in ("cat /proc/4242/environ", "tr '\\0' '\\n' < /proc/$(pgrep node)/environ", "ps eww",
                    "ps auxe | grep node", "cd /run/user/1000/keyleash && cat *", "ls $XDG_RUNTIME_DIR/keyleash",
                    "cat ~/.config/keyleash/x", "find / -name grants.json"):
            r = self.hook({"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": cmd}})
            self.assertEqual(r.returncode, 2, cmd)
        for cmd in ("ps -ef", "ps aux | grep node", "cd ~/development/keyleash && git status",
                    "keyleash run K -- node build.js --config config.json"):
            r = self.hook({"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": cmd}})
            self.assertEqual(r.returncode, 0, cmd)

    def test_multiedit_and_notebook_writes_are_checked(self):
        r = self.hook({"hook_event_name": "PreToolUse", "tool_name": "MultiEdit",
                       "tool_input": {"file_path": "/tmp/a.py", "edits": [{"new_string": "k='sk-" + "a1B2" * 8 + "'"}]}})
        self.assertEqual(json.loads(r.stdout)["hookSpecificOutput"]["permissionDecision"], "ask")
        r = self.hook({"hook_event_name": "PreToolUse", "tool_name": "NotebookEdit",
                       "tool_input": {"notebook_path": "/run/user/1000/keyleash/grants.json", "new_source": "{}"}})
        self.assertEqual(r.returncode, 2)


class Keyring(unittest.TestCase):
    NAME = "KEYLEASH_SELFTEST"

    def test_round_trip_in_login_keyring(self):
        try:
            col = kg.collections()["login"]
        except BaseException as e:  # no Secret Service on this machine
            self.skipTest(str(e))
        if col.is_locked():
            self.skipTest("login keyring is locked")
        try:
            kg.store(self.NAME, DUMMY.decode(), where="login")
            self.assertEqual(kg.find(self.NAME)[0], "login")
            self.assertEqual(kg.lookup(self.NAME), DUMMY)
        finally:
            for item in col.search_items({"application": kg.APP, "name": self.NAME}):
                item.delete()
        self.assertIsNone(kg.find(self.NAME)[2])


if __name__ == "__main__":
    unittest.main()
