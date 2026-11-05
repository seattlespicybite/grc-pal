"""Two people editing at once never silently lose a save (B-044 / R-03, first slice: implementation notes)."""
from __future__ import annotations

import pytest

from grcpal.portal.service import Conflict
from test_portal import ADMIN, ADMIN2, as_, csrf, env  # noqa: F401 - env is a fixture


def test_a_save_from_an_old_page_is_refused_and_nothing_is_written(env):  # noqa: F811
    portal, _ = env
    portal.save_control_note(ADMIN, "IAM-02", "First text.", base_version=0)
    # ADMIN and ADMIN2 both open version 1; ADMIN2 saves first
    portal.save_control_note(ADMIN2, "IAM-02", "ADMIN2 added the quarterly review.", base_version=1)
    with pytest.raises(Conflict) as exc:
        portal.save_control_note(ADMIN, "IAM-02", "ADMIN's edit of version 1.", base_version=1)
    assert exc.value.current["version"] == 2 and exc.value.current["by"] == ADMIN2.email
    assert "saved a newer version (version 2)" in str(exc.value)
    assert [h["version"] for h in portal.control_note_history("IAM-02")] == [2, 1]
    assert sum(1 for r in portal.log.records() if r["action"] == "control.note") == 2  # refused save not audited
    assert portal.save_control_note(ADMIN, "IAM-02", "Merged text.", base_version=2)["version"] == 3


def test_two_saves_that_race_for_the_same_version_do_not_crash(env, monkeypatch):  # noqa: F811
    portal, _ = env
    portal.save_control_note(ADMIN, "IAM-02", "v1")
    real = portal.control_note
    monkeypatch.setattr(portal, "control_note", lambda cid: real(cid) if cid != "IAM-02" else
                        {"version": 0})  # this writer still thinks there is no note yet
    with pytest.raises(Conflict) as exc:
        portal.save_control_note(ADMIN2, "IAM-02", "v1 from someone else")
    assert exc.value.current["text"] == "v1"


def test_conflict_page_keeps_what_you_typed(env):  # noqa: F811
    portal, client = env
    portal.save_control_note(ADMIN, "IAM-02", "Old text.")
    as_(client, ADMIN2)
    token = csrf(client, "/controls/IAM-02")
    portal.save_control_note(ADMIN, "IAM-02", "Newer text <b>by admin</b>.")
    r = client.post("/controls/IAM-02/note", data={"csrf": token, "base_version": "1",
                                                   "text": "My careful edit <script>x</script>"})
    assert r.status_code == 409
    assert "Your notes were not saved" in r.text and "My careful edit &lt;script&gt;" in r.text
    assert "Newer text &lt;b&gt;by admin&lt;/b&gt;." in r.text and 'name="base_version" value="2"' in r.text
    r = client.post("/controls/IAM-02/note", data={"csrf": token, "base_version": "2", "text": "Merged."},
                    follow_redirects=False)
    assert r.status_code == 303 and portal.control_note("IAM-02")["text"] == "Merged."


def test_control_page_form_carries_the_version(env):  # noqa: F811
    portal, client = env
    portal.save_control_note(ADMIN, "IAM-02", "Text.")
    assert 'name="base_version" value="1"' in as_(client, ADMIN).get("/controls/IAM-02").text
