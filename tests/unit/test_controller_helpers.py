from src.gdb_controller import _update_state, _clean_responses, _hexdump, GdbState


def test_update_state_stopped():
    responses = [{"type": "notify", "message": "stopped"}]
    assert _update_state(responses, GdbState.RUNNING) == GdbState.STOPPED


def test_update_state_running():
    responses = [{"type": "notify", "message": "running"}]
    assert _update_state(responses, GdbState.STOPPED) == GdbState.RUNNING


def test_update_state_thread_selected():
    responses = [{"type": "notify", "message": "thread-selected"}]
    assert _update_state(responses, GdbState.RUNNING) == GdbState.STOPPED


def test_update_state_thread_group_exited():
    responses = [{"type": "notify", "message": "thread-group-exited"}]
    assert _update_state(responses, GdbState.RUNNING) == GdbState.STOPPED


def test_update_state_ignores_non_notify():
    responses = [{"type": "console", "message": "stopped"}]
    assert _update_state(responses, GdbState.DEAD) == GdbState.DEAD


def test_update_state_no_responses():
    assert _update_state([], GdbState.STOPPED) == GdbState.STOPPED


def test_clean_responses_removes_noise():
    responses = [
        {"type": "notify", "message": "cmd-param-changed", "payload": ""},
        {"type": "console", "message": "", "payload": "keep this"},
    ]
    cleaned = _clean_responses(responses)
    assert len(cleaned) == 1
    assert cleaned[0]["payload"] == "keep this"


def test_clean_responses_removes_library_loaded():
    responses = [
        {"type": "notify", "message": "library-loaded", "payload": "libfoo"},
        {"type": "console", "message": "", "payload": "output"},
    ]
    cleaned = _clean_responses(responses)
    assert len(cleaned) == 1


def test_clean_responses_strips_ansi():
    responses = [{"type": "console", "message": "", "payload": "\x1b[31mred\x1b[0m"}]
    cleaned = _clean_responses(responses)
    assert cleaned[0]["payload"] == "red"


def test_clean_responses_preserves_non_string_payload():
    responses = [{"type": "result", "message": "", "payload": {"key": "val"}}]
    cleaned = _clean_responses(responses)
    assert cleaned[0]["payload"] == {"key": "val"}


def test_hexdump_basic():
    data = b"ABCD"
    result = _hexdump(data)
    assert "41 42 43 44" in result
    assert "ABCD" in result


def test_hexdump_non_printable():
    data = bytes([0, 1, 2, 3])
    result = _hexdump(data)
    assert "00 01 02 03" in result
    assert "...." in result


def test_hexdump_empty():
    assert _hexdump(b"") == ""
