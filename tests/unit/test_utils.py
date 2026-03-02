from src.utils import strip_ansi, format_responses, format_console_output, format_error


def test_strip_ansi_removes_color_codes():
    assert strip_ansi("\x1b[31mred\x1b[0m") == "red"


def test_strip_ansi_passthrough_clean():
    assert strip_ansi("clean text") == "clean text"


def test_strip_ansi_complex_sequences():
    assert strip_ansi("\x1b[1;32;40mbold green\x1b[0m") == "bold green"


def test_format_responses_console():
    responses = [{"type": "console", "payload": "hello\n"}]
    assert "hello" in format_responses(responses)


def test_format_responses_result_dict():
    responses = [{"type": "result", "payload": {"key": "val"}}]
    result = format_responses(responses)
    assert "key" in result


def test_format_responses_skips_none_payload():
    responses = [{"type": "console", "payload": None}]
    assert format_responses(responses) == ""


def test_format_responses_multiple():
    responses = [
        {"type": "console", "payload": "line1"},
        {"type": "console", "payload": "line2"},
    ]
    result = format_responses(responses)
    assert "line1" in result
    assert "line2" in result


def test_format_console_output_console_and_log():
    responses = [
        {"type": "console", "payload": "console line"},
        {"type": "log", "payload": "log line"},
        {"type": "result", "payload": "hidden"},
    ]
    result = format_console_output(responses)
    assert "console line" in result
    assert "log line" in result
    assert "hidden" not in result


def test_format_error():
    result = format_error(ValueError("bad"))
    assert "ValueError" in result
    assert "bad" in result
