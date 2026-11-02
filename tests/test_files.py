import os

from bugscanx.utils.files import check_output_path, resolve_output_mode, same_file


def test_same_file(tmp_path):
    f = tmp_path / "a.txt"
    f.write_text("x")
    assert same_file(str(f), str(tmp_path / "." / "a.txt"))
    assert not same_file(str(f), str(tmp_path / "b.txt"))
    assert not same_file(str(f), None)


def test_output_equal_to_input_rejected(tmp_path):
    f = tmp_path / "hosts.txt"
    f.write_text("a.com\n")
    assert check_output_path(str(f), [str(f)]) is not None
    assert resolve_output_mode(str(f), [str(f)], ask=lambda *a: "Overwrite") is None
    assert f.read_text() == "a.com\n"


def test_new_file_is_write_mode(tmp_path):
    assert resolve_output_mode(str(tmp_path / "new.txt"), ask=lambda *a: 1 / 0) == "w"


def test_existing_file_prompts(tmp_path):
    f = tmp_path / "out.txt"
    f.write_text("keep me\n")
    assert resolve_output_mode(str(f), ask=lambda *a: "Append") == "a"
    assert resolve_output_mode(str(f), ask=lambda *a: "Overwrite") == "w"
    assert resolve_output_mode(str(f), ask=lambda *a: "Cancel") is None
    assert f.read_text() == "keep me\n"


def test_directory_rejected(tmp_path):
    assert check_output_path(str(tmp_path)) is not None
