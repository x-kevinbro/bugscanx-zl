"""Output-file safety helpers.

Every place that writes results asks these helpers first, so a typo in an
output filename can no longer truncate an existing file or the input list.
"""

import os


def same_file(a, b):
    """True if two paths point at the same file (symlinks / ./ resolved)."""
    if not a or not b:
        return False
    try:
        if os.path.exists(a) and os.path.exists(b):
            return os.path.samefile(a, b)
    except OSError:
        pass
    return os.path.realpath(os.path.abspath(a)) == os.path.realpath(os.path.abspath(b))


def check_output_path(output_file, input_files=()):
    """Return an error message if output_file must not be used, else None."""
    if not output_file or not str(output_file).strip():
        return "Output filename is required."
    for inp in input_files:
        if inp and same_file(output_file, inp):
            return (f"Output file '{output_file}' is the same as the input file - "
                    f"choose a different output filename.")
    if os.path.isdir(output_file):
        return f"'{output_file}' is a directory."
    return None


def resolve_output_mode(output_file, input_files=(), ask=None):
    """Decide how to open output_file.

    Returns 'w' (new file or confirmed overwrite), 'a' (append to existing)
    or None (cancelled / invalid). `ask(question, choices)` is injected so the
    logic is testable without a terminal; it defaults to an InquirerPy prompt.
    """
    error = check_output_path(output_file, input_files)
    if error:
        print(f" {error}")
        return None
    if not os.path.exists(output_file) or os.path.getsize(output_file) == 0:
        return 'w'

    if ask is None:
        from bugscanx.utils.prompts import get_input

        def ask(question, choices):
            return get_input(question, input_type="choice", choices=choices)

    choice = ask(f"'{output_file}' already exists", ["Append", "Overwrite", "Cancel"])
    return {'Append': 'a', 'Overwrite': 'w'}.get(choice)
