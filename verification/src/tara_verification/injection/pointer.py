"""Internal JSON pointers. They may contain list indices and never go into a location."""

from __future__ import annotations

from typing import Any

Pointer = tuple  # of str (dict key) and int (list index)


def get_at(doc: Any, pointer: Pointer) -> Any:
    for step in pointer:
        doc = doc[step]
    return doc


def set_at(doc: Any, pointer: Pointer, value: Any) -> None:
    if not pointer:
        raise ValueError("cannot replace the document root")
    get_at(doc, pointer[:-1])[pointer[-1]] = value


def to_rfc6901(pointer: Pointer) -> str:
    return "".join("/" + str(s).replace("~", "~0").replace("/", "~1") for s in pointer)


def from_rfc6901(text: str, doc: Any) -> Pointer:
    """Parse an RFC 6901 pointer; doc decides whether a step is a list index."""
    if text == "":
        return ()
    if not text.startswith("/"):
        raise ValueError(f"not an RFC 6901 pointer: {text!r}")
    out = []
    for raw in text[1:].split("/"):
        step = raw.replace("~1", "/").replace("~0", "~")
        key: Any = int(step) if isinstance(doc, list) else step
        out.append(key)
        doc = doc[key]
    return tuple(out)
