"""Putting real values back, on this machine.

A port of the Secure AI service's own restore (cloudflare-worker/restoreCore.ts).
It answers every case in sdk/restore-cases.json the same way the service and
the TypeScript SDK do; the tests hold the three together.

The map runs stand-in -> real value, as ``redact`` returns it. Nothing here
makes a request: the map never leaves the process.
"""

from __future__ import annotations

import re

__all__ = ["restore", "restore_text", "half_names", "lookalikes", "case_forms"]

_DASHES = re.compile("[‐-―−﹘﹣－]")
_SPACES = re.compile("[   ]")
_LETTER = r"[^\W\d_]"
_WORD = re.compile(rf"^(?:{_LETTER}|['-])+$")


def lookalikes(s: str) -> str:
    """Look-alike dashes as "-" and no-break spaces as " ", one for one."""
    return _SPACES.sub(" ", _DASHES.sub("-", s))


def _same_case(like: str, to: str) -> str:
    if like == like.lower() and like != like.upper():
        return to.lower()
    if like == like.upper() and like != like.lower():
        return to.upper()
    return to


def case_forms(entries: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """Each stand-in with its all-small and all-capital forms."""
    out: list[tuple[str, str]] = []
    have: set[str] = set()

    def put(fake: str, real: str) -> None:
        if fake in have:
            return
        have.add(fake)
        out.append((fake, real))

    for fake, real in entries:
        put(fake, real)
    for fake, real in entries:
        put(fake.lower(), _same_case(fake.lower(), real))
        put(fake.upper(), _same_case(fake.upper(), real))
    return out


def restore_text(text: str, entries: list[tuple[str, str]]) -> str:
    """Every stand-in back to its real value, in one pass, longest first."""
    ordered = sorted(
        ((lookalikes(fake), real) for fake, real in case_forms(entries) if fake),
        key=lambda e: -len(e[0]),
    )
    if not ordered:
        return text
    seen = lookalikes(text)
    by_first: dict[str, list[tuple[str, str]]] = {}
    for entry in ordered:
        by_first.setdefault(entry[0][0], []).append(entry)

    out: list[str] = []
    i = 0
    plain = 0
    while i < len(text):
        hit = None
        for entry in by_first.get(seen[i], ()):
            if seen.startswith(entry[0], i):
                hit = entry
                break
        if hit:
            out.append(text[plain:i])
            out.append(hit[1])
            i += len(hit[0])
            plain = i
        else:
            i += 1
    if plain == 0:
        return text
    out.append(text[plain:])
    return "".join(out)


def half_names(mapping: dict[str, str]) -> list[tuple[str, str]]:
    """Half a two-word stand-in name, and the half of the real name it stands for."""
    real_words = {w for r in mapping.values() for w in r.lower().split()}
    pairs: dict[str, str | None] = {}
    for stand_in, real in mapping.items():
        a = stand_in.strip().split()
        b = real.strip().split()
        if len(a) != 2 or len(b) != 2 or not all(_WORD.match(w) for w in a + b):
            continue
        for i in (0, 1):
            if a[i] == b[i] or a[i].lower() in real_words:
                continue
            before = pairs.get(a[i], ...)
            pairs[a[i]] = b[i] if before is ... or before == b[i] else None
    return [(k, v) for k, v in pairs.items() if v is not None]


def restore(text: str, mapping: dict[str, str]) -> str:
    """Put the real values back: whole stand-ins, then halves of stand-in names."""
    out = restore_text(text, list(mapping.items()))
    for src, dst in half_names(mapping):
        out = re.sub(rf"(?<!{_LETTER}){re.escape(src)}(?!{_LETTER})", lambda _m, d=dst: d, out)
    return out
