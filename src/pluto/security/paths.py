"""Filesystem sandbox.

Every path the agent touches passes through :class:`PathGuard`. The guard is
deliberately paranoid: it resolves symlinks, rejects traversal, enforces an
allow-list of roots, blocks known-sensitive system locations, and refuses to
create executables without a critical-level approval.

Design note — why ``os.path.realpath`` and not ``Path.resolve``:
both are used. ``resolve()`` normalises and follows links for existing paths;
for a path that does not exist yet we resolve the nearest existing ancestor and
re-join, so that ``C:/allowed/../../etc/passwd`` is caught even though the
target file is absent.
"""

from __future__ import annotations

import os
import re
import unicodedata
from collections.abc import Iterable, Sequence
from pathlib import Path, PurePath

from pluto.core.constants import EXECUTABLE_EXTENSIONS, FORBIDDEN_PATH_FRAGMENTS
from pluto.core.exceptions import PathTraversalError

#: Characters Windows forbids in a filename, plus control characters.
_ILLEGAL_NAME_CHARS = re.compile(r'[<>:"/\\|?*\x00-\x1f]')

#: Reserved device names on Windows. A file called "CON.txt" is still CON.
_WINDOWS_RESERVED = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{i}" for i in range(1, 10)}
    | {f"LPT{i}" for i in range(1, 10)}
)

#: Alternate Data Stream marker — "file.txt:hidden" writes a hidden stream.
_ADS_PATTERN = re.compile(r"^[A-Za-z]:$")


def _normalise_for_comparison(path: Path) -> str:
    """Lower-cased, separator-normalised string used for blocklist matching."""
    text = str(path)
    # Compare using both separators so a Windows blocklist entry still matches
    # when the test suite runs on Linux and vice versa.
    text = text.replace("\\", "/").lower()
    return text


def _contains_forbidden_fragment(path: Path) -> str | None:
    """Return the matching forbidden fragment, or None."""
    haystack = _normalise_for_comparison(path)
    for fragment in FORBIDDEN_PATH_FRAGMENTS:
        needle = fragment.replace("\\", "/").lower()
        if needle in haystack:
            return fragment
    return None


def resolve_strict(candidate: str | os.PathLike[str]) -> Path:
    """Fully resolve *candidate*, even if it does not exist yet.

    Walks up to the nearest existing ancestor, resolves that (following
    symlinks), then re-appends the remaining components. This defeats
    ``a/../../b`` traversal against not-yet-created files, which a naive
    ``Path(x).absolute()`` would miss.
    """
    raw = Path(candidate).expanduser()

    # Reject NUL bytes outright — they truncate paths in C APIs.
    if "\x00" in str(raw):
        raise PathTraversalError(
            "Path contains a NUL byte",
            user_message="That filename is not valid.",
        )

    if raw.exists() or raw.is_symlink():
        return Path(os.path.realpath(raw))

    # Find the deepest ancestor that exists.
    existing = raw
    tail: list[str] = []
    while not existing.exists():
        parent = existing.parent
        if parent == existing:  # reached the root
            break
        tail.append(existing.name)
        existing = parent

    base = Path(os.path.realpath(existing)) if existing.exists() else existing
    for part in reversed(tail):
        base = base / part
    # Normalise any residual "..": os.path.normpath is purely lexical, which is
    # exactly what we want now that the real part is already link-resolved.
    return Path(os.path.normpath(base))


def is_within(child: Path, parent: Path) -> bool:
    """True if *child* is *parent* or lives underneath it."""
    try:
        child.relative_to(parent)
    except ValueError:
        return False
    return True


def sanitise_filename(name: str, *, fallback: str = "untitled") -> str:
    """Make *name* safe to use as a single path component.

    Strips directory separators, control characters, Windows-illegal
    characters, trailing dots and spaces, and avoids reserved device names.
    """
    cleaned = unicodedata.normalize("NFKC", name).strip()
    cleaned = _ILLEGAL_NAME_CHARS.sub("_", cleaned)
    # Windows silently strips trailing dots/spaces, which can be used to
    # sidestep an extension check.
    cleaned = cleaned.rstrip(". ")
    if not cleaned:
        return fallback

    stem = cleaned.split(".")[0].upper()
    if stem in _WINDOWS_RESERVED:
        cleaned = f"_{cleaned}"

    # Keep well under MAX_PATH pressure.
    if len(cleaned) > 180:
        suffix = Path(cleaned).suffix[:20]
        cleaned = cleaned[: 180 - len(suffix)] + suffix
    return cleaned


class PathGuard:
    """Enforces the filesystem sandbox.

    Parameters
    ----------
    allowed_roots:
        Folders the agent may read and write inside. Empty means *nothing* is
        allowed, which is the safe default for a fresh install.
    read_only_roots:
        Folders the agent may read but never modify.
    """

    def __init__(
        self,
        allowed_roots: Iterable[str | os.PathLike[str]] = (),
        read_only_roots: Iterable[str | os.PathLike[str]] = (),
    ) -> None:
        self._allowed: list[Path] = []
        self._read_only: list[Path] = []
        for root in allowed_roots:
            self.add_root(root)
        for root in read_only_roots:
            self.add_root(root, read_only=True)

    # -- configuration ----------------------------------------------------
    @property
    def allowed_roots(self) -> tuple[Path, ...]:
        return tuple(self._allowed)

    @property
    def read_only_roots(self) -> tuple[Path, ...]:
        return tuple(self._read_only)

    def add_root(
        self, root: str | os.PathLike[str], *, read_only: bool = False
    ) -> Path:
        """Register a sandbox root. Refuses obviously dangerous roots."""
        resolved = resolve_strict(root)

        fragment = _contains_forbidden_fragment(resolved)
        if fragment is not None:
            raise PathTraversalError(
                f"Refusing to sandbox a protected location: {fragment}",
                user_message=(
                    "That folder is a protected system location and cannot be "
                    "granted to Pluto."
                ),
            )

        # Granting a filesystem root would make the sandbox meaningless.
        if resolved.parent == resolved:
            raise PathTraversalError(
                f"Refusing to grant a filesystem root: {resolved}",
                user_message=(
                    "Pluto will not take a whole drive as a workspace. "
                    "Pick a specific folder."
                ),
            )

        target = self._read_only if read_only else self._allowed
        if resolved not in target:
            target.append(resolved)
        return resolved

    def remove_root(self, root: str | os.PathLike[str]) -> bool:
        """Revoke a root. Returns True if something was removed."""
        resolved = resolve_strict(root)
        removed = False
        for collection in (self._allowed, self._read_only):
            if resolved in collection:
                collection.remove(resolved)
                removed = True
        return removed

    def clear(self) -> None:
        self._allowed.clear()
        self._read_only.clear()

    # -- enforcement ------------------------------------------------------
    def validate(
        self,
        candidate: str | os.PathLike[str],
        *,
        for_write: bool = False,
        allow_executable: bool = False,
    ) -> Path:
        """Resolve and authorise *candidate*.

        Returns the fully resolved path on success.

        Raises
        ------
        PathTraversalError
            If the path escapes the sandbox, hits a protected location, or
            would create an executable without permission.
        """
        resolved = resolve_strict(candidate)

        fragment = _contains_forbidden_fragment(resolved)
        if fragment is not None:
            raise PathTraversalError(
                f"Path hits protected location ({fragment}): {resolved}",
                user_message="That location is protected and Pluto will not touch it.",
                detail=str(resolved),
            )

        if not self._allowed and not self._read_only:
            raise PathTraversalError(
                "No sandbox roots configured",
                user_message=(
                    "Pluto has no approved folders yet. Add one under "
                    "Settings → Permissions before asking for file work."
                ),
            )

        writable = any(is_within(resolved, root) for root in self._allowed)
        readable = writable or any(
            is_within(resolved, root) for root in self._read_only
        )

        if not readable:
            raise PathTraversalError(
                f"Path outside sandbox: {resolved}",
                user_message=(
                    "That location is outside the folders Pluto is allowed to use."
                ),
                detail=str(resolved),
            )

        if for_write and not writable:
            raise PathTraversalError(
                f"Write attempted on read-only root: {resolved}",
                user_message="Pluto may read that folder but not change it.",
                detail=str(resolved),
            )

        if for_write and not allow_executable:
            suffix = resolved.suffix.lower()
            if suffix in EXECUTABLE_EXTENSIONS:
                raise PathTraversalError(
                    f"Refusing to write executable file type: {suffix}",
                    user_message=(
                        f"Pluto will not create {suffix} files — they can run code."
                    ),
                )

        # Alternate Data Streams: "notes.txt:payload" hides content on NTFS.
        # A drive letter like "C:" is legitimate, so only flag colons that
        # appear in the final component.
        name = resolved.name
        if ":" in name and not _ADS_PATTERN.match(name):
            raise PathTraversalError(
                f"Alternate data stream syntax rejected: {name}",
                user_message="That filename is not allowed.",
            )

        return resolved

    def validate_many(
        self,
        candidates: Sequence[str | os.PathLike[str]],
        *,
        for_write: bool = False,
    ) -> list[Path]:
        """Validate a batch, failing on the first bad path."""
        return [self.validate(c, for_write=for_write) for c in candidates]

    def is_allowed(
        self, candidate: str | os.PathLike[str], *, for_write: bool = False
    ) -> bool:
        """Non-raising variant of :meth:`validate`."""
        try:
            self.validate(candidate, for_write=for_write)
        except PathTraversalError:
            return False
        return True

    def describe(self) -> dict[str, list[str]]:
        """Human-readable summary for the permissions dashboard."""
        return {
            "writable": [str(p) for p in self._allowed],
            "read_only": [str(p) for p in self._read_only],
        }

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return (
            f"PathGuard(writable={len(self._allowed)}, "
            f"read_only={len(self._read_only)})"
        )


def relative_display(path: PurePath, roots: Sequence[Path]) -> str:
    """Render *path* relative to its sandbox root, for log messages.

    Keeps absolute user paths out of logs where a relative one will do.
    """
    for root in roots:
        try:
            return str(Path(path).relative_to(root))
        except ValueError:
            continue
    return Path(path).name
