"""Tests for the filesystem sandbox.

These are the highest-value tests in the suite: a hole here undermines every
other control, so the cases are deliberately adversarial.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from pluto.core.exceptions import PathTraversalError
from pluto.security.paths import (
    PathGuard,
    is_within,
    relative_display,
    resolve_strict,
    sanitise_filename,
)


@pytest.fixture()
def workspace(tmp_path: Path) -> Path:
    ws = tmp_path / "workspace"
    (ws / "sub" / "deep").mkdir(parents=True)
    (ws / "notes.txt").write_text("hello", encoding="utf-8")
    (ws / "sub" / "data.csv").write_text("a,b\n1,2\n", encoding="utf-8")
    return ws


@pytest.fixture()
def readonly_dir(tmp_path: Path) -> Path:
    ro = tmp_path / "reference"
    ro.mkdir()
    (ro / "manual.txt").write_text("read me", encoding="utf-8")
    return ro


@pytest.fixture()
def guard(workspace: Path, readonly_dir: Path) -> PathGuard:
    return PathGuard(allowed_roots=[workspace], read_only_roots=[readonly_dir])


# --------------------------------------------------------------------------
# Happy path
# --------------------------------------------------------------------------
class TestAllowedAccess:
    def test_file_inside_root_is_allowed(self, guard: PathGuard, workspace: Path):
        assert guard.validate(workspace / "notes.txt") == workspace / "notes.txt"

    def test_nested_file_is_allowed(self, guard: PathGuard, workspace: Path):
        result = guard.validate(workspace / "sub" / "deep" / "new.txt", for_write=True)
        assert is_within(result, workspace)

    def test_nonexistent_file_in_root_is_allowed_for_write(
        self, guard: PathGuard, workspace: Path
    ):
        target = workspace / "does-not-exist-yet.md"
        assert guard.validate(target, for_write=True) == target

    def test_read_only_root_readable(self, guard: PathGuard, readonly_dir: Path):
        assert guard.validate(readonly_dir / "manual.txt") == readonly_dir / "manual.txt"

    def test_is_allowed_returns_bool_not_raise(self, guard: PathGuard, tmp_path: Path):
        assert guard.is_allowed(tmp_path / "workspace" / "notes.txt") is True
        assert guard.is_allowed("/etc/hosts") is False


# --------------------------------------------------------------------------
# Traversal
# --------------------------------------------------------------------------
class TestTraversalRejected:
    def test_parent_escape_rejected(self, guard: PathGuard, workspace: Path):
        with pytest.raises(PathTraversalError):
            guard.validate(workspace / ".." / "outside.txt")

    def test_deep_parent_escape_rejected(self, guard: PathGuard, workspace: Path):
        with pytest.raises(PathTraversalError):
            guard.validate(workspace / "sub" / ".." / ".." / ".." / "etc" / "passwd")

    def test_traversal_on_nonexistent_target_rejected(
        self, guard: PathGuard, workspace: Path
    ):
        """The important case: the file does not exist, so a naive
        implementation would skip resolution and let it through."""
        sneaky = str(workspace / "sub" / ".." / ".." / "escaped" / "new.txt")
        with pytest.raises(PathTraversalError):
            guard.validate(sneaky, for_write=True)

    def test_absolute_outside_path_rejected(self, guard: PathGuard, tmp_path: Path):
        with pytest.raises(PathTraversalError):
            guard.validate(tmp_path / "elsewhere.txt")

    def test_sibling_prefix_not_treated_as_inside(self, guard: PathGuard, tmp_path: Path):
        """`/tmp/x/workspace-evil` must not pass because it starts with
        `/tmp/x/workspace`."""
        evil = tmp_path / "workspace-evil"
        evil.mkdir()
        with pytest.raises(PathTraversalError):
            guard.validate(evil / "file.txt")

    def test_nul_byte_rejected(self, guard: PathGuard, workspace: Path):
        with pytest.raises(PathTraversalError):
            guard.validate(f"{workspace}/evil\x00.txt")

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlink semantics")
    def test_symlink_escape_rejected(self, guard: PathGuard, workspace: Path, tmp_path: Path):
        secret = tmp_path / "secret.txt"
        secret.write_text("classified", encoding="utf-8")
        link = workspace / "innocent.txt"
        link.symlink_to(secret)
        with pytest.raises(PathTraversalError):
            guard.validate(link)

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlink semantics")
    def test_symlinked_directory_escape_rejected(
        self, guard: PathGuard, workspace: Path, tmp_path: Path
    ):
        outside = tmp_path / "outside_dir"
        outside.mkdir()
        (workspace / "shortcut").symlink_to(outside, target_is_directory=True)
        with pytest.raises(PathTraversalError):
            guard.validate(workspace / "shortcut" / "loot.txt", for_write=True)


# --------------------------------------------------------------------------
# Write restrictions
# --------------------------------------------------------------------------
class TestWriteRestrictions:
    def test_write_to_read_only_root_rejected(self, guard: PathGuard, readonly_dir: Path):
        with pytest.raises(PathTraversalError):
            guard.validate(readonly_dir / "manual.txt", for_write=True)

    @pytest.mark.parametrize("ext", [".exe", ".bat", ".ps1", ".dll", ".vbs", ".sh", ".reg"])
    def test_executable_write_rejected(self, guard: PathGuard, workspace: Path, ext: str):
        with pytest.raises(PathTraversalError):
            guard.validate(workspace / f"payload{ext}", for_write=True)

    def test_executable_write_allowed_with_explicit_flag(
        self, guard: PathGuard, workspace: Path
    ):
        result = guard.validate(
            workspace / "installer.exe", for_write=True, allow_executable=True
        )
        assert result.name == "installer.exe"

    def test_executable_extension_case_insensitive(self, guard: PathGuard, workspace: Path):
        with pytest.raises(PathTraversalError):
            guard.validate(workspace / "Payload.EXE", for_write=True)

    def test_reading_an_executable_is_fine(self, guard: PathGuard, workspace: Path):
        target = workspace / "existing.exe"
        target.write_bytes(b"MZ")
        assert guard.validate(target) == target

    def test_alternate_data_stream_rejected(self, guard: PathGuard, workspace: Path):
        with pytest.raises(PathTraversalError):
            guard.validate(f"{workspace}/notes.txt:hidden", for_write=True)


# --------------------------------------------------------------------------
# Protected locations
# --------------------------------------------------------------------------
class TestProtectedLocations:
    @pytest.mark.parametrize(
        "bad",
        [
            "/etc/shadow",
            "/etc/passwd",
            "/proc/self/environ",
            "C:/Windows/System32/config/SAM",
            "C:/Windows/SysWOW64/cmd.exe",
        ],
    )
    def test_protected_paths_rejected_even_if_rooted(self, workspace: Path, bad: str):
        guard = PathGuard(allowed_roots=[workspace])
        with pytest.raises(PathTraversalError):
            guard.validate(bad)

    def test_cannot_add_protected_root(self):
        guard = PathGuard()
        with pytest.raises(PathTraversalError):
            guard.add_root("/etc/sudoers")

    def test_cannot_add_filesystem_root(self):
        guard = PathGuard()
        with pytest.raises(PathTraversalError):
            guard.add_root("/" if os.name != "nt" else "C:\\")

    def test_ssh_directory_blocked(self, workspace: Path):
        guard = PathGuard(allowed_roots=[workspace])
        with pytest.raises(PathTraversalError):
            guard.validate(Path.home() / ".ssh" / "id_rsa")


# --------------------------------------------------------------------------
# Empty sandbox = deny all
# --------------------------------------------------------------------------
class TestDefaultDeny:
    def test_no_roots_denies_everything(self, tmp_path: Path):
        guard = PathGuard()
        with pytest.raises(PathTraversalError) as exc:
            guard.validate(tmp_path / "anything.txt")
        assert "approved folders" in exc.value.user_message.lower()

    def test_clear_revokes_access(self, guard: PathGuard, workspace: Path):
        assert guard.is_allowed(workspace / "notes.txt")
        guard.clear()
        assert not guard.is_allowed(workspace / "notes.txt")

    def test_remove_root_revokes_access(self, guard: PathGuard, workspace: Path):
        assert guard.remove_root(workspace) is True
        assert not guard.is_allowed(workspace / "notes.txt")


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
class TestSanitiseFilename:
    @pytest.mark.parametrize(
        ("raw", "expected_absent"),
        [
            ("../../etc/passwd", "/"),
            ("a\\b.txt", "\\"),
            ("bad<name>.txt", "<"),
            ("pipe|name.txt", "|"),
            ("null\x00byte.txt", "\x00"),
        ],
    )
    def test_dangerous_characters_removed(self, raw: str, expected_absent: str):
        assert expected_absent not in sanitise_filename(raw)

    def test_reserved_device_name_escaped(self):
        assert sanitise_filename("CON.txt") != "CON.txt"
        assert sanitise_filename("con.txt").lower() != "con.txt"

    def test_trailing_dots_and_spaces_stripped(self):
        assert sanitise_filename("report.txt. . ") == "report.txt"

    def test_empty_falls_back(self):
        assert sanitise_filename("   ") == "untitled"
        assert sanitise_filename("...") == "untitled"

    def test_long_name_truncated_keeping_extension(self):
        result = sanitise_filename("x" * 400 + ".xlsx")
        assert len(result) <= 180
        assert result.endswith(".xlsx")

    def test_normal_name_survives(self):
        assert sanitise_filename("Q3 Sales Report.xlsx") == "Q3 Sales Report.xlsx"


class TestResolveStrict:
    def test_resolves_relative_traversal_lexically(self, tmp_path: Path):
        result = resolve_strict(tmp_path / "a" / ".." / "b.txt")
        assert result == tmp_path / "b.txt"

    def test_existing_file_resolved(self, tmp_path: Path):
        target = tmp_path / "real.txt"
        target.write_text("x", encoding="utf-8")
        assert resolve_strict(target).exists()


class TestIsWithin:
    def test_true_for_descendant(self, tmp_path: Path):
        assert is_within(tmp_path / "a" / "b", tmp_path)

    def test_true_for_self(self, tmp_path: Path):
        assert is_within(tmp_path, tmp_path)

    def test_false_for_sibling(self, tmp_path: Path):
        assert not is_within(tmp_path.parent / "other", tmp_path)


class TestRelativeDisplay:
    def test_renders_relative_to_root(self, workspace: Path):
        text = relative_display(workspace / "sub" / "data.csv", [workspace])
        assert text == str(Path("sub") / "data.csv")

    def test_falls_back_to_basename(self, workspace: Path, tmp_path: Path):
        assert relative_display(tmp_path / "far" / "away.txt", [workspace]) == "away.txt"
