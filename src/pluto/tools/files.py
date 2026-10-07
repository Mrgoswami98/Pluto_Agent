"""Filesystem tools.

All of them take a :class:`~pluto.security.paths.PathGuard` and validate every
path through it. None of them accept a path that escapes the sandbox, and the
write-side tools verify their own effect rather than assuming success.
"""

from __future__ import annotations

import hashlib
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, ClassVar, Literal

from pydantic import BaseModel, Field, field_validator

from pluto.core.constants import RiskLevel, ToolCategory
from pluto.core.exceptions import ToolExecutionError
from pluto.core.logging_config import get_logger
from pluto.core.models import ToolResult
from pluto.security.paths import PathGuard, sanitise_filename
from pluto.security.untrusted import wrap as wrap_untrusted
from pluto.tools.registry import Tool, ToolContext

log = get_logger("tools.files")

#: Extensions we will read as text.
TEXT_EXTENSIONS = frozenset(
    {
        ".txt", ".md", ".markdown", ".csv", ".tsv", ".json", ".jsonl", ".xml",
        ".yaml", ".yml", ".ini", ".cfg", ".conf", ".toml", ".log", ".html",
        ".htm", ".css", ".js", ".ts", ".py", ".sql", ".rst", ".srt", ".vtt",
    }
)

MAX_READ_BYTES = 5 * 1024 * 1024
MAX_WRITE_BYTES = 20 * 1024 * 1024


def _human_size(num: int) -> str:
    size = float(num)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} GB"


def _file_info(path: Path, root: Path | None = None) -> dict[str, Any]:
    try:
        stat = path.stat()
    except OSError:
        return {"name": path.name, "error": "unreadable"}
    return {
        "name": path.name,
        "path": str(path.relative_to(root)) if root and path.is_relative_to(root) else str(path),
        "is_dir": path.is_dir(),
        "size_bytes": stat.st_size if path.is_file() else None,
        "size": _human_size(stat.st_size) if path.is_file() else None,
        "modified": datetime.fromtimestamp(stat.st_mtime, UTC).isoformat(),
        "extension": path.suffix.lower(),
    }


def _sha256(path: Path, limit: int = 50 * 1024 * 1024) -> str | None:
    """Digest used as verification evidence for copies."""
    try:
        if path.stat().st_size > limit:
            return None
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


class SandboxedTool(Tool[Any]):
    """Base for tools that need a path guard."""

    def __init__(self, guard: PathGuard) -> None:
        self.guard = guard


# --------------------------------------------------------------------------
# List
# --------------------------------------------------------------------------
class ListFilesArgs(BaseModel):
    folder: str = Field(description="Folder to list. Must be inside an approved folder.")
    pattern: str = Field(default="*", max_length=100)
    recursive: bool = False
    include_hidden: bool = False
    max_results: int = Field(default=200, ge=1, le=2000)


class ListFilesTool(SandboxedTool):
    name: ClassVar[str] = "file.list"
    description: ClassVar[str] = (
        "List files and folders inside an approved folder. Supports glob "
        "patterns such as '*.xlsx' and optional recursion."
    )
    category: ClassVar[ToolCategory] = ToolCategory.FILESYSTEM
    risk_level: ClassVar[RiskLevel] = RiskLevel.READ_ONLY
    action_kind: ClassVar[str] = "list_files"
    args_model: ClassVar[type[BaseModel]] = ListFilesArgs
    timeout_seconds: ClassVar[int] = 30

    def run(self, args: ListFilesArgs, context: ToolContext) -> ToolResult:
        folder = self.guard.validate(args.folder)
        if not folder.is_dir():
            return ToolResult.fail(f"Not a folder: {folder.name}")

        globber = folder.rglob if args.recursive else folder.glob
        entries: list[dict[str, Any]] = []
        truncated = False

        for item in globber(args.pattern):
            context.check_cancelled()
            if not args.include_hidden and any(
                part.startswith(".") for part in item.relative_to(folder).parts
            ):
                continue
            if not self.guard.is_allowed(item):
                continue  # a symlink pointing outside the sandbox
            if len(entries) >= args.max_results:
                truncated = True
                break
            entries.append(_file_info(item, folder))

        entries.sort(key=lambda e: (not e.get("is_dir", False), e["name"].lower()))
        files = sum(1 for e in entries if not e.get("is_dir"))
        folders = len(entries) - files

        return ToolResult.ok(
            output={"entries": entries, "truncated": truncated, "folder": str(folder)},
            summary=(
                f"Found {files} file(s) and {folders} folder(s) in {folder.name}"
                + (f" (capped at {args.max_results})" if truncated else "")
            ),
            verified=True,
            verification_note=f"Listing read directly from {folder}",
        )


# --------------------------------------------------------------------------
# Search
# --------------------------------------------------------------------------
class SearchFilesArgs(BaseModel):
    folder: str
    query: str = Field(min_length=1, max_length=200)
    search_content: bool = Field(
        default=False, description="Also search inside text files."
    )
    max_results: int = Field(default=50, ge=1, le=500)


class SearchFilesTool(SandboxedTool):
    name: ClassVar[str] = "file.search"
    description: ClassVar[str] = (
        "Search for files by name, and optionally by text content, within an "
        "approved folder."
    )
    category: ClassVar[ToolCategory] = ToolCategory.FILESYSTEM
    risk_level: ClassVar[RiskLevel] = RiskLevel.READ_ONLY
    action_kind: ClassVar[str] = "search_files"
    args_model: ClassVar[type[BaseModel]] = SearchFilesArgs
    timeout_seconds: ClassVar[int] = 60

    def run(self, args: SearchFilesArgs, context: ToolContext) -> ToolResult:
        folder = self.guard.validate(args.folder)
        if not folder.is_dir():
            return ToolResult.fail(f"Not a folder: {folder.name}")

        needle = args.query.lower()
        matches: list[dict[str, Any]] = []

        for item in folder.rglob("*"):
            context.check_cancelled()
            if len(matches) >= args.max_results:
                break
            if not item.is_file() or not self.guard.is_allowed(item):
                continue

            if needle in item.name.lower():
                matches.append({**_file_info(item, folder), "matched": "name"})
                continue

            if args.search_content and item.suffix.lower() in TEXT_EXTENSIONS:
                try:
                    if item.stat().st_size > MAX_READ_BYTES:
                        continue
                    text = item.read_text("utf-8", errors="ignore")
                except OSError:
                    continue
                index = text.lower().find(needle)
                if index >= 0:
                    start = max(0, index - 60)
                    snippet = text[start : index + 120].replace("\n", " ").strip()
                    matches.append(
                        {**_file_info(item, folder), "matched": "content",
                         "snippet": snippet}
                    )

        return ToolResult.ok(
            output={"matches": matches, "query": args.query},
            summary=f"{len(matches)} match(es) for '{args.query}' in {folder.name}",
            verified=True,
            verification_note="Search performed against the live filesystem.",
        )


# --------------------------------------------------------------------------
# Read
# --------------------------------------------------------------------------
class ReadFileArgs(BaseModel):
    path: str
    max_characters: int = Field(default=50_000, ge=100, le=500_000)
    treat_as_untrusted: bool = Field(
        default=True,
        description="Wrap the content so its text is never treated as instructions.",
    )


class ReadFileTool(SandboxedTool):
    name: ClassVar[str] = "file.read"
    description: ClassVar[str] = (
        "Read a text file (txt, md, csv, json, log, code and similar) from an "
        "approved folder. Content is treated as untrusted data."
    )
    category: ClassVar[ToolCategory] = ToolCategory.FILESYSTEM
    risk_level: ClassVar[RiskLevel] = RiskLevel.READ_ONLY
    action_kind: ClassVar[str] = "read_file"
    args_model: ClassVar[type[BaseModel]] = ReadFileArgs
    timeout_seconds: ClassVar[int] = 30

    def run(self, args: ReadFileArgs, context: ToolContext) -> ToolResult:
        path = self.guard.validate(args.path)
        if not path.is_file():
            return ToolResult.fail(f"No such file: {path.name}")

        size = path.stat().st_size
        if size > MAX_READ_BYTES:
            return ToolResult.fail(
                f"{path.name} is {_human_size(size)}; the limit is "
                f"{_human_size(MAX_READ_BYTES)}."
            )

        suffix = path.suffix.lower()
        if suffix not in TEXT_EXTENSIONS:
            return ToolResult.fail(
                f"'{suffix or 'no extension'}' is not a readable text format. "
                f"Use the spreadsheet tools for Excel files."
            )

        try:
            text = path.read_text("utf-8", errors="replace")
        except OSError as exc:
            raise ToolExecutionError(
                f"Could not read {path.name}: {exc}",
                user_message=f"Pluto could not read {path.name}.",
            ) from exc

        truncated = len(text) > args.max_characters
        if truncated:
            text = text[: args.max_characters] + "\n\n[... truncated by Pluto ...]"

        assessment_summary = None
        if args.treat_as_untrusted:
            text, assessment = wrap_untrusted(
                text, source=path.name, content_type=suffix.lstrip(".") or "text"
            )
            if assessment.is_suspicious:
                assessment_summary = assessment.summary

        return ToolResult.ok(
            output={"content": text, "truncated": truncated, "size_bytes": size},
            summary=(
                f"Read {path.name} ({_human_size(size)})"
                + (f" — {assessment_summary}" if assessment_summary else "")
            ),
            verified=True,
            verification_note=f"Content read from {path}",
            suspicious_content=bool(assessment_summary),
        )


# --------------------------------------------------------------------------
# Write
# --------------------------------------------------------------------------
class WriteFileArgs(BaseModel):
    path: str
    content: str = Field(max_length=MAX_WRITE_BYTES)
    mode: Literal["create", "overwrite", "append"] = "create"
    encoding: str = Field(default="utf-8", max_length=20)

    @field_validator("encoding")
    @classmethod
    def _known_encoding(cls, value: str) -> str:
        import codecs

        try:
            codecs.lookup(value)
        except LookupError as exc:
            raise ValueError(f"unknown encoding '{value}'") from exc
        return value


class WriteFileTool(SandboxedTool):
    name: ClassVar[str] = "file.write"
    description: ClassVar[str] = (
        "Write a text file inside an approved folder. 'create' refuses to "
        "clobber an existing file; overwriting is a higher-risk action."
    )
    category: ClassVar[ToolCategory] = ToolCategory.FILESYSTEM
    risk_level: ClassVar[RiskLevel] = RiskLevel.LOW
    action_kind: ClassVar[str] = "write_file"
    args_model: ClassVar[type[BaseModel]] = WriteFileArgs
    timeout_seconds: ClassVar[int] = 30

    def run(self, args: WriteFileArgs, context: ToolContext) -> ToolResult:
        path = self.guard.validate(args.path, for_write=True)

        if path.exists() and args.mode == "create":
            return ToolResult.fail(
                f"{path.name} already exists. Use mode='overwrite' to replace it "
                f"— that needs your approval."
            )
        if path.is_dir():
            return ToolResult.fail(f"{path.name} is a folder, not a file.")

        path.parent.mkdir(parents=True, exist_ok=True)
        file_mode = "a" if args.mode == "append" else "w"

        try:
            with path.open(file_mode, encoding=args.encoding, newline="") as handle:
                handle.write(args.content)
        except OSError as exc:
            raise ToolExecutionError(
                f"Could not write {path.name}: {exc}",
                user_message=f"Pluto could not write {path.name}.",
            ) from exc

        return ToolResult.ok(
            output={"path": str(path), "bytes_written": len(args.content.encode(args.encoding))},
            summary=f"Wrote {path.name} ({len(args.content):,} characters)",
        )

    def verify(
        self, args: WriteFileArgs, result: ToolResult, context: ToolContext
    ) -> ToolResult:
        """Read the file back and confirm the content is actually there."""
        if not result.success:
            return result
        path = Path(result.output["path"])
        if not path.exists():
            result.verified = False
            result.verification_note = "File does not exist after writing."
            return result

        try:
            written = path.read_text(args.encoding, errors="replace")
        except OSError as exc:
            result.verified = False
            result.verification_note = f"Could not read the file back: {exc}"
            return result

        if args.mode == "append":
            matched = written.endswith(args.content)
            note = "Appended content found at the end of the file."
        else:
            matched = written == args.content
            note = f"File content matches exactly ({path.stat().st_size} bytes on disk)."

        result.verified = matched
        result.verification_note = (
            note if matched else "File content does not match what was requested."
        )
        return result


# --------------------------------------------------------------------------
# Copy / move
# --------------------------------------------------------------------------
class CopyFileArgs(BaseModel):
    source: str
    destination: str
    overwrite: bool = False


class CopyFileTool(SandboxedTool):
    name: ClassVar[str] = "file.copy"
    description: ClassVar[str] = "Copy a file within approved folders."
    category: ClassVar[ToolCategory] = ToolCategory.FILESYSTEM
    risk_level: ClassVar[RiskLevel] = RiskLevel.LOW
    action_kind: ClassVar[str] = "copy_file"
    args_model: ClassVar[type[BaseModel]] = CopyFileArgs
    timeout_seconds: ClassVar[int] = 120

    def run(self, args: CopyFileArgs, context: ToolContext) -> ToolResult:
        source = self.guard.validate(args.source)
        destination = self.guard.validate(args.destination, for_write=True)

        if not source.is_file():
            return ToolResult.fail(f"No such file: {source.name}")
        if destination.exists() and not args.overwrite:
            return ToolResult.fail(
                f"{destination.name} already exists. Set overwrite=true to replace it."
            )

        destination.parent.mkdir(parents=True, exist_ok=True)
        try:
            shutil.copy2(source, destination)
        except OSError as exc:
            raise ToolExecutionError(
                f"Copy failed: {exc}",
                user_message=f"Pluto could not copy {source.name}.",
            ) from exc

        return ToolResult.ok(
            output={
                "source": str(source),
                "destination": str(destination),
                "source_sha256": _sha256(source),
            },
            summary=f"Copied {source.name} to {destination.name}",
        )

    def verify(
        self, args: CopyFileArgs, result: ToolResult, context: ToolContext
    ) -> ToolResult:
        """Compare digests — the only honest proof a copy is identical."""
        if not result.success:
            return result
        destination = Path(result.output["destination"])
        if not destination.exists():
            result.verified = False
            result.verification_note = "Destination file does not exist."
            return result

        source_digest = result.output.get("source_sha256")
        dest_digest = _sha256(destination)
        if source_digest and dest_digest:
            result.verified = source_digest == dest_digest
            result.verification_note = (
                "Source and destination SHA-256 digests match."
                if result.verified
                else "Digests differ — the copy is not identical."
            )
        else:
            source = Path(result.output["source"])
            same_size = source.stat().st_size == destination.stat().st_size
            result.verified = same_size
            result.verification_note = (
                "File too large to hash; sizes match."
                if same_size
                else "Sizes differ after copy."
            )
        return result


class MoveFileArgs(BaseModel):
    source: str
    destination: str
    overwrite: bool = False


class MoveFileTool(SandboxedTool):
    name: ClassVar[str] = "file.move"
    description: ClassVar[str] = (
        "Move or rename a file within approved folders. This changes existing "
        "data, so it is a medium-risk action."
    )
    category: ClassVar[ToolCategory] = ToolCategory.FILESYSTEM
    risk_level: ClassVar[RiskLevel] = RiskLevel.MEDIUM
    action_kind: ClassVar[str] = "move_file"
    args_model: ClassVar[type[BaseModel]] = MoveFileArgs
    timeout_seconds: ClassVar[int] = 120

    def run(self, args: MoveFileArgs, context: ToolContext) -> ToolResult:
        source = self.guard.validate(args.source)
        destination = self.guard.validate(args.destination, for_write=True)

        if not source.exists():
            return ToolResult.fail(f"No such file: {source.name}")
        if destination.exists() and not args.overwrite:
            return ToolResult.fail(
                f"{destination.name} already exists. Set overwrite=true to replace it."
            )

        destination.parent.mkdir(parents=True, exist_ok=True)
        try:
            shutil.move(str(source), str(destination))
        except OSError as exc:
            raise ToolExecutionError(
                f"Move failed: {exc}",
                user_message=f"Pluto could not move {source.name}.",
            ) from exc

        return ToolResult.ok(
            output={"source": str(source), "destination": str(destination)},
            summary=f"Moved {source.name} to {destination.name}",
        )

    def verify(
        self, args: MoveFileArgs, result: ToolResult, context: ToolContext
    ) -> ToolResult:
        if not result.success:
            return result
        source = Path(result.output["source"])
        destination = Path(result.output["destination"])
        moved = destination.exists() and not source.exists()
        result.verified = moved
        result.verification_note = (
            "Destination exists and the source is gone."
            if moved
            else f"Move not confirmed (destination exists: {destination.exists()}, "
            f"source still present: {source.exists()})."
        )
        return result


# --------------------------------------------------------------------------
# Create folder
# --------------------------------------------------------------------------
class CreateFolderArgs(BaseModel):
    path: str


class CreateFolderTool(SandboxedTool):
    name: ClassVar[str] = "file.create_folder"
    description: ClassVar[str] = "Create a folder inside an approved folder."
    category: ClassVar[ToolCategory] = ToolCategory.FILESYSTEM
    risk_level: ClassVar[RiskLevel] = RiskLevel.LOW
    action_kind: ClassVar[str] = "create_folder"
    args_model: ClassVar[type[BaseModel]] = CreateFolderArgs
    timeout_seconds: ClassVar[int] = 15

    def run(self, args: CreateFolderArgs, context: ToolContext) -> ToolResult:
        path = self.guard.validate(args.path, for_write=True)
        if path.exists():
            return ToolResult.ok(
                output={"path": str(path), "already_existed": True},
                summary=f"{path.name} already exists",
            )
        path.mkdir(parents=True, exist_ok=True)
        return ToolResult.ok(output={"path": str(path)}, summary=f"Created {path.name}")

    def verify(
        self, args: CreateFolderArgs, result: ToolResult, context: ToolContext
    ) -> ToolResult:
        if result.success:
            path = Path(result.output["path"])
            result.verified = path.is_dir()
            result.verification_note = (
                f"{path.name} exists as a folder."
                if result.verified
                else "Folder was not created."
            )
        return result


# --------------------------------------------------------------------------
# Organise
# --------------------------------------------------------------------------
#: Extension -> folder name, used by file.organize.
CATEGORY_MAP: dict[str, str] = {
    **dict.fromkeys([".jpg", ".jpeg", ".png", ".gif", ".bmp", ".svg", ".webp",
                     ".tiff", ".heic"], "Images"),
    **dict.fromkeys([".pdf"], "PDFs"),
    **dict.fromkeys([".doc", ".docx", ".odt", ".rtf", ".txt", ".md"], "Documents"),
    **dict.fromkeys([".xls", ".xlsx", ".xlsm", ".csv", ".tsv", ".ods"], "Spreadsheets"),
    **dict.fromkeys([".ppt", ".pptx", ".odp"], "Presentations"),
    **dict.fromkeys([".zip", ".rar", ".7z", ".tar", ".gz", ".bz2"], "Archives"),
    **dict.fromkeys([".mp3", ".wav", ".flac", ".aac", ".ogg", ".m4a"], "Audio"),
    **dict.fromkeys([".mp4", ".avi", ".mkv", ".mov", ".wmv", ".webm"], "Video"),
    **dict.fromkeys([".py", ".js", ".ts", ".java", ".c", ".cpp", ".cs", ".go",
                     ".rs", ".rb", ".php", ".html", ".css", ".json", ".xml"], "Code"),
}


class OrganizeArgs(BaseModel):
    folder: str
    strategy: Literal["by_type", "by_date", "by_extension"] = "by_type"
    dry_run: bool = Field(
        default=True,
        description="Preview the plan without moving anything. Strongly preferred.",
    )


class OrganizeFolderTool(SandboxedTool):
    name: ClassVar[str] = "file.organize"
    description: ClassVar[str] = (
        "Sort files in a folder into subfolders by type, extension or date. "
        "Defaults to a dry run that only reports what it would do."
    )
    category: ClassVar[ToolCategory] = ToolCategory.FILESYSTEM
    risk_level: ClassVar[RiskLevel] = RiskLevel.MEDIUM
    action_kind: ClassVar[str] = "organize_files"
    args_model: ClassVar[type[BaseModel]] = OrganizeArgs
    timeout_seconds: ClassVar[int] = 300

    def run(self, args: OrganizeArgs, context: ToolContext) -> ToolResult:
        folder = self.guard.validate(args.folder, for_write=True)
        if not folder.is_dir():
            return ToolResult.fail(f"Not a folder: {folder.name}")

        plan: list[dict[str, str]] = []
        for item in folder.iterdir():
            context.check_cancelled()
            if not item.is_file() or item.name.startswith("."):
                continue
            if not self.guard.is_allowed(item):
                continue
            plan.append(
                {
                    "file": item.name,
                    "destination_folder": self._bucket(item, args.strategy),
                }
            )

        if args.dry_run:
            return ToolResult.ok(
                output={"plan": plan, "dry_run": True},
                summary=f"Would reorganise {len(plan)} file(s) in {folder.name}",
                verified=True,
                verification_note="Dry run — the filesystem was not changed.",
            )

        moved, skipped = [], []
        for entry in plan:
            context.check_cancelled()
            source = folder / entry["file"]
            target_dir = folder / sanitise_filename(entry["destination_folder"])
            target = target_dir / entry["file"]
            if target.exists():
                skipped.append(entry["file"])
                continue
            try:
                target_dir.mkdir(parents=True, exist_ok=True)
                shutil.move(str(source), str(target))
                moved.append({"file": entry["file"], "to": str(target)})
            except OSError as exc:
                log.warning("Could not move %s: %s", entry["file"], exc)
                skipped.append(entry["file"])

        return ToolResult.ok(
            output={"moved": moved, "skipped": skipped, "dry_run": False},
            summary=(
                f"Moved {len(moved)} file(s) in {folder.name}"
                + (f"; skipped {len(skipped)}" if skipped else "")
            ),
        )

    @staticmethod
    def _bucket(path: Path, strategy: str) -> str:
        if strategy == "by_extension":
            return (path.suffix.lstrip(".") or "no_extension").upper()
        if strategy == "by_date":
            stamp = datetime.fromtimestamp(path.stat().st_mtime, UTC)
            return stamp.strftime("%Y-%m")
        return CATEGORY_MAP.get(path.suffix.lower(), "Other")

    def verify(
        self, args: OrganizeArgs, result: ToolResult, context: ToolContext
    ) -> ToolResult:
        if not result.success or result.output.get("dry_run"):
            return result
        moved = result.output.get("moved", [])
        confirmed = sum(1 for entry in moved if Path(entry["to"]).exists())
        result.verified = confirmed == len(moved)
        result.verification_note = (
            f"All {confirmed} moved file(s) confirmed at their new location."
            if result.verified
            else f"Only {confirmed} of {len(moved)} moved files were found."
        )
        return result


# --------------------------------------------------------------------------
# File info
# --------------------------------------------------------------------------
class FileInfoArgs(BaseModel):
    path: str


class FileInfoTool(SandboxedTool):
    name: ClassVar[str] = "file.info"
    description: ClassVar[str] = "Get details about a file or folder: size, dates, type."
    category: ClassVar[ToolCategory] = ToolCategory.FILESYSTEM
    risk_level: ClassVar[RiskLevel] = RiskLevel.READ_ONLY
    action_kind: ClassVar[str] = "read_metadata"
    args_model: ClassVar[type[BaseModel]] = FileInfoArgs
    timeout_seconds: ClassVar[int] = 15

    def run(self, args: FileInfoArgs, context: ToolContext) -> ToolResult:
        path = self.guard.validate(args.path)
        if not path.exists():
            return ToolResult.fail(f"No such file or folder: {path.name}")

        info = _file_info(path)
        if path.is_dir():
            children = list(path.iterdir())
            info["item_count"] = len(children)
        return ToolResult.ok(
            output=info,
            summary=f"{path.name}: {info.get('size') or 'folder'}",
            verified=True,
            verification_note="Metadata read from the filesystem.",
        )


def build_file_tools(guard: PathGuard) -> list[Tool[Any]]:
    """Every filesystem tool, bound to *guard*."""
    return [
        ListFilesTool(guard),
        SearchFilesTool(guard),
        ReadFileTool(guard),
        WriteFileTool(guard),
        CopyFileTool(guard),
        MoveFileTool(guard),
        CreateFolderTool(guard),
        OrganizeFolderTool(guard),
        FileInfoTool(guard),
    ]
