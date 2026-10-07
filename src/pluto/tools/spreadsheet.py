"""Spreadsheet and CSV analysis tools.

Built on pandas and openpyxl. Treats cell contents as untrusted data — a
spreadsheet is a perfectly good injection vector.
"""

from __future__ import annotations

import math
from pathlib import Path
from typing import Any, ClassVar, Literal

import pandas as pd
from pydantic import BaseModel, Field

from pluto.core.constants import RiskLevel, ToolCategory
from pluto.core.exceptions import ToolExecutionError
from pluto.core.logging_config import get_logger
from pluto.core.models import ToolResult
from pluto.security.paths import PathGuard
from pluto.security.untrusted import scan
from pluto.tools.registry import Tool, ToolContext

log = get_logger("tools.spreadsheet")

SPREADSHEET_EXTENSIONS = frozenset({".xlsx", ".xlsm", ".xltx", ".csv", ".tsv"})
MAX_ROWS = 1_000_000
MAX_PREVIEW_ROWS = 100


def _clean(value: Any) -> Any:
    """Make a pandas value JSON-safe."""
    if value is None or (isinstance(value, float) and math.isnan(value)):
        return None
    if isinstance(value, (pd.Timestamp,)):
        return value.isoformat()
    if hasattr(value, "item"):
        try:
            return value.item()
        except (ValueError, AttributeError):
            pass
    return value


def _records(frame: pd.DataFrame, limit: int) -> list[dict[str, Any]]:
    subset = frame.head(limit)
    return [
        {str(col): _clean(row[col]) for col in subset.columns}
        for _, row in subset.iterrows()
    ]


def _load(path: Path, sheet: str | int | None = None) -> pd.DataFrame:
    suffix = path.suffix.lower()
    try:
        if suffix in {".csv", ".tsv"}:
            separator = "\t" if suffix == ".tsv" else ","
            return pd.read_csv(path, sep=separator, nrows=MAX_ROWS,
                               encoding_errors="replace")
        return pd.read_excel(path, sheet_name=sheet if sheet is not None else 0,
                             nrows=MAX_ROWS)
    except Exception as exc:
        raise ToolExecutionError(
            f"Could not read {path.name}: {exc}",
            user_message=f"Pluto could not open {path.name}. It may be corrupt, "
            f"password-protected, or in an unexpected format.",
            detail=str(exc),
        ) from exc


class SpreadsheetTool(Tool[Any]):
    def __init__(self, guard: PathGuard) -> None:
        self.guard = guard

    def _validated(self, raw: str, *, for_write: bool = False) -> Path:
        path = self.guard.validate(raw, for_write=for_write)
        if path.suffix.lower() not in SPREADSHEET_EXTENSIONS:
            raise ToolExecutionError(
                f"'{path.suffix}' is not a spreadsheet format",
                user_message=(
                    f"{path.name} is not a spreadsheet. Supported: "
                    f"{', '.join(sorted(SPREADSHEET_EXTENSIONS))}"
                ),
            )
        return path


# --------------------------------------------------------------------------
# Inspect
# --------------------------------------------------------------------------
class InspectArgs(BaseModel):
    path: str
    sheet: str | int | None = None
    preview_rows: int = Field(default=10, ge=1, le=MAX_PREVIEW_ROWS)


class InspectSpreadsheetTool(SpreadsheetTool):
    name: ClassVar[str] = "sheet.inspect"
    description: ClassVar[str] = (
        "Open an Excel or CSV file and report its structure: sheet names, "
        "columns, data types, row count, missing values and a preview."
    )
    category: ClassVar[ToolCategory] = ToolCategory.SPREADSHEET
    risk_level: ClassVar[RiskLevel] = RiskLevel.READ_ONLY
    action_kind: ClassVar[str] = "read_spreadsheet"
    args_model: ClassVar[type[BaseModel]] = InspectArgs
    timeout_seconds: ClassVar[int] = 120

    def run(self, args: InspectArgs, context: ToolContext) -> ToolResult:
        path = self._validated(args.path)
        if not path.is_file():
            return ToolResult.fail(f"No such file: {path.name}")

        sheet_names: list[str] = []
        if path.suffix.lower() not in {".csv", ".tsv"}:
            try:
                sheet_names = pd.ExcelFile(path).sheet_names
            except Exception as exc:
                log.debug("Could not list sheets: %s", exc)

        frame = _load(path, args.sheet)
        context.check_cancelled()

        columns = []
        for name in frame.columns:
            series = frame[name]
            columns.append(
                {
                    "name": str(name),
                    "dtype": str(series.dtype),
                    "non_null": int(series.notna().sum()),
                    "null_count": int(series.isna().sum()),
                    "unique_values": int(series.nunique(dropna=True)),
                    "sample": _clean(series.dropna().iloc[0]) if series.notna().any() else None,
                }
            )

        # Cells are untrusted content.
        preview = _records(frame, args.preview_rows)
        flagged = scan(str(preview)[:20_000]).is_suspicious

        return ToolResult.ok(
            output={
                "file": path.name,
                "sheet_names": sheet_names,
                "row_count": len(frame),
                "column_count": len(frame.columns),
                "columns": columns,
                "preview": preview,
                "contains_instruction_like_text": flagged,
            },
            summary=(
                f"{path.name}: {len(frame):,} rows x {len(frame.columns)} columns"
                + (f" across {len(sheet_names)} sheets" if len(sheet_names) > 1 else "")
                + (" — contains instruction-like text, treated as data" if flagged else "")
            ),
            verified=True,
            verification_note=f"Structure read directly from {path.name}.",
        )


# --------------------------------------------------------------------------
# Analyse
# --------------------------------------------------------------------------
class AnalyzeArgs(BaseModel):
    path: str
    sheet: str | int | None = None
    columns: list[str] | None = Field(
        default=None, description="Restrict to these columns. Omit for all."
    )
    group_by: str | None = None
    aggregate: Literal["sum", "mean", "count", "min", "max", "median"] = "sum"


class AnalyzeSpreadsheetTool(SpreadsheetTool):
    name: ClassVar[str] = "sheet.analyze"
    description: ClassVar[str] = (
        "Compute summary statistics for a spreadsheet: totals, averages, "
        "min/max, and optional grouping such as revenue by region."
    )
    category: ClassVar[ToolCategory] = ToolCategory.SPREADSHEET
    risk_level: ClassVar[RiskLevel] = RiskLevel.READ_ONLY
    action_kind: ClassVar[str] = "analyze_spreadsheet"
    args_model: ClassVar[type[BaseModel]] = AnalyzeArgs
    timeout_seconds: ClassVar[int] = 180

    def run(self, args: AnalyzeArgs, context: ToolContext) -> ToolResult:
        path = self._validated(args.path)
        if not path.is_file():
            return ToolResult.fail(f"No such file: {path.name}")

        frame = _load(path, args.sheet)
        context.check_cancelled()

        if args.columns:
            missing = [c for c in args.columns if c not in frame.columns]
            if missing:
                return ToolResult.fail(
                    f"Column(s) not found: {', '.join(missing)}. "
                    f"Available: {', '.join(str(c) for c in frame.columns[:20])}"
                )
            frame = frame[args.columns]

        numeric = frame.select_dtypes("number")
        statistics: dict[str, dict[str, Any]] = {}
        for name in numeric.columns:
            series = numeric[name].dropna()
            if series.empty:
                continue
            statistics[str(name)] = {
                "count": int(series.count()),
                "sum": _clean(series.sum()),
                "mean": _clean(round(series.mean(), 4)),
                "median": _clean(series.median()),
                "min": _clean(series.min()),
                "max": _clean(series.max()),
                "std": _clean(round(series.std(), 4)) if len(series) > 1 else None,
            }

        grouped: list[dict[str, Any]] | None = None
        if args.group_by:
            if args.group_by not in frame.columns:
                return ToolResult.fail(f"Group-by column not found: {args.group_by}")
            try:
                aggregated = (
                    frame.groupby(args.group_by, dropna=False)
                    .agg(args.aggregate, numeric_only=True)
                    .reset_index()
                )
                grouped = _records(aggregated, 200)
            except Exception as exc:
                return ToolResult.fail(f"Could not group by {args.group_by}: {exc}")

        return ToolResult.ok(
            output={
                "file": path.name,
                "row_count": len(frame),
                "statistics": statistics,
                "grouped": grouped,
                "group_by": args.group_by,
                "aggregate": args.aggregate,
            },
            summary=(
                f"Analysed {len(frame):,} rows of {path.name}; "
                f"{len(statistics)} numeric column(s)"
                + (f", grouped by {args.group_by}" if args.group_by else "")
            ),
            verified=True,
            verification_note=f"Statistics computed from {len(frame):,} rows read from disk.",
        )


# --------------------------------------------------------------------------
# Filter / query
# --------------------------------------------------------------------------
class FilterArgs(BaseModel):
    path: str
    sheet: str | int | None = None
    column: str
    operator: Literal["equals", "not_equals", "contains", "greater_than",
                      "less_than", "is_empty", "not_empty"] = "equals"
    value: str | float | int | None = None
    max_results: int = Field(default=100, ge=1, le=5000)


class FilterSpreadsheetTool(SpreadsheetTool):
    name: ClassVar[str] = "sheet.filter"
    description: ClassVar[str] = (
        "Find rows matching a condition, such as orders over 5000 or rows "
        "where Status equals Pending."
    )
    category: ClassVar[ToolCategory] = ToolCategory.SPREADSHEET
    risk_level: ClassVar[RiskLevel] = RiskLevel.READ_ONLY
    action_kind: ClassVar[str] = "query_spreadsheet"
    args_model: ClassVar[type[BaseModel]] = FilterArgs
    timeout_seconds: ClassVar[int] = 120

    def run(self, args: FilterArgs, context: ToolContext) -> ToolResult:
        path = self._validated(args.path)
        if not path.is_file():
            return ToolResult.fail(f"No such file: {path.name}")

        frame = _load(path, args.sheet)
        if args.column not in frame.columns:
            return ToolResult.fail(
                f"Column '{args.column}' not found. Available: "
                f"{', '.join(str(c) for c in frame.columns[:20])}"
            )

        series = frame[args.column]
        try:
            mask = self._mask(series, args.operator, args.value)
        except (TypeError, ValueError) as exc:
            return ToolResult.fail(
                f"Cannot apply '{args.operator}' to column '{args.column}': {exc}"
            )

        matched = frame[mask]
        return ToolResult.ok(
            output={
                "matched_rows": len(matched),
                "total_rows": len(frame),
                "rows": _records(matched, args.max_results),
                "truncated": len(matched) > args.max_results,
            },
            summary=(
                f"{len(matched):,} of {len(frame):,} rows match "
                f"{args.column} {args.operator} {args.value!r}"
            ),
            verified=True,
            verification_note="Filter applied to the full dataset read from disk.",
        )

    @staticmethod
    def _mask(series: pd.Series, operator: str, value: Any) -> pd.Series:
        if operator == "is_empty":
            return series.isna()
        if operator == "not_empty":
            return series.notna()
        if operator == "contains":
            return series.astype(str).str.contains(str(value), case=False, na=False)
        if operator == "equals":
            return series.astype(str).str.lower() == str(value).lower()
        if operator == "not_equals":
            return series.astype(str).str.lower() != str(value).lower()

        numeric = pd.to_numeric(series, errors="coerce")
        threshold = float(value)  # type: ignore[arg-type]
        if operator == "greater_than":
            return numeric > threshold
        return numeric < threshold


# --------------------------------------------------------------------------
# Export
# --------------------------------------------------------------------------
class ExportArgs(BaseModel):
    source_path: str
    destination_path: str
    sheet: str | int | None = None
    columns: list[str] | None = None
    overwrite: bool = False


class ExportSpreadsheetTool(SpreadsheetTool):
    name: ClassVar[str] = "sheet.export"
    description: ClassVar[str] = (
        "Write a spreadsheet out to a new .xlsx or .csv file, optionally "
        "keeping only selected columns."
    )
    category: ClassVar[ToolCategory] = ToolCategory.SPREADSHEET
    risk_level: ClassVar[RiskLevel] = RiskLevel.LOW
    action_kind: ClassVar[str] = "write_spreadsheet"
    args_model: ClassVar[type[BaseModel]] = ExportArgs
    timeout_seconds: ClassVar[int] = 180

    def run(self, args: ExportArgs, context: ToolContext) -> ToolResult:
        source = self._validated(args.source_path)
        destination = self._validated(args.destination_path, for_write=True)

        if not source.is_file():
            return ToolResult.fail(f"No such file: {source.name}")
        if destination.exists() and not args.overwrite:
            return ToolResult.fail(
                f"{destination.name} already exists. Set overwrite=true to replace it."
            )

        frame = _load(source, args.sheet)
        if args.columns:
            missing = [c for c in args.columns if c not in frame.columns]
            if missing:
                return ToolResult.fail(f"Column(s) not found: {', '.join(missing)}")
            frame = frame[args.columns]

        destination.parent.mkdir(parents=True, exist_ok=True)
        try:
            if destination.suffix.lower() in {".csv", ".tsv"}:
                separator = "\t" if destination.suffix.lower() == ".tsv" else ","
                frame.to_csv(destination, index=False, sep=separator)
            else:
                frame.to_excel(destination, index=False, engine="openpyxl")
        except Exception as exc:
            raise ToolExecutionError(
                f"Export failed: {exc}",
                user_message=f"Pluto could not write {destination.name}.",
            ) from exc

        return ToolResult.ok(
            output={
                "destination": str(destination),
                "rows_written": len(frame),
                "columns_written": len(frame.columns),
            },
            summary=f"Exported {len(frame):,} rows to {destination.name}",
        )

    def verify(
        self, args: ExportArgs, result: ToolResult, context: ToolContext
    ) -> ToolResult:
        """Read the file back and count the rows — not just 'the call returned'."""
        if not result.success:
            return result
        destination = Path(result.output["destination"])
        if not destination.exists():
            result.verified = False
            result.verification_note = "Exported file does not exist."
            return result
        try:
            written = _load(destination)
        except ToolExecutionError as exc:
            result.verified = False
            result.verification_note = f"Exported file could not be re-opened: {exc}"
            return result

        expected = result.output["rows_written"]
        result.verified = len(written) == expected
        result.verification_note = (
            f"Re-opened {destination.name}: {len(written):,} rows, as expected."
            if result.verified
            else f"Expected {expected:,} rows but the file contains {len(written):,}."
        )
        return result


def build_spreadsheet_tools(guard: PathGuard) -> list[Tool[Any]]:
    return [
        InspectSpreadsheetTool(guard),
        AnalyzeSpreadsheetTool(guard),
        FilterSpreadsheetTool(guard),
        ExportSpreadsheetTool(guard),
    ]
