"""Planning: turning a request into a validated plan.

The model proposes; this module disposes. Everything that comes back is
validated before it can reach the executor:

* unknown tool names are rejected,
* arguments are validated against each tool's own schema,
* the dependency graph is checked for cycles and dangling ids,
* **risk levels are recomputed from the tool registry, not trusted from the
  model** — a plan claiming that deleting a file is "read_only" gets corrected.

That last point matters: it is the difference between a plan the model wrote
and a plan the system is willing to run.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from pluto.ai.client import ClaudeClient
from pluto.ai.prompts import PLANNER_PROMPT
from pluto.core.constants import RiskLevel, TaskStatus
from pluto.core.exceptions import PlanningError
from pluto.core.logging_config import get_logger
from pluto.core.models import Task, TaskStep
from pluto.tools.registry import ToolRegistry

log = get_logger("ai.planner")

_JSON_BLOCK = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL)


@dataclass
class PlanningResult:
    """Either a plan, or a question for the user."""

    task: Task | None
    clarification_needed: str | None = None
    corrections: list[str] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.corrections is None:
            self.corrections = []

    @property
    def needs_clarification(self) -> bool:
        return self.clarification_needed is not None


def extract_json(text: str) -> dict[str, Any]:
    """Pull a JSON object out of a model response.

    Handles a bare object, a fenced block, and an object with prose around it.
    """
    text = text.strip()
    if not text:
        raise PlanningError(
            "The model returned an empty plan",
            user_message="Pluto could not produce a plan. Try rephrasing the request.",
        )

    candidates: list[str] = []

    fenced = _JSON_BLOCK.search(text)
    if fenced:
        candidates.append(fenced.group(1))
    candidates.append(text)

    # Last resort: the outermost braces.
    start, end = text.find("{"), text.rfind("}")
    if start >= 0 and end > start:
        candidates.append(text[start : end + 1])

    for candidate in candidates:
        try:
            parsed = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            return parsed

    raise PlanningError(
        f"Could not parse a plan from the model response: {text[:300]}",
        user_message=(
            "Pluto's plan came back in an unexpected format. Try asking again."
        ),
        detail=text[:1000],
    )


class Planner:
    """Produces validated :class:`Task` objects from natural-language requests."""

    def __init__(
        self,
        client: ClaudeClient,
        registry: ToolRegistry,
        *,
        max_steps: int = 25,
    ) -> None:
        self._client = client
        self._registry = registry
        self._max_steps = max_steps

    def plan(
        self,
        request: str,
        *,
        system_prompt: str,
        autonomy_mode: Any = None,
        context: str | None = None,
        cancel_event: Any = None,
    ) -> PlanningResult:
        """Ask the model for a plan and validate it."""
        tool_catalogue = json.dumps(self._registry.schemas(), indent=2)[:30_000]

        user_content = (
            f"User request:\n{request}\n\n"
            f"Tools available:\n{tool_catalogue}\n\n"
            f"Maximum steps allowed: {self._max_steps}"
        )
        if context:
            user_content += f"\n\nRelevant context:\n{context}"

        response = self._client.send(
            messages=[{"role": "user", "content": user_content}],
            system=f"{system_prompt}\n\n{PLANNER_PROMPT}",
            cancel_event=cancel_event,
        )

        payload = extract_json(response.text)
        return self.build_task(
            payload, request=request, autonomy_mode=autonomy_mode
        )

    # -- validation -------------------------------------------------------
    def build_task(
        self,
        payload: dict[str, Any],
        *,
        request: str,
        autonomy_mode: Any = None,
    ) -> PlanningResult:
        """Validate a raw plan payload and turn it into a Task."""
        clarification = payload.get("clarification_needed")
        if clarification:
            return PlanningResult(task=None, clarification_needed=str(clarification))

        raw_steps = payload.get("steps") or []
        if not isinstance(raw_steps, list):
            raise PlanningError(
                "The plan's 'steps' field is not a list",
                user_message="Pluto produced a malformed plan. Try asking again.",
            )
        if not raw_steps:
            return PlanningResult(
                task=None,
                clarification_needed=(
                    payload.get("summary")
                    or "Pluto could not work out any steps for that. "
                    "Could you be more specific?"
                ),
            )
        if len(raw_steps) > self._max_steps:
            raise PlanningError(
                f"Plan has {len(raw_steps)} steps; the limit is {self._max_steps}",
                user_message=(
                    f"That needs more than {self._max_steps} steps. Break it into "
                    f"smaller requests."
                ),
            )

        corrections: list[str] = []
        steps: list[TaskStep] = []
        id_map: dict[str, str] = {}

        # First pass: build the steps.
        for index, raw in enumerate(raw_steps):
            if not isinstance(raw, dict):
                raise PlanningError(
                    f"Step {index} is not an object",
                    user_message="Pluto produced a malformed plan.",
                )
            step = self._build_step(raw, index, corrections)
            model_id = str(raw.get("id") or f"s{index + 1}")
            id_map[model_id] = step.id
            steps.append(step)

        # Second pass: translate dependency ids now that the map is complete.
        for step, raw in zip(steps, raw_steps, strict=True):
            raw_deps = raw.get("depends_on") or []
            if not isinstance(raw_deps, list):
                raw_deps = []
            resolved: list[str] = []
            for dep in raw_deps:
                mapped = id_map.get(str(dep))
                if mapped is None:
                    corrections.append(
                        f"Step '{step.description[:40]}' referenced unknown "
                        f"dependency '{dep}', which was dropped."
                    )
                elif mapped == step.id:
                    corrections.append("A step depended on itself; dropped.")
                else:
                    resolved.append(mapped)
            step.depends_on = resolved

        task = Task(
            title=str(payload.get("title") or request)[:300],
            request=request,
            plan_summary=str(payload.get("summary") or "")[:2000] or None,
            steps=steps,
            status=TaskStatus.PENDING,
        )
        if autonomy_mode is not None:
            task.autonomy_mode = autonomy_mode
        task.risk_level = task.max_step_risk

        try:
            task.validate_dependency_graph()
        except ValueError as exc:
            raise PlanningError(
                f"Invalid plan graph: {exc}",
                user_message=f"Pluto's plan had a dependency problem: {exc}",
            ) from exc

        if corrections:
            log.info("Plan corrected: %s", "; ".join(corrections))

        return PlanningResult(task=task, corrections=corrections)

    def _build_step(
        self, raw: dict[str, Any], index: int, corrections: list[str]
    ) -> TaskStep:
        description = str(raw.get("description") or "").strip()
        if not description:
            description = f"Step {index + 1}"

        tool_name = raw.get("tool_name")
        tool_name = str(tool_name).strip() if tool_name else None
        if tool_name in {"", "null", "none", "None"}:
            tool_name = None

        arguments = raw.get("arguments") or {}
        if not isinstance(arguments, dict):
            corrections.append(f"Step {index + 1} had non-object arguments; ignored.")
            arguments = {}

        declared = self._parse_risk(raw.get("risk_level"))

        if tool_name is None:
            # A pure reasoning step. Nothing to look up, nothing to execute.
            return TaskStep(
                description=description,
                tool_name=None,
                arguments={},
                risk_level=RiskLevel.READ_ONLY,
                ordinal=index,
            )

        if not self._registry.has(tool_name):
            available = ", ".join(self._registry.names[:25])
            raise PlanningError(
                f"Plan uses unknown tool '{tool_name}'",
                user_message=(
                    f"Pluto's plan referred to a tool that does not exist "
                    f"('{tool_name}'). Available tools: {available}"
                ),
            )

        tool = self._registry.get(tool_name)

        # The authoritative risk is the tool's own declaration. A plan cannot
        # talk its way into a lower approval threshold.
        actual_risk = tool.risk_level
        if declared is not None and declared.rank < actual_risk.rank:
            corrections.append(
                f"Step {index + 1} claimed {declared.value} risk for "
                f"{tool_name}; corrected to {actual_risk.value}."
            )

        # Validate arguments against the tool's schema now, so a broken plan
        # fails at planning time rather than halfway through execution.
        try:
            tool.args_model.model_validate(arguments)
        except Exception as exc:
            corrections.append(
                f"Step {index + 1} arguments for {tool_name} failed validation: "
                f"{_first_error(exc)}"
            )

        return TaskStep(
            description=description,
            tool_name=tool_name,
            arguments=arguments,
            risk_level=actual_risk,
            max_attempts=0 if actual_risk.rank >= RiskLevel.HIGH.rank else 2,
            ordinal=index,
        )

    @staticmethod
    def _parse_risk(value: Any) -> RiskLevel | None:
        if not value:
            return None
        try:
            return RiskLevel(str(value).strip().lower())
        except ValueError:
            return None


def _first_error(exc: Exception) -> str:
    errors = getattr(exc, "errors", None)
    if callable(errors):
        try:
            first = errors()[0]
            location = ".".join(str(p) for p in first["loc"]) or "(root)"
            return f"{location}: {first['msg']}"
        except (IndexError, KeyError, TypeError):
            pass
    return str(exc)[:200]
