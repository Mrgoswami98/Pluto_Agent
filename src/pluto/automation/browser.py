"""Browser automation tools, built on Playwright.

Policy, from spec §6:

* The browser is **visible by default**. Hidden automation is not a feature.
* Only domains on the allow-list may be visited; everything else is refused
  before a request is made.
* Page content is untrusted data and is wrapped as such.
* Credentials, cookies and tokens are never extracted.
* MFA, CAPTCHA and other human checks pause for the user; the agent does not
  attempt to solve or bypass them.
* Submitting a form is an always-confirm action.
"""

from __future__ import annotations

import re
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any, ClassVar, TypeVar
from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_validator

from pluto.core.constants import RiskLevel, ToolCategory
from pluto.core.exceptions import BrowserAutomationError, PermissionDeniedError
from pluto.core.logging_config import get_logger
from pluto.core.models import ToolResult
from pluto.security.untrusted import wrap as wrap_untrusted
from pluto.tools.registry import Tool, ToolContext

log = get_logger("automation.browser")

_T = TypeVar("_T")

#: Fields we refuse to fill, because filling them means handling a credential.
_SENSITIVE_FIELD = re.compile(
    r"(?i)\b(?:password|passwd|pwd|pin|cvv|cvc|card[\s_-]?number|ssn|otp|"
    r"security[\s_-]?code|secret)\b"
)

#: Page markers suggesting a human verification step is in the way.
_HUMAN_CHECK = re.compile(
    r"(?i)\b(?:captcha|recaptcha|hcaptcha|cloudflare|verify you are human|"
    r"two[- ]factor|2fa|one[- ]time (?:code|password)|security challenge|"
    r"i am not a robot)\b"
)


class DomainPolicy:
    """Allow-list for web access. Default deny."""

    def __init__(self, allowed_domains: list[str] | None = None) -> None:
        self._domains = [d.lower().lstrip(".") for d in (allowed_domains or [])]

    @property
    def domains(self) -> list[str]:
        return list(self._domains)

    def allow(self, domain: str) -> None:
        cleaned = domain.lower().lstrip(".").strip()
        if cleaned and cleaned not in self._domains:
            self._domains.append(cleaned)

    def revoke(self, domain: str) -> bool:
        cleaned = domain.lower().lstrip(".")
        if cleaned in self._domains:
            self._domains.remove(cleaned)
            return True
        return False

    def check(self, url: str) -> str:
        """Return the host if permitted; raise otherwise."""
        parsed = urlparse(url if "://" in url else f"https://{url}")

        if parsed.scheme not in {"http", "https"}:
            raise PermissionDeniedError(
                f"Refusing scheme '{parsed.scheme}'",
                user_message=(
                    "Pluto only opens http and https pages. "
                    f"'{parsed.scheme}:' is not allowed."
                ),
            )

        host = (parsed.hostname or "").lower()
        if not host:
            raise PermissionDeniedError(
                f"Could not read a hostname from '{url}'",
                user_message="That does not look like a valid web address.",
            )

        if not self._domains:
            raise PermissionDeniedError(
                "No domains are approved",
                user_message=(
                    "No websites are approved yet. Add the site under "
                    "Settings → Permissions before asking Pluto to browse."
                ),
            )

        for allowed in self._domains:
            # Exact host, or a subdomain of an allowed domain. The leading dot
            # is what stops "evil-example.com" matching "example.com".
            if host == allowed or host.endswith(f".{allowed}"):
                return host

        raise PermissionDeniedError(
            f"Domain '{host}' is not approved",
            user_message=(
                f"'{host}' is not on your approved list. Add it under "
                f"Settings → Permissions if you want Pluto to visit it."
            ),
        )

    def is_allowed(self, url: str) -> bool:
        try:
            self.check(url)
        except PermissionDeniedError:
            return False
        return True


@dataclass
class PageSnapshot:
    """What the agent is allowed to know about a page."""

    url: str
    title: str
    text: str
    links: list[dict[str, str]]
    forms: list[dict[str, Any]]
    human_check_detected: bool = False


class BrowserSession:
    """Owns the Playwright browser, on a dedicated thread.

    Playwright's synchronous API is **thread-affine**: every call must happen on
    the thread that started it, or greenlet raises "cannot switch to a different
    thread". Pluto calls tools from a worker pool (to enforce timeouts) and from
    the Qt GUI thread, so the session owns a single-worker executor and marshals
    every browser operation onto it via :meth:`run`.

    Tools must therefore never touch ``_page`` directly; they pass a callable to
    :meth:`run`, which receives the live page.
    """

    def __init__(
        self,
        policy: DomainPolicy,
        *,
        headless: bool = False,
        timeout_seconds: int = 45,
        user_data_dir: str | None = None,
    ) -> None:
        self.policy = policy
        self.headless = headless
        self.timeout_ms = timeout_seconds * 1000
        self._user_data_dir = user_data_dir
        self._playwright: Any = None
        self._browser: Any = None
        self._page: Any = None
        self._lock = threading.RLock()
        self._executor = ThreadPoolExecutor(
            max_workers=1, thread_name_prefix="pluto-browser"
        )
        self._started = False

    @property
    def is_running(self) -> bool:
        return self._started and self._browser is not None

    # -- lifecycle --------------------------------------------------------
    def run(self, operation: Callable[[Any], _T], *, timeout: float | None = None) -> _T:
        """Run *operation(page)* on the browser thread and return its result.

        Exceptions raised inside the operation propagate to the caller
        unchanged, so a PermissionDeniedError from a tool still surfaces.
        """
        self.start()
        future = self._executor.submit(self._invoke, operation)
        return future.result(timeout=timeout or (self.timeout_ms / 1000) + 30)

    def _invoke(self, operation: Callable[[Any], _T]) -> _T:
        return operation(self._page)

    def start(self) -> None:
        """Start the browser on its own thread. Idempotent."""
        with self._lock:
            if self._started and self._browser is not None:
                return
            self._executor.submit(self._start_on_thread).result(timeout=120)
            self._started = True

    def _start_on_thread(self) -> None:
        if self._browser is not None:
            return
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as exc:
            raise BrowserAutomationError(
                "Playwright is not installed",
                user_message=(
                    "Browser automation needs Playwright. Run "
                    "'pip install playwright' then 'playwright install chromium'."
                ),
            ) from exc

        try:
            self._playwright = sync_playwright().start()
            self._browser = self._playwright.chromium.launch(
                headless=self.headless,
                args=["--disable-blink-features=AutomationControlled"],
            )
            self._page = self._browser.new_page()
            self._page.set_default_timeout(self.timeout_ms)
        except Exception as exc:
            self._teardown_on_thread()
            raise BrowserAutomationError(
                f"Could not start the browser: {exc}",
                user_message=(
                    "Pluto could not start the browser. If this is a fresh "
                    "install, run 'playwright install chromium'."
                ),
                detail=str(exc)[:500],
            ) from exc

    def stop(self) -> None:
        """Close the browser. Safe to call from any thread, and twice."""
        with self._lock:
            if not self._started:
                return
            try:
                self._executor.submit(self._teardown_on_thread).result(timeout=30)
            except Exception as exc:  # pragma: no cover - shutdown best effort
                log.debug("Browser teardown raised: %s", exc)
            self._started = False

    def _teardown_on_thread(self) -> None:
        for handle, closer in (
            (self._page, "close"),
            (self._browser, "close"),
            (self._playwright, "stop"),
        ):
            if handle is None:
                continue
            try:
                getattr(handle, closer)()
            except Exception:
                pass
        self._page = self._browser = self._playwright = None

    def shutdown(self) -> None:
        """Stop the browser and retire its thread."""
        self.stop()
        self._executor.shutdown(wait=False, cancel_futures=True)

    # -- reading ----------------------------------------------------------
    def snapshot(self, *, max_chars: int = 40_000) -> PageSnapshot:
        """Read the current page. Never touches cookies or storage."""
        return self.run(lambda page: self._snapshot_on_thread(page, max_chars))

    @classmethod
    def _snapshot_on_thread(cls, page: Any, max_chars: int) -> PageSnapshot:
        try:
            text = page.inner_text("body")[:max_chars]
        except Exception:
            text = ""
        try:
            title = page.title()
        except Exception:
            title = ""

        links: list[dict[str, str]] = []
        try:
            for element in page.query_selector_all("a[href]")[:100]:
                href = element.get_attribute("href") or ""
                label = (element.inner_text() or "").strip()[:100]
                if href:
                    links.append({"text": label, "href": href})
        except Exception:
            pass

        return PageSnapshot(
            url=page.url,
            title=title,
            text=text,
            links=links,
            forms=cls._describe_forms(page),
            human_check_detected=bool(_HUMAN_CHECK.search(f"{title} {text[:5000]}")),
        )

    @property
    def current_url(self) -> str:
        return self.run(lambda page: page.url)

    def set_content(self, html: str) -> None:
        """Load HTML directly. Used by tests and by local report previews."""
        self.run(lambda page: page.set_content(html))

    @staticmethod
    def _describe_forms(page: Any) -> list[dict[str, Any]]:
        """Describe form fields by name and type, never by value."""
        forms: list[dict[str, Any]] = []
        try:
            for form in page.query_selector_all("form")[:10]:
                fields = []
                for field in form.query_selector_all("input, select, textarea")[:40]:
                    name = field.get_attribute("name") or field.get_attribute("id") or ""
                    field_type = (field.get_attribute("type") or field.evaluate(
                        "el => el.tagName.toLowerCase()"
                    ) or "text")
                    fields.append(
                        {
                            "name": name,
                            "type": field_type,
                            "sensitive": bool(
                                _SENSITIVE_FIELD.search(f"{name} {field_type}")
                            ),
                        }
                    )
                forms.append({"action": form.get_attribute("action") or "", "fields": fields})
        except Exception:
            pass
        return forms


class BrowserTool(Tool[Any]):
    """Base for browser tools."""

    def __init__(self, session: BrowserSession) -> None:
        self.session = session


# --------------------------------------------------------------------------
# Navigate
# --------------------------------------------------------------------------
class NavigateArgs(BaseModel):
    url: str = Field(min_length=3, max_length=2000)
    wait_for: str | None = Field(
        default=None, description="Optional CSS selector to wait for."
    )

    @field_validator("url")
    @classmethod
    def _reject_dangerous_schemes(cls, value: str) -> str:
        lowered = value.strip().lower()
        for scheme in ("javascript:", "data:", "file:", "vbscript:", "about:"):
            if lowered.startswith(scheme):
                raise ValueError(f"'{scheme}' URLs are not allowed")
        return value.strip()


class NavigateTool(BrowserTool):
    name: ClassVar[str] = "browser.navigate"
    description: ClassVar[str] = (
        "Open a web page in the visible browser and report what is on it. "
        "Only approved domains can be opened."
    )
    category: ClassVar[ToolCategory] = ToolCategory.BROWSER
    risk_level: ClassVar[RiskLevel] = RiskLevel.MEDIUM
    action_kind: ClassVar[str] = "browse_web"
    args_model: ClassVar[type[BaseModel]] = NavigateArgs
    timeout_seconds: ClassVar[int] = 90
    requires_network: ClassVar[bool] = True

    def run(self, args: NavigateArgs, context: ToolContext) -> ToolResult:
        # Domain check happens before the browser is touched at all.
        host = self.session.policy.check(args.url)
        context.check_cancelled()

        def navigate(page: Any) -> tuple[Any, PageSnapshot]:
            response = page.goto(args.url, wait_until="domcontentloaded")
            if args.wait_for:
                page.wait_for_selector(args.wait_for, state="attached")
            return response, BrowserSession._snapshot_on_thread(page, 40_000)

        try:
            response, snapshot = self.session.run(navigate)
        except Exception as exc:
            return ToolResult.fail(
                f"Could not open {host}: {_short(exc)}",
                summary=f"Navigation to {host} failed",
            )

        status = getattr(response, "status", None)

        if snapshot.human_check_detected:
            return ToolResult.ok(
                output={
                    "url": snapshot.url,
                    "title": snapshot.title,
                    "human_verification_required": True,
                },
                summary=(
                    f"{host} is showing a human-verification step (CAPTCHA, 2FA or "
                    f"similar). Pluto has stopped — please complete it in the "
                    f"browser window, then tell Pluto to continue."
                ),
                verified=False,
                verification_note="Blocked by a human-verification challenge.",
            )

        wrapped, assessment = wrap_untrusted(
            snapshot.text, source=snapshot.url, content_type="webpage"
        )

        return ToolResult.ok(
            output={
                "url": snapshot.url,
                "title": snapshot.title,
                "status_code": status,
                "content": wrapped,
                "links": snapshot.links[:40],
                "forms": snapshot.forms,
                "suspicious_content": assessment.is_suspicious,
            },
            summary=(
                f"Opened {snapshot.title or host} ({status})"
                + (
                    " — page contains instruction-like text, treated as data"
                    if assessment.is_suspicious
                    else ""
                )
            ),
        )

    def verify(self, args: NavigateArgs, result: ToolResult, context: ToolContext) -> ToolResult:
        """Confirm we landed on the host we asked for, not a redirect elsewhere."""
        if not result.success:
            return result
        if result.output.get("human_verification_required"):
            return result

        requested = urlparse(
            args.url if "://" in args.url else f"https://{args.url}"
        ).hostname or ""
        landed = urlparse(result.output.get("url", "")).hostname or ""

        same = (
            landed == requested
            or landed.endswith(f".{requested}")
            or requested.endswith(f".{landed}")
        )
        result.verified = bool(landed) and same
        result.verification_note = (
            f"Landed on {landed}, as requested."
            if result.verified
            else f"Requested {requested} but ended up on {landed or 'nowhere'}."
        )
        if not result.verified and landed:
            log.warning("Navigation redirected: %s -> %s", requested, landed)
        return result


# --------------------------------------------------------------------------
# Extract
# --------------------------------------------------------------------------
class ExtractArgs(BaseModel):
    selector: str | None = Field(
        default=None, description="CSS selector. Omit for the whole page."
    )
    max_characters: int = Field(default=20_000, ge=100, le=100_000)


class ExtractContentTool(BrowserTool):
    name: ClassVar[str] = "browser.extract"
    description: ClassVar[str] = (
        "Read text from the page currently open in the browser, optionally "
        "narrowed to a CSS selector."
    )
    category: ClassVar[ToolCategory] = ToolCategory.BROWSER
    risk_level: ClassVar[RiskLevel] = RiskLevel.READ_ONLY
    action_kind: ClassVar[str] = "read_web_content"
    args_model: ClassVar[type[BaseModel]] = ExtractArgs
    timeout_seconds: ClassVar[int] = 60
    requires_network: ClassVar[bool] = True

    def run(self, args: ExtractArgs, context: ToolContext) -> ToolResult:
        if not self.session.is_running:
            return ToolResult.fail("No page is open. Navigate to a page first.")

        def extract(page: Any) -> tuple[str | None, str]:
            if args.selector:
                elements = page.query_selector_all(args.selector)
                if not elements:
                    return None, page.url
                text = "\n\n".join(
                    (e.inner_text() or "") for e in elements[:50]
                )[: args.max_characters]
            else:
                text = page.inner_text("body")[: args.max_characters]
            return text, page.url

        try:
            text, url = self.session.run(extract)
        except Exception as exc:
            return ToolResult.fail(f"Could not read the page: {_short(exc)}")

        if text is None:
            return ToolResult.fail(f"Nothing on the page matches '{args.selector}'.")

        wrapped, assessment = wrap_untrusted(text, source=url, content_type="webpage")
        return ToolResult.ok(
            output={"content": wrapped, "url": url,
                    "suspicious_content": assessment.is_suspicious},
            summary=f"Read {len(text):,} characters from {urlparse(url).hostname or 'the page'}",
            verified=True,
            verification_note="Text read from the live page.",
        )


# --------------------------------------------------------------------------
# Fill
# --------------------------------------------------------------------------
class FillFieldArgs(BaseModel):
    selector: str = Field(min_length=1, max_length=500)
    value: str = Field(max_length=5000)


class FillFormTool(BrowserTool):
    name: ClassVar[str] = "browser.fill"
    description: ClassVar[str] = (
        "Type a value into a form field. Refuses password, PIN, card and other "
        "credential fields."
    )
    category: ClassVar[ToolCategory] = ToolCategory.BROWSER
    risk_level: ClassVar[RiskLevel] = RiskLevel.MEDIUM
    action_kind: ClassVar[str] = "fill_form"
    args_model: ClassVar[type[BaseModel]] = FillFieldArgs
    timeout_seconds: ClassVar[int] = 45
    requires_network: ClassVar[bool] = True

    def run(self, args: FillFieldArgs, context: ToolContext) -> ToolResult:
        if not self.session.is_running:
            return ToolResult.fail("No page is open. Navigate to a page first.")

        def inspect(page: Any) -> dict[str, str] | None:
            element = page.query_selector(args.selector)
            if element is None:
                return None
            return {
                "name": element.get_attribute("name") or "",
                "id": element.get_attribute("id") or "",
                "type": element.get_attribute("type") or "",
            }

        try:
            info = self.session.run(inspect)
        except Exception as exc:
            return ToolResult.fail(f"Could not look up '{args.selector}': {_short(exc)}")

        if info is None:
            return ToolResult.fail(f"No field matches '{args.selector}'.")

        # Refuse credential fields, whatever the caller asked for. This is
        # checked before anything is typed.
        descriptor = f"{info['name']} {info['id']} {info['type']} {args.selector}"
        if info["type"].lower() == "password" or _SENSITIVE_FIELD.search(descriptor):
            raise PermissionDeniedError(
                f"Refusing to fill a credential field: {info['name'] or args.selector}",
                user_message=(
                    "Pluto will not type passwords, PINs or card details into a "
                    "web page. Please fill that field yourself in the browser window."
                ),
            )

        try:
            self.session.run(lambda page: page.fill(args.selector, args.value))
        except Exception as exc:
            return ToolResult.fail(f"Could not fill the field: {_short(exc)}")

        return ToolResult.ok(
            output={"selector": args.selector, "field_name": info["name"]},
            summary=f"Filled '{info['name'] or args.selector}'",
        )

    def verify(self, args: FillFieldArgs, result: ToolResult, context: ToolContext) -> ToolResult:
        """Read the field back and confirm the value took."""
        if not result.success:
            return result
        try:
            actual = self.session.run(lambda page: page.input_value(args.selector))
        except Exception as exc:
            result.verified = False
            result.verification_note = f"Could not read the field back: {_short(exc)}"
            return result

        result.verified = actual == args.value
        result.verification_note = (
            "Field contains exactly the value that was typed."
            if result.verified
            else "The field does not contain the value that was typed."
        )
        return result


# --------------------------------------------------------------------------
# Click
# --------------------------------------------------------------------------
class ClickArgs(BaseModel):
    selector: str = Field(min_length=1, max_length=500)
    expect_navigation: bool = False


class ClickTool(BrowserTool):
    name: ClassVar[str] = "browser.click"
    description: ClassVar[str] = "Click an element on the current page."
    category: ClassVar[ToolCategory] = ToolCategory.BROWSER
    risk_level: ClassVar[RiskLevel] = RiskLevel.MEDIUM
    action_kind: ClassVar[str] = "click_element"
    args_model: ClassVar[type[BaseModel]] = ClickArgs
    timeout_seconds: ClassVar[int] = 60
    requires_network: ClassVar[bool] = True

    def run(self, args: ClickArgs, context: ToolContext) -> ToolResult:
        if not self.session.is_running:
            return ToolResult.fail("No page is open. Navigate to a page first.")

        def click(page: Any) -> tuple[str | None, str, str]:
            before = page.url
            element = page.query_selector(args.selector)
            if element is None:
                return None, before, before
            label = (element.inner_text() or "").strip()[:80]
            element.click()
            if args.expect_navigation:
                page.wait_for_load_state("domcontentloaded")
            return label, before, page.url

        try:
            label, before, after = self.session.run(click)
        except Exception as exc:
            return ToolResult.fail(f"Could not click: {_short(exc)}")

        if label is None:
            return ToolResult.fail(f"Nothing matches '{args.selector}'.")

        # A click can navigate somewhere not on the allow-list.
        if after != before and not self.session.policy.is_allowed(after):
            host = urlparse(after).hostname
            log.warning("Click navigated off the allow-list to %s", host)
            try:
                self.session.run(lambda page: page.go_back())
            except Exception:
                pass
            return ToolResult.fail(
                f"That click led to '{host}', which is not approved. Pluto went back."
            )

        return ToolResult.ok(
            output={"selector": args.selector, "label": label,
                    "url_before": before, "url_after": after,
                    "navigated": before != after},
            summary=f"Clicked '{label or args.selector}'",
        )

    def verify(self, args: ClickArgs, result: ToolResult, context: ToolContext) -> ToolResult:
        if not result.success:
            return result
        navigated = result.output.get("navigated", False)
        if args.expect_navigation:
            result.verified = navigated
            result.verification_note = (
                f"Page moved to {result.output['url_after']}."
                if navigated
                else "A navigation was expected but the URL did not change."
            )
        else:
            result.verified = True
            result.verification_note = "Click dispatched; page state read back."
        return result


# --------------------------------------------------------------------------
# Submit — always requires confirmation
# --------------------------------------------------------------------------
class SubmitArgs(BaseModel):
    selector: str = Field(default="form", max_length=500)


class SubmitFormTool(BrowserTool):
    name: ClassVar[str] = "browser.submit"
    description: ClassVar[str] = (
        "Submit a form. This has a real external effect, so it always needs "
        "your explicit confirmation."
    )
    category: ClassVar[ToolCategory] = ToolCategory.BROWSER
    risk_level: ClassVar[RiskLevel] = RiskLevel.HIGH
    action_kind: ClassVar[str] = "submit_form"
    args_model: ClassVar[type[BaseModel]] = SubmitArgs
    timeout_seconds: ClassVar[int] = 90
    requires_network: ClassVar[bool] = True

    def run(self, args: SubmitArgs, context: ToolContext) -> ToolResult:
        if not self.session.is_running:
            return ToolResult.fail("No page is open. Navigate to a page first.")

        def submit(page: Any) -> tuple[bool, str, str, str]:
            before = page.url
            form = page.query_selector(args.selector)
            if form is None:
                return False, before, before, ""
            form.evaluate("f => f.requestSubmit ? f.requestSubmit() : f.submit()")
            page.wait_for_load_state("domcontentloaded")
            try:
                title = page.title()
            except Exception:
                title = ""
            return True, before, page.url, title

        try:
            found, before, after, title = self.session.run(submit)
        except Exception as exc:
            return ToolResult.fail(f"Could not submit the form: {_short(exc)}")

        if not found:
            return ToolResult.fail(f"No form matches '{args.selector}'.")

        return ToolResult.ok(
            output={"url_before": before, "url_after": after, "title_after": title},
            summary=f"Submitted the form; now at {urlparse(after).hostname or after}",
        )

    def verify(self, args: SubmitArgs, result: ToolResult, context: ToolContext) -> ToolResult:
        """A submission is only verified if the page actually changed."""
        if not result.success:
            return result
        changed = result.output["url_before"] != result.output["url_after"]
        result.verified = changed
        result.verification_note = (
            f"Page moved to {result.output['url_after']} after submitting."
            if changed
            else (
                "The URL did not change after submitting, so Pluto cannot confirm "
                "the form was accepted. Check the page yourself."
            )
        )
        return result


def _short(exc: Exception) -> str:
    return str(exc).split("\n")[0][:200]


def build_browser_tools(session: BrowserSession) -> list[Tool[Any]]:
    return [
        NavigateTool(session),
        ExtractContentTool(session),
        FillFormTool(session),
        ClickTool(session),
        SubmitFormTool(session),
    ]
