"""Static inspection of submitted messages and fetched pages.

Nothing here executes scripts, loads subresources, or submits forms. All text extracted
from pages or messages is attacker-controlled and is only ever returned as data.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urljoin

from teger_security_core.urls import UrlValidationError, extract_urls, normalize_url

_WS = re.compile(r"\s+")

PAYMENT_CHANGE = re.compile(
    r"\b(new|updated?|change[sd]?|chang(?:e|ing) (?:of|to)|different)\b.{0,40}\b(bank|account|remittance|payment|"
    r"iban|sort code|routing|wire)\b|\b(bank|payment|remittance) (details|information|instructions)\b",
    re.IGNORECASE,
)
PAYMENT_REQUEST = re.compile(r"\b(invoice|payment|pay|remit|transfer|outstanding|overdue)\b", re.IGNORECASE)
CREDENTIAL_REQUEST = re.compile(
    r"\b(sign[- ]?in|log[- ]?in|verify your (account|identity|mailbox)|re-?enter your password|"
    r"confirm your (password|credentials)|password)\b",
    re.IGNORECASE,
)
URGENCY = re.compile(r"\b(urgent(ly)?|immediately|today|within (24|48) hours|final notice|suspend(ed)?|"
                     r"expire[sd]?|as soon as possible|asap)\b", re.IGNORECASE)
# Text addressed to an AI system or trying to change its configuration.
AGENT_DIRECTED = re.compile(
    r"(ignore (all |any )?(previous|prior) instructions|\b(ai|llm|language model|security) (assistant|agent|"
    r"scanner|system)s?\b|classify (this|it) as (safe|legitimate)|add [\w.-]+ to (the )?(trusted|approved|allow)"
    r"|mark (this|it) as (safe|trusted)|system prompt)",
    re.IGNORECASE,
)
_PASSWORD_NAMES = re.compile(r"pass(word|wd|code)?|pin\b", re.IGNORECASE)
_PAYMENT_NAMES = re.compile(r"iban|account[_-]?(no|number)|sort[_-]?code|routing|swift|bic|card", re.IGNORECASE)


def collapse(text: str, limit: int) -> str:
    text = _WS.sub(" ", text or "").strip()
    return text if len(text) <= limit else text[: limit - 1] + "…"


def find_names(text: str, names: list[str]) -> list[str]:
    lowered = (text or "").lower()
    return [n for n in names if n and n.lower() in lowered]


# ------------------------------------------------------------------ messages

@dataclass(frozen=True)
class MessageFacts:
    links: list[str]
    link_hosts: list[str]
    sender_domain: str | None
    claimed_orgs: list[str]
    requests_payment_change: bool
    requests_payment: bool
    requests_credentials: bool
    urgency: bool
    agent_directed_text: str | None
    excerpt: str


def sender_domain(sender: str | None) -> str | None:
    if not sender:
        return None
    match = re.search(r"@([A-Za-z0-9.-]+\.[A-Za-z]{2,63})", sender)
    return match.group(1).lower().rstrip(".") if match else None


def inspect_message(text: str, sender: str | None, subject: str | None, known_orgs: list[str]) -> MessageFacts:
    body = f"{subject or ''}\n{text or ''}"
    urls = extract_urls(text or "", limit=10)
    agent = AGENT_DIRECTED.search(body)
    return MessageFacts(
        links=[u.normalized for u in urls],
        link_hosts=list(dict.fromkeys(u.host for u in urls)),
        sender_domain=sender_domain(sender),
        claimed_orgs=find_names(f"{sender or ''} {body}", known_orgs),
        requests_payment_change=bool(PAYMENT_CHANGE.search(body)),
        requests_payment=bool(PAYMENT_REQUEST.search(body)),
        requests_credentials=bool(CREDENTIAL_REQUEST.search(body)),
        urgency=bool(URGENCY.search(body)),
        agent_directed_text=collapse(body[max(0, agent.start() - 40): agent.end() + 80], 240) if agent else None,
        excerpt=collapse(text or "", 400),
    )


# ------------------------------------------------------------------ pages

@dataclass
class FormFacts:
    action: str | None
    action_host: str | None
    method: str
    field_names: list[str] = field(default_factory=list)
    has_password: bool = False
    has_payment_fields: bool = False


class _PageParser(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.title_parts: list[str] = []
        self.text_parts: list[str] = []
        self.hidden_text_parts: list[str] = []
        self.forms: list[FormFacts] = []
        self.meta_refresh: str | None = None
        self.script_count = 0
        self._in_title = False
        self._skip = 0  # inside script/style
        self._hidden_depth = 0
        self._stack: list[tuple[str, bool]] = []

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        hidden = "hidden" in a or "display:none" in a.get("style", "").replace(" ", "").lower() \
            or a.get("aria-hidden") == "true"
        if tag not in {"br", "img", "input", "meta", "link", "hr"}:
            self._stack.append((tag, hidden))
            if hidden:
                self._hidden_depth += 1
        if tag in {"script", "style", "noscript", "template"}:
            self._skip += 1
            if tag == "script":
                self.script_count += 1
        elif tag == "title":
            self._in_title = True
        elif tag == "meta" and a.get("http-equiv", "").lower() == "refresh":
            match = re.search(r"url\s*=\s*['\"]?([^'\";]+)", a.get("content", ""), re.IGNORECASE)
            if match:
                self.meta_refresh = urljoin(self.base_url, match.group(1).strip())
        elif tag == "form":
            action = urljoin(self.base_url, a.get("action", "")) if a.get("action") else self.base_url
            try:
                host = normalize_url(action).host
            except UrlValidationError:
                host = None
            self.forms.append(FormFacts(action=action[:300], action_host=host, method=a.get("method", "get").lower()))
        elif tag in {"input", "select", "textarea"} and self.forms:
            form = self.forms[-1]
            name = (a.get("name") or a.get("id") or a.get("autocomplete") or "")[:40]
            if name and len(form.field_names) < 20:
                form.field_names.append(name)
            if a.get("type", "").lower() == "password" or _PASSWORD_NAMES.search(name or ""):
                form.has_password = True
            if _PAYMENT_NAMES.search(name or "") or a.get("autocomplete", "").startswith("cc-"):
                form.has_payment_fields = True

    def handle_endtag(self, tag):
        if tag in {"script", "style", "noscript", "template"} and self._skip:
            self._skip -= 1
        if tag == "title":
            self._in_title = False
        for i in range(len(self._stack) - 1, -1, -1):
            if self._stack[i][0] == tag:
                for _, was_hidden in self._stack[i:]:
                    if was_hidden:
                        self._hidden_depth -= 1
                del self._stack[i:]
                break

    def handle_data(self, data):
        if self._in_title:
            self.title_parts.append(data)
        if self._skip:
            return
        (self.hidden_text_parts if self._hidden_depth else self.text_parts).append(data)


@dataclass(frozen=True)
class PageFacts:
    title: str
    text_excerpt: str
    claimed_orgs: list[str]
    forms: list[FormFacts]
    meta_refresh: str | None
    script_count: int
    agent_directed_text: str | None
    agent_directed_hidden: bool
    requests_credentials: bool
    requests_payment_change: bool


def inspect_page(html: str, base_url: str, known_orgs: list[str]) -> PageFacts:
    parser = _PageParser(base_url)
    try:
        parser.feed(html or "")
        parser.close()
    except Exception:  # malformed markup must not crash an investigation
        pass
    title = collapse(" ".join(parser.title_parts), 160)
    visible = collapse(" ".join(parser.text_parts), 4000)
    hidden = collapse(" ".join(parser.hidden_text_parts), 2000)
    agent_visible = AGENT_DIRECTED.search(visible)
    agent_hidden = AGENT_DIRECTED.search(hidden)
    agent_match, source = (agent_hidden, hidden) if agent_hidden else (agent_visible, visible)
    agent_text = None
    if agent_match:
        agent_text = collapse(source[max(0, agent_match.start() - 60): agent_match.end() + 120], 300)
    return PageFacts(
        title=title,
        text_excerpt=collapse(visible, 400),
        claimed_orgs=find_names(f"{title} {visible}", known_orgs),
        forms=parser.forms[:5],
        meta_refresh=parser.meta_refresh,
        script_count=parser.script_count,
        agent_directed_text=agent_text,
        agent_directed_hidden=bool(agent_hidden),
        requests_credentials=any(f.has_password for f in parser.forms) or bool(CREDENTIAL_REQUEST.search(title)),
        requests_payment_change=any(f.has_payment_fields for f in parser.forms) or bool(PAYMENT_CHANGE.search(visible)),
    )


def domain_matches(host: str, approved: str) -> bool:
    host, approved = host.lower().rstrip("."), approved.lower().rstrip(".")
    return host == approved or host.endswith("." + approved)


def lookalike_of(host: str, approved_domains: list[str]) -> str | None:
    """Approved domain whose distinctive label is embedded in ``host`` without matching it."""
    host = host.lower()
    for domain in approved_domains:
        if domain_matches(host, domain):
            continue
        label = domain.split(".")[0]
        if len(label) >= 5 and label in host:
            return domain
    return None
