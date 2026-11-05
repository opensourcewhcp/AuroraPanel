"""The Live Events search box: client_ip:1.2.3.4 AND rule_id:942100 AND status>=500.

Parsed by hand into SQL with bound values, so nothing typed here ever becomes part of the query text.
Field names come from a fixed list. A bare word searches the URL.
"""
from __future__ import annotations

import re

TEXT = {"client_ip", "peer_ip", "domain", "rule_id", "source", "action", "method", "severity", "account", "server", "confidence"}
LIKE = {"url", "user_agent", "tags"}
NUMBER = {"status", "anomaly_score", "response_size"}
FIELDS = sorted(TEXT | LIKE | NUMBER)
_TOKEN = re.compile(r'\s*(?:(?P<paren>[()])|(?P<field>[a-z_]+)(?P<op>>=|<=|!=|:|>|<|=)(?P<value>"[^"]*"|[^\s()]+)|(?P<word>"[^"]*"|[^\s()]+))')
MAX_LENGTH, MAX_TERMS = 500, 20


class QueryError(ValueError):
    pass


def _tokens(text: str) -> list[tuple]:
    pos, out = 0, []
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        if not m or m.end() == pos:
            if not text[pos:].strip():
                break
            raise QueryError(f"Can't read the search at: {text[pos:pos + 20]}")
        pos = m.end()
        if m.group("paren"):
            out.append(("paren", m.group("paren")))
        elif m.group("field"):
            out.append(("term", m.group("field"), m.group("op"), m.group("value").strip('"')))
        else:
            word = m.group("word")
            out.append(("op", word.upper()) if word.upper() in ("AND", "OR", "NOT") else ("word", word.strip('"')))
    return out


def _term(field: str, op: str, value: str) -> tuple[str, list]:
    if field in NUMBER:
        if not re.fullmatch(r"\d{1,12}", value):
            raise QueryError(f"{field} takes a number")
        sql = {":": "=", "=": "=", "!=": "!=", ">": ">", "<": "<", ">=": ">=", "<=": "<="}[op]
        return f"{field} {sql} ?", [int(value)]
    if field in TEXT:
        if op in (":", "="):
            return f"{field} = ?", [value]
        if op == "!=":
            return f"({field} IS NULL OR {field} != ?)", [value]
    elif field in LIKE:
        if op in (":", "="):
            return f"{field} LIKE ? ESCAPE '\\'", [_like(value)]
        if op == "!=":
            return f"({field} IS NULL OR {field} NOT LIKE ? ESCAPE '\\')", [_like(value)]
    else:
        raise QueryError(f"Unknown field: {field}. Fields: {', '.join(FIELDS)}")
    raise QueryError(f"{field} can't be compared with {op}")


def _like(value: str) -> str:
    return "%" + value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


class _Parser:
    def __init__(self, toks: list[tuple]):
        self.toks, self.i, self.args, self.terms = toks, 0, [], 0

    def peek(self):
        return self.toks[self.i] if self.i < len(self.toks) else None

    def take(self):
        self.i += 1
        return self.toks[self.i - 1]

    def expr(self) -> str:
        left = self.conj()
        while self.peek() == ("op", "OR"):
            self.take()
            left = f"({left} OR {self.conj()})"
        return left

    def conj(self) -> str:
        left = self.unary()
        while True:
            t = self.peek()
            if t == ("op", "AND"):
                self.take()
            elif t is None or t == ("op", "OR") or t == ("paren", ")"):
                return left
            left = f"({left} AND {self.unary()})"

    def unary(self) -> str:
        t = self.peek()
        if t is None:
            raise QueryError("The search ends too early")
        if t == ("op", "NOT"):
            self.take()
            return f"(NOT COALESCE({self.unary()}, 0))"
        if t == ("paren", "("):
            self.take()
            inner = self.expr()
            if self.peek() != ("paren", ")"):
                raise QueryError("A bracket isn't closed")
            self.take()
            return inner
        self.terms += 1
        if self.terms > MAX_TERMS:
            raise QueryError(f"Too many conditions ({MAX_TERMS} at most)")
        self.take()
        if t[0] == "term":
            sql, args = _term(t[1], t[2], t[3])
        elif t[0] == "word":
            sql, args = _term("url", ":", t[1])
        else:
            raise QueryError("Unexpected word in the search")
        self.args += args
        return sql


def compile_query(text: str) -> tuple[str, list]:
    """(SQL condition, values). Empty text is no condition."""
    text = (text or "").strip()
    if not text:
        return "", []
    if len(text) > MAX_LENGTH:
        raise QueryError(f"The search is too long ({MAX_LENGTH} characters at most)")
    p = _Parser(_tokens(text))
    sql = p.expr()
    if p.peek() is not None:
        raise QueryError("Unexpected text at the end of the search")
    return sql, p.args
