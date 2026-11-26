#!/usr/bin/env python3
"""Turns a "Propose rules" issue into a rule file change. Used by .github/workflows/propose.yml.

    ISSUE_BODY=<the issue body> python tools/propose.py [--check]

Reads the issue form (### Site / ### Rules / ### Deny hosts / ### Allow hosts), checks every line with lint.py and
merges the accepted lines into sites/<c>/<domain>.txt. Writes a Markdown report to stdout and, in the workflow,
the results to $GITHUB_OUTPUT: status (ok | review | rejected | invalid), path, domain. When the proposal is
accepted, the author's "What the rules do" goes to what.md, a ready Markdown section for the pull request.
The issue body is untrusted text: it is only parsed here, never executed and never put into a command line.
"""
import datetime
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lint  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NO_RESPONSE = "_No response_"
WHAT_FILE = "what.md"
WHAT_LIMIT = 2000


def form_fields(body):
    """{heading: text} of a GitHub issue form body"""
    fields = {}
    current = None
    for line in body.replace("\r\n", "\n").split("\n"):
        m = re.match(r"^###\s+(.+?)\s*$", line)
        if m:
            current = m.group(1).strip().lower()
            fields[current] = []
        elif current is not None:
            fields[current].append(line)
    return {k: "\n".join(v).strip() for k, v in fields.items()}


def lines_of(value):
    """the lines of a textarea: code fences and the placeholder of an empty field are dropped"""
    if not value or value.strip() == NO_RESPONSE:
        return []
    out = []
    for line in value.split("\n"):
        line = line.strip()
        if not line or line.startswith("```"):
            continue
        out.append(line)
    return out


def site_of(value):
    """the domain from the Site field: lower case, no scheme, no path, no www."""
    site = (value or "").strip().split()[0].lower() if (value or "").strip() else ""
    site = re.sub(r"^[a-z][a-z0-9+.-]*://", "", site).split("/")[0].split(":")[0]
    if site.startswith("www."):
        site = site[4:]
    return site


def sections_of(path):
    """the existing file: header lines and the lines of each section, in order"""
    header, sections = [], {s: [] for s in lint.SECTIONS}
    if not os.path.exists(path):
        return header, sections
    section = None
    with open(path, encoding="utf-8") as f:
        for raw in f.read().replace("\r\n", "\n").split("\n"):
            line = raw.rstrip()
            name = line.strip()[1:-1].strip().lower() if line.strip().startswith("[") and line.strip().endswith("]") else None
            if name in lint.SECTIONS:
                section = name
            elif section is None:
                if line.strip():
                    header.append(line)
            elif line.strip():
                sections[section].append(line)
    return header, sections


def code(text, limit=160):
    """text for the bot's answer as a Markdown code span: the reasons and file errors carry pieces of the author's
    lines, and outside a code span "[x](link)", "![img](...)" or "@user" would be a link, an image or a mention
    written by the bot. Backticks become quotes, so the text cannot close the span; one line, cut to limit."""
    text = " ".join(str(text).split())
    if len(text) > limit:
        text = text[:limit] + "..."
    return "`%s`" % text.replace("`", "'")


def what_section(value):
    """the "What the rules do" field as a Markdown section for the pull request, or "" when it is empty.
    The text is the issue author's: it goes into a code block, where @mentions, links, images and other markup do
    nothing. The fence is longer than any run of backticks in the text, so the text cannot close the block."""
    text = (value or "").strip()
    if not text or text == NO_RESPONSE:
        return ""
    if len(text) > WHAT_LIMIT:
        text = text[:WHAT_LIMIT].rstrip() + "\n[...]"
    fence = "`" * max(3, max((len(run) for run in re.findall(r"`+", text)), default=0) + 1)
    return "### What the rules do\n\n%stext\n%s\n%s\n" % (fence, text, fence)


COMMENT_LIMIT = lint.MAX_COMMENT


def comment_for(repository, issue, what):
    """The comment lines put above the lines of one proposal in each section, as public filter lists usually do:
    the full link to the issue, then the first line of "What the rules do" (control characters dropped, the line cut
    to COMMENT_LIMIT). Either line is left out when there is nothing for it or the checker would refuse it."""
    lines = []
    if re.match(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", repository or "") and str(issue or "").isdigit():
        lines.append("! https://github.com/%s/issues/%s" % (repository, issue))
    text = ""
    for line in (what or "").split("\n"):
        line = " ".join("".join(c for c in line if c.isprintable()).split())
        if line and line != NO_RESPONSE:
            text = line
            break
    if len(text) > COMMENT_LIMIT - 2:
        text = text[:COMMENT_LIMIT - 5].rstrip() + "..."
    # "! Target: ..." is the header of the file, not a comment; personal data stays out of the file
    if text and not re.match(r"^target\s*:", text, re.I) and lint.check_comment("! " + text)[0] != lint.REJECT:
        lines.append("! " + text)
    return lines


without_empty_blocks = lint.without_empty_blocks


def render(domain, sections):
    out = ["! Title: " + domain, "! Target: site " + domain, "! Updated: " + datetime.date.today().isoformat()]
    for name in lint.SECTIONS:
        if sections[name]:
            out += ["", "[%s]" % name] + sections[name]
    return "\n".join(out) + "\n"


def main(argv):
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")   # the report goes into a Markdown file
    body = os.environ.get("ISSUE_BODY", "")
    fields = form_fields(body)
    domain = site_of(fields.get("site", ""))
    outputs = {"status": "invalid", "path": "", "domain": domain}
    report = []

    def finish(code):
        target = os.environ.get("GITHUB_OUTPUT")
        if target and "--check" not in argv:
            with open(target, "a", encoding="utf-8") as f:
                for k, v in outputs.items():
                    f.write("%s=%s\n" % (k, v))
        sys.stdout.write("\n".join(report) + "\n")
        return code

    if "site" not in fields:
        report.append("The issue does not follow the **Propose rules** form: there is no `### Site` heading. Open it with "
                      "the form, or write the body with the form's headings, each on its own line: `### Site`, `### Rules`, "
                      "`### Deny hosts`, `### Allow hosts`, `### What the rules do`. Edit the issue - it will be checked again.")
        return finish(1)
    if not lint.is_host(domain):
        report.append("The **Site** field must be a domain like `example.com`; got %s." % code(fields.get("site", ""), 80))
        return finish(1)

    proposed = {"rules": lines_of(fields.get("rules", "")), "deny": lines_of(fields.get("deny hosts", "")),
                "allow": lines_of(fields.get("allow hosts", ""))}
    if not any(proposed.values()):
        report.append("The proposal has no rules.")
        return finish(1)

    text = "! Target: site %s\n" % domain + "".join("[%s]\n%s\n" % (s, "\n".join(proposed[s])) for s in lint.SECTIONS if proposed[s])
    checked = lint.lint_text(text, domain)
    rejected = [l for l in checked["lines"] if l["verdict"] == lint.REJECT]
    review = [l for l in checked["lines"] if l["verdict"] == lint.REVIEW]
    report.append("Checked %d line(s)%s for `%s`: %d ok, %d need a maintainer's review, %d rejected." % (
        len(checked["lines"]), " and %d comment(s)" % checked["comments"] if checked["comments"] else "", domain,
        checked["counts"][lint.OK], len(review), len(rejected)))
    for e in checked["errors"]:
        report.append("- file: %s" % code(e))
    for l in rejected:
        report.append("- rejected %s — %s" % (code(l["text"], 120), code(l["reason"])))
    for l in review:
        report.append("- review %s — %s" % (code(l["text"], 120), code(l["reason"])))
    if rejected or checked["errors"]:
        outputs["status"] = "rejected"
        report.append("")
        report.append("Nothing was changed. Fix the rejected lines (see FORMAT.md) and edit the issue - it will be checked again.")
        return finish(1)

    rel = "sites/%s/%s.txt" % (domain[0], domain)
    path = os.path.join(ROOT, rel)
    _header, sections = sections_of(path)
    added = 0
    comment = comment_for(os.environ.get("GITHUB_REPOSITORY", ""), os.environ.get("ISSUE", ""), fields.get("what the rules do", ""))
    for name in lint.SECTIONS:
        # rules already in the file are dropped together with their comments; directives are kept and the blocks
        # left empty are removed
        have = set(l.strip() for l in sections[name] if not l.strip().startswith("!"))

        def fresh(line):
            if line in have:
                return False
            have.add(line)
            return True
        new = lint.select_with_comments(checked["accepted"][name], fresh)
        rules = sum(1 for l in new if not l.startswith("!"))
        if rules:
            sections[name] += comment + new
            added += rules
    merged = render(domain, sections)
    final = lint.lint_text(merged, domain)
    if lint.failed(final):
        outputs["status"] = "rejected"
        report.append("Together with the rules already in `%s` the file does not pass the checker:" % rel)
        report += ["- %s" % code(e) for e in final["errors"]]
        return finish(1)
    if added == 0:
        outputs["status"] = "invalid"
        report.append("Every proposed line is already in `%s`." % rel)
        return finish(1)

    outputs["status"] = "review" if review else "ok"
    outputs["path"] = rel
    if "--check" not in argv:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(merged)
        what = what_section(fields.get("what the rules do", ""))
        if what:
            with open(os.path.join(ROOT, WHAT_FILE), "w", encoding="utf-8", newline="\n") as f:
                f.write(what)
    report.append("")
    report.append("%d new line(s) for `%s`." % (added, rel))
    return finish(0)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
