#!/usr/bin/env python3
"""Tests of tools/propose.py and of the file-level checks of tools/lint.py. Standard library only.

    python tools/test_tools.py
"""
import contextlib
import io
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lint  # noqa: E402
import propose  # noqa: E402


def issue(site="example.com", rules="", deny="", allow="", what="hides banners"):
    """the body GitHub builds from the Propose rules form"""
    def field(value, fenced=True):
        if not value:
            return "_No response_"
        return "```text\n%s\n```" % value if fenced else value
    return ("### Site\n\n%s\n\n### Rules\n\n%s\n\n### Deny hosts\n\n%s\n\n### Allow hosts\n\n%s\n\n"
            "### What the rules do\n\n%s\n\n### Confirmation\n\n- [X] I wrote or tested these rules myself\n"
            % (site, field(rules), field(deny), field(allow), what))


class ProposeTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = propose.ROOT
        propose.ROOT = self.tmp.name
        self.output = os.path.join(self.tmp.name, "github_output")
        self.env = dict(os.environ)
        os.environ["GITHUB_OUTPUT"] = self.output
        for name in ("GITHUB_REPOSITORY", "ISSUE"):   # set in Actions; each test sets them itself
            os.environ.pop(name, None)

    def tearDown(self):
        propose.ROOT = self.root
        os.environ.clear()
        os.environ.update(self.env)
        self.tmp.cleanup()

    def run_issue(self, body, args=()):
        os.environ["ISSUE_BODY"] = body
        if os.path.exists(self.output):
            os.remove(self.output)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = propose.main(list(args))
        outputs = {}
        if os.path.exists(self.output):
            with open(self.output, encoding="utf-8") as f:
                outputs = dict(line.rstrip("\n").split("=", 1) for line in f if "=" in line)
        return code, outputs, out.getvalue()

    def read(self, rel):
        with open(os.path.join(self.tmp.name, rel), encoding="utf-8") as f:
            return f.read()

    def test_new_file(self):
        code, out, report = self.run_issue(issue(rules="example.com##.ad\n||ads.example.net^$domain=example.com", deny="*.ads.example.com"))
        self.assertEqual(code, 0, report)
        self.assertEqual(out["status"], "ok")
        self.assertEqual(out["path"], "sites/e/example.com.txt")
        text = self.read("sites/e/example.com.txt")
        self.assertIn("! Target: site example.com", text)
        self.assertIn("[rules]\n! hides banners\nexample.com##.ad\n||ads.example.net^$domain=example.com\n", text)
        self.assertIn("[deny]\n! hides banners\n*.ads.example.com\n", text)
        self.assertNotIn("[allow]", text)
        self.assertFalse(lint.failed(lint.lint_text(text, "example.com")))

    def test_site_field_is_normalised(self):
        code, out, _ = self.run_issue(issue(site="https://WWW.Example.com/some/page?x=1", rules="example.com##.ad"))
        self.assertEqual(code, 0)
        self.assertEqual(out["domain"], "example.com")
        self.assertEqual(out["path"], "sites/e/example.com.txt")

    def test_rejected_line_changes_nothing(self):
        code, out, report = self.run_issue(issue(rules="example.com##.ad\nexample.com#%#alert(1)\n||ads.example.net^"))
        self.assertEqual(code, 1)
        self.assertEqual(out["status"], "rejected")
        self.assertIn("script injection", report)
        self.assertIn("not tied to example.com", report)
        self.assertFalse(os.path.exists(os.path.join(self.tmp.name, "sites")))

    def test_review_lines_are_marked(self):
        code, out, report = self.run_issue(issue(rules="@@||example.com/player.js", allow="pay.example.com"))
        self.assertEqual(code, 0)
        self.assertEqual(out["status"], "review")
        self.assertIn("exception (@@)", report)
        self.assertIn("[allow]\n! hides banners\npay.example.com\n", self.read("sites/e/example.com.txt"))

    def test_merge_into_existing_file(self):
        self.run_issue(issue(rules="example.com##.ad"))
        code, out, report = self.run_issue(issue(rules="example.com##.ad\nexample.com##.banner", deny="ads.example.com"))
        self.assertEqual(code, 0, report)
        self.assertIn("2 new line(s)", report)
        text = self.read("sites/e/example.com.txt")
        self.assertEqual(text.count("example.com##.ad\n"), 1)
        self.assertIn("example.com##.banner\n", text)
        self.assertIn("[deny]\n! hides banners\nads.example.com\n", text)
        self.assertEqual(text.count("! Target:"), 1)

    def test_nothing_new(self):
        self.run_issue(issue(rules="example.com##.ad"))
        code, out, report = self.run_issue(issue(rules="example.com##.ad"))
        self.assertEqual(code, 1)
        self.assertEqual(out["status"], "invalid")
        self.assertIn("already in", report)

    def test_bad_site_and_empty_proposal(self):
        code, out, report = self.run_issue(issue(site="not a domain", rules="x##.ad"))
        self.assertEqual((code, out["status"]), (1, "invalid"))
        code, out, report = self.run_issue(issue())
        self.assertEqual((code, out["status"]), (1, "invalid"))
        self.assertIn("no rules", report)

    def test_body_not_in_the_form(self):
        """an issue written by hand or by an assistant without the form's headings gets an answer, not silence"""
        code, out, report = self.run_issue("Rules for example.com\n\nexample.com##.ad\n")
        self.assertEqual((code, out["status"]), (1, "invalid"))
        self.assertIn("### Site", report)

    def test_author_text_in_the_answer_is_code(self):
        """the reasons carry pieces of the author's lines: in the bot's answer they stay code, not an image, link or mention"""
        code, out, report = self.run_issue(issue(rules="example.com##.ad", deny="see ![x](https://evil.example/a.png) @someone"))
        self.assertEqual((code, out["status"]), (1, "rejected"))
        self.assertIn("`not a host name or *.host: see ![x](https://evil.example/a.png) @someone`", report)
        for line in report.split("\n"):
            outside = "".join(part for i, part in enumerate(line.split("`")) if i % 2 == 0)
            self.assertNotIn("](", outside)
            self.assertNotIn("@someone", outside)

    def test_check_mode_writes_nothing(self):
        code, out, _ = self.run_issue(issue(rules="example.com##.ad"), args=["--check"])
        self.assertEqual(code, 0)
        self.assertEqual(out, {})
        self.assertFalse(os.path.exists(os.path.join(self.tmp.name, "sites")))

    def test_issue_body_is_only_data(self):
        """shell and Markdown metacharacters in the body end up in a rejected line, never in a path or a command"""
        code, out, report = self.run_issue(issue(site="example.com", rules="$(touch /tmp/pwned)\n`id`\n../../etc/passwd"))
        self.assertEqual(code, 1)
        self.assertEqual(out["status"], "rejected")
        self.assertNotIn("`id`", report)  # backticks are neutralised in the Markdown report
        code, out, _ = self.run_issue(issue(site="../../etc/passwd", rules="example.com##.ad"))
        self.assertEqual((code, out["status"], out["path"]), (1, "invalid", ""))

    def test_no_response_placeholder(self):
        fields = propose.form_fields(issue(rules="example.com##.ad"))
        self.assertEqual(propose.lines_of(fields["deny hosts"]), [])
        self.assertEqual(propose.lines_of(fields["rules"]), ["example.com##.ad"])

    def what(self):
        path = os.path.join(self.tmp.name, propose.WHAT_FILE)
        if not os.path.exists(path):
            return None
        with open(path, encoding="utf-8") as f:
            return f.read()

    def test_what_the_rules_do_goes_to_the_pull_request(self):
        code, _, _ = self.run_issue(issue(rules="example.com##.ad", what="Hides the empty video block, @someone"))
        self.assertEqual(code, 0)
        self.assertEqual(self.what(), "### What the rules do\n\n```text\nHides the empty video block, @someone\n```\n")

    def test_what_cannot_leave_its_code_block(self):
        """the author's text is untrusted: a fence inside it must not close the block and let markup through"""
        text = "x\n```\n![img](https://evil.example/a.png) @everyone\n````"
        self.run_issue(issue(rules="example.com##.ad", what=text))
        what = self.what()
        self.assertTrue(what.startswith("### What the rules do\n\n`````text\n"), what)
        self.assertTrue(what.endswith("\n`````\n"), what)
        self.assertIn(text, what)

    def test_what_is_limited_and_optional(self):
        self.run_issue(issue(rules="example.com##.ad", what="a" * 5000))
        self.assertLess(len(self.what()), propose.WHAT_LIMIT + 100)
        self.assertIn("[...]", self.what())
        os.remove(os.path.join(self.tmp.name, propose.WHAT_FILE))
        self.run_issue(issue(rules="example.com##.banner", what="_No response_"))
        self.assertIsNone(self.what())

    REPO = "Hankuper/adlock-community-rules"
    URL = "! https://github.com/Hankuper/adlock-community-rules/issues/"

    def test_comment_links_the_issue(self):
        """as public filter lists usually do: the full link to the issue, then the description"""
        os.environ.update(GITHUB_REPOSITORY=self.REPO, ISSUE="5")
        what = "Hides the empty video block.\nThe player is blocked, the frame stays.\n\x07"
        code, _, report = self.run_issue(issue(rules="example.com##.video", deny="ads.example.com", what=what))
        self.assertEqual(code, 0, report)
        text = self.read("sites/e/example.com.txt")
        self.assertIn("[rules]\n" + self.URL + "5\n! Hides the empty video block.\nexample.com##.video\n", text)
        self.assertIn("[deny]\n" + self.URL + "5\n! Hides the empty video block.\nads.example.com\n", text)
        self.assertFalse(lint.failed(lint.lint_text(text, "example.com")))

    def test_comment_lines_are_safe(self):
        self.assertEqual(propose.comment_for(self.REPO, "7", "_No response_"), [self.URL + "7"])
        self.assertEqual(propose.comment_for("", "", "_No response_"), [])
        self.assertEqual(propose.comment_for("not a repo; rm", "7", "x"), ["! x"])
        self.assertEqual(propose.comment_for(self.REPO, "7 ", "x"), ["! x"])
        # "! Target: ..." would read as the header of the file: such a description is left out
        self.assertEqual(propose.comment_for(self.REPO, "7", "Target: site evil.org"), [self.URL + "7"])
        long = propose.comment_for("", "", "x" * 500)[0]
        self.assertTrue(long.endswith("...") and len(long) <= propose.COMMENT_LIMIT)
        for line in propose.comment_for(self.REPO, "1", "#include x") + propose.comment_for(self.REPO, "1", "+ NOT_OPTIMIZED"):
            self.assertTrue(line.startswith("! "), line)   # never a directive (!#) or a compiler hint (!+)
        # a description with personal data is left out, the link stays
        self.assertEqual(propose.comment_for(self.REPO, "7", "write to jane.doe@mail.com"), [self.URL + "7"])

    def test_rule_comments_stay_above_their_rules(self):
        os.environ.update(GITHUB_REPOSITORY=self.REPO, ISSUE="5")
        rules = ("! empty banner slots: sidebar, text, home page\nexample.com##div[class^=\"Banner-module__\"]\n"
                 "example.com##div[class*=\"__ads\"]\n! the placeholder of the video widget\nexample.com##div[class^=\"_video_\"]")
        code, _, report = self.run_issue(issue(rules=rules))
        self.assertEqual(code, 0, report)
        self.assertIn("Checked 3 line(s) and 2 comment(s)", report)
        text = self.read("sites/e/example.com.txt")
        self.assertIn("[rules]\n" + self.URL + "5\n! hides banners\n! empty banner slots: sidebar, text, home page\n"
                      "example.com##div[class^=\"Banner-module__\"]\nexample.com##div[class*=\"__ads\"]\n"
                      "! the placeholder of the video widget\nexample.com##div[class^=\"_video_\"]\n", text)
        self.assertFalse(lint.failed(lint.lint_text(text, "example.com")))
        # the same proposal again with one new rule: no comment is repeated, the new rule comes with its own
        os.environ["ISSUE"] = "6"
        code, _, report = self.run_issue(issue(rules=rules + "\n! the sticky footer\nexample.com##.sticky-footer"))
        self.assertEqual(code, 0, report)
        self.assertIn("1 new line(s)", report)
        text = self.read("sites/e/example.com.txt")
        self.assertEqual(text.count("! empty banner slots"), 1)
        self.assertEqual(text.count("! the placeholder of the video widget"), 1)
        self.assertIn(self.URL + "6\n! hides banners\n! the sticky footer\nexample.com##.sticky-footer\n", text)

    def test_rule_comments_are_checked(self):
        for comment, reason in (("! asked by jane.doe@mail.com", "e-mail"), ("!+ NOT_OPTIMIZED", "compiler hints"),
                                ("! " + "x" * 250, "longer than")):
            code, out, report = self.run_issue(issue(rules=comment + "\nexample.com##.ad"))
            self.assertEqual((code, out["status"]), (1, "rejected"), comment)
            self.assertIn(reason, report)
        # comments before the first section header are the header of the file, not counted
        r = lint.lint_text("! Title: example.com\n! Target: site example.com\n! anything\n[rules]\n! about .ad\nexample.com##.ad\n", "example.com")
        self.assertEqual((r["comments"], r["accepted"]["rules"]), (1, ["! about .ad", "example.com##.ad"]))

    def test_select_with_comments(self):
        lines = ["! a", "x1", "x2", "! b", "! b2", "!#if adguard", "y", "!#endif", "! c", "z", "! orphan"]
        self.assertEqual(lint.select_with_comments(lines, lambda l: l in ("x2", "z")), ["! a", "x2", "! c", "z"])
        self.assertEqual(lint.select_with_comments(lines, lambda l: l == "y"), ["! b", "! b2", "!#if adguard", "y", "!#endif"])

    def test_directive_block_is_kept_whole(self):
        os.environ.update(GITHUB_REPOSITORY=self.REPO, ISSUE="3")
        rules = "!#if !env_mobile\nexample.com##.promo\n!#else\nexample.com##.promo-wrapper\n!#endif\nexample.com##.ad"
        code, out, report = self.run_issue(issue(rules=rules))
        self.assertEqual(code, 0, report)
        self.assertIn("Checked 3 line(s)", report)   # directives are not rule lines
        text = self.read("sites/e/example.com.txt")
        self.assertIn(self.URL + "3\n! hides banners\n!#if !env_mobile\nexample.com##.promo\n!#else\nexample.com##.promo-wrapper\n!#endif\nexample.com##.ad\n", text)
        # the same block again: its rules are in the file, the block is not added a second time, the new rule is
        os.environ["ISSUE"] = "4"
        code, out, report = self.run_issue(issue(rules=rules + "\nexample.com##.banner"))
        self.assertEqual(code, 0, report)
        self.assertIn("1 new line(s)", report)
        text = self.read("sites/e/example.com.txt")
        self.assertEqual(text.count("!#if"), 1)
        self.assertIn(self.URL + "4\n! hides banners\nexample.com##.banner\n", text)
        self.assertFalse(lint.failed(lint.lint_text(text, "example.com")))

    def test_broken_blocks_are_rejected(self):
        for rules in ("!#if adguard\nexample.com##.ad", "example.com##.ad\n!#endif", "!#if adguard\n!#else\n!#else\n!#endif\nexample.com##.ad",
                      "!#if adguard_typo\nexample.com##.ad\n!#endif", "!#include other.txt\nexample.com##.ad"):
            code, out, report = self.run_issue(issue(rules=rules))
            self.assertEqual((code, out["status"]), (1, "rejected"), rules)
        # a block may not cross a section
        r = lint.lint_text("! Target: site example.com\n!#if adguard\nexample.com##.ad\n[deny]\nads.example.com\n!#endif\n", "example.com")
        self.assertTrue(lint.failed(r))
        self.assertTrue(any("!#if without !#endif before [deny]" in e for e in r["errors"]), r["errors"])
        self.assertTrue(any(l["reason"] == "directives are accepted only in [rules]" for l in r["lines"]), r["lines"])

    def test_whole_site_deny_and_personal_data(self):
        code, out, report = self.run_issue(issue(rules="example.com##.ad", deny="example.com"))
        self.assertEqual((code, out["status"]), (0, "review"))
        self.assertIn("blocks the whole site", report)
        code, out, report = self.run_issue(issue(rules="||example.com/api?session=8f3a&x=1"))
        self.assertEqual((code, out["status"]), (1, "rejected"))
        self.assertIn("session=", report)

    def test_what_is_not_written_for_a_rejected_proposal_or_a_check(self):
        self.run_issue(issue(rules="example.com#%#alert(1)"))
        self.assertIsNone(self.what())
        self.run_issue(issue(rules="example.com##.ad"), args=["--check"])
        self.assertIsNone(self.what())


class LintFileTest(unittest.TestCase):
    def test_paths(self):
        self.assertEqual(lint.target_from_path("sites/e/example.com.txt"), ("site", "example.com"))
        self.assertEqual(lint.target_from_path("C:\\repo\\sites\\e\\example.com.txt"), ("site", "example.com"))
        self.assertIsNone(lint.target_from_path("sites/x/example.com.txt"))
        self.assertIsNone(lint.target_from_path("example.com.txt"))
        self.assertEqual(lint.target_from_path("apps/windows/app.exe.txt"), ("app", "windows", "app.exe"))

    def test_header_must_match_the_file(self):
        self.assertTrue(lint.failed(lint.lint_text("! Target: site other.org\nexample.com##.ad\n", "example.com")))
        self.assertTrue(lint.failed(lint.lint_text("example.com##.ad\n", "example.com")))
        self.assertFalse(lint.failed(lint.lint_text("! Target: site example.com\r\n\r\nexample.com##.ad\r\n", "example.com")))

    def test_limits(self):
        many = "! Target: site example.com\n" + "".join("example.com##.ad%d\n" % i for i in range(lint.MAX_RULES + 1))
        self.assertTrue(any("limit" in e for e in lint.lint_text(many, "example.com")["errors"]))
        long_line = "! Target: site example.com\nexample.com##" + "a" * (lint.MAX_LINE + 1) + "\n"
        self.assertEqual(lint.lint_text(long_line, "example.com")["counts"][lint.REJECT], 1)

    def test_application_files_are_reserved(self):
        report = lint.lint_text("! Target: app android com.example\n[deny]\nads.example.com\n")
        self.assertTrue(lint.failed(report))

    def test_every_file_of_the_repository(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(lint.__file__)))
        for path in lint.all_files(root):
            self.assertFalse(lint.failed(lint.lint_file(path)), path)


if __name__ == "__main__":
    unittest.main(verbosity=1)
