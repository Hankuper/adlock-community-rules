# Rules of the repository

## Who can contribute

Anyone with a GitHub account. You do not need an invitation and you do not need to clone anything.

**The easy way — an issue.** Open [Propose rules](../../issues/new?template=propose-rules.yml), name the site,
paste the rules. A workflow checks them and opens a pull request with one file for you. If a line is rejected,
the workflow answers in the issue and says why.

**The usual way — a pull request.** Fork, add or edit one file under `sites/`, open a pull request. One pull
request — one site.

AdLock itself never sends anything here: rules are shared only by you, with your own GitHub account.

A proposal becomes public in this repository only after a maintainer has reviewed and merged it.

## License of your contribution

Everything in this repository is released under [CC0 1.0 Universal](LICENSE) — the public domain.

By submitting rules — through the Propose rules form or a pull request — you confirm that you wrote them yourself
for the sites they name, with or without the help of tools such as AdLock, that you did not copy them from other
filter lists, and that you have the right to share them; and you dedicate them to the public domain under CC0 1.0
Universal. Anyone, including Hankuper (the company behind AdLock), may then use, change and redistribute them for
any purpose, also commercially, without asking you and without naming you.

Most of the well-known filter lists are published under other licenses (GPL, CC BY-SA), and their lines cannot be
relicensed here. Knowing how other lists solve a problem is fine, and a rule you wrote yourself from the page may come
out the same as a line of another list: short rules often do. Copying is what is not allowed.

Your GitHub account stays visible in the history of the repository as the author of the proposal.

## What gets merged

1. The file passes `tools/lint.py` with no rejected lines ([FORMAT.md](FORMAT.md) lists what is accepted).
2. Every rule is tied to the site of its file.
3. Lines marked `review` (exceptions, allow-list entries, a deny entry for the whole site) are merged only when a maintainer has looked at each
   of them and the pull request explains what they fix.
4. The rules do what the description says: they remove ads, trackers or annoyances on that site. Rules that
   break the site, hide its content or favour one advertiser over another are removed.
5. No personal data: no full URLs with query strings, tokens, user names or session identifiers. A rule needs a
   host and a path prefix, not your address bar.
6. Rules for a sensitive site or service follow the stricter rules below.

## Sensitive sites and services

On some sites a wrong or malicious rule does more harm than any ad: it can cost a user money, access to an
account or their safety. Banks, payment acquiring and checkout pages, wallets and exchanges, the login and account
pages of any service (single sign-on, two-factor authentication, password recovery), government services, health
care, security software, corporate systems — and anything of the same kind. There is no list of such sites here:
judge by what the site does, not by its name.

- The checker cannot recognise such sites, so its `ok` is not enough there: a maintainer looks at every line as
  if it were marked `review`.
- A rule that hides a warning, a security notice, a form field or a confirmation step, or that blocks the service
  itself, is rejected.
- When in doubt whether a site is sensitive, treat it as sensitive.

## What is not accepted

- Script injection, response rewriting, redirects, conditional rules — see FORMAT.md. They can do anything on a
  page, and this repository is not reviewed line by line by the AdLock team.
- Rules for sites whose only purpose is illegal content.
- Bulk imports of other filter lists and rules copied from them. Link to the list instead; many of them are
  already part of AdLock.

## Changing and removing rules

- A rule that breaks a site is removed first and discussed afterwards. Open an issue with the site and what
  stopped working.
- Maintainers may edit a proposal before merging it (narrow a selector, add `$domain=`).
- A file with no rules left is deleted.

## Maintainers

Maintainers are appointed by Hankuper, the company behind AdLock. Only they merge into `main`.

## Conduct

Be specific and civil. Discuss rules, not people.
