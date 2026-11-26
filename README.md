# AdLock community rules

Ad-blocking rules for [AdLock](https://adlock.com) written by its users — one small file per site.

Nothing here is applied automatically. A rule file is a proposal: every line is checked, you see what it would
do, and only the rules you accept are added to your own lists.

- **Use rules** — take the file of the site you need, e.g. `sites/e/example.com.txt`. Nothing else has to be
  downloaded.
- **Share rules** — open an issue with the [Propose rules](../../issues/new?template=propose-rules.yml) form,
  or send a pull request. No invitation is needed, only a GitHub account.
- **Format** — [FORMAT.md](FORMAT.md). **Rules of the repository** — [CONTRIBUTING.md](CONTRIBUTING.md).
- **License** — [CC0 1.0](LICENSE): public domain, use the rules any way you like.

## Layout

```
sites/<first character>/<domain>.txt     rules for one site, e.g. sites/e/example.com.txt
apps/<platform>/<application id>.txt     reserved: rules for one application (not accepted yet)
tools/lint.py                            the checker every file passes before it is merged
```

One file can be fetched without cloning the repository:

```
https://raw.githubusercontent.com/Hankuper/adlock-community-rules/main/sites/e/example.com.txt
```

## What a file may contain

| Kind | Example | Status |
|---|---|---|
| Hide an element on the site | `example.com##.ad-banner` | accepted |
| Block a request made by the site | `\|\|ads.example.net^$domain=example.com` | accepted |
| Block a host of the site itself | `\|\|counter.example.com^` | accepted |
| Block a subdomain everywhere (no HTTPS inspection needed) | `*.ads.example.com` in `[deny]` | accepted |
| Exception (`@@…`, `#@#`), allow-list entry, the whole site in `[deny]` | `@@\|\|example.com/player.js`, `example.com` in `[deny]` | merged only after a maintainer's review |
| Conditional blocks of the common rule syntax | `!#if cap_html_filtering` … `!#endif` | accepted, rules inside are checked as usual |
| Script injection, response rewriting, redirects, conditional rules | `#%#`, `$replace`, `$redirect`, `!#state` | rejected |
| Personal data: e-mail addresses, tokens, session identifiers | `?session=8f3a…` | rejected |

Every rule must be tied to the site of its file: a file for `example.com` cannot change what happens on any
other site.

## Trust

These rules are written by users, not by the AdLock team. They are not signed and not part of the filter lists
AdLock ships. Every proposal is reviewed by a maintainer before it appears here, so that nothing harmful gets
in — but read the rules before accepting them.

## License

Everything in this repository — the rules and the tools — is dedicated to the public domain under
[CC0 1.0 Universal](LICENSE).

- Anyone may copy, change, combine and redistribute the rules, in any product, free or commercial, without
  asking permission. That includes Hankuper, the company behind AdLock: it may analyse the rules and use them
  in its own products.
- Credit is not required. A link to this repository or to [adlock.com](https://adlock.com) is welcome.
- The rules come as they are, with no warranty: a rule may stop working or break a site at any time.
- Whoever proposes rules releases them under the same terms — see [CONTRIBUTING.md](CONTRIBUTING.md#license-of-your-contribution).

AdLock is a product and a trademark of Hankuper. The name and the logo are not covered by this dedication.
