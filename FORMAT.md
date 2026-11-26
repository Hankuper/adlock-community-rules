# File format

A rule file is plain UTF-8 text, LF or CRLF, at most 300 rule lines, each line at most 2000 characters.

## Path

```
sites/<first character of the domain>/<domain>.txt
```

- `<domain>` is the site's registrable domain in lower case, punycode for non-ASCII names, without `www.`:
  `example.com`, `bbc.co.uk`, `xn--80aswg.xn--p1ai`.
- Subdomains go into the file of their site: rules for `mail.example.com` live in `sites/e/example.com.txt`.
- `apps/<platform>/<application id>.txt` is reserved for rules bound to one application. The id is what AdLock
  identifies the application by: the process name on Windows and Linux (`windows/app.exe`), the package name on
  Android (`android/com.example.app`), the bundle id on macOS. A full path on somebody's computer is never part
  of a file. Files there are not accepted yet.

## Header

```
! Title: example.com
! Target: site example.com
! Updated: 2026-11-12
```

`! Target:` is required and must match the path.

## Comments

A line starting with `!` is a comment, as in the common rule syntax. Write it as `! text`, with a space: `!#…`
are directives (see below) and `!+ …` are list compiler hints, which are rejected.

Comments before the first section header are the header of the file. Inside a section a comment belongs to
the rule or rules below it, up to the next comment: say there what each rule hides or fixes, so that a
maintainer can review it and anyone can repair it when the site changes. Such a comment:

- is at most 200 characters and is checked like a rule for personal data (addresses, tokens, identifiers);
- stays only together with its rules: when every rule below it is already in the file, the comment is not
  added a second time.

When the workflow adds the rules of a proposal, it marks them the way public filter lists usually do: above
them, in each section it changes, the full link to the issue and then the first line of "What the rules do".
The author's own comments follow, each above its rules.

```
! https://github.com/Hankuper/adlock-community-rules/issues/5
! Hides the empty ad slots
! empty banner slots: sidebar, text, home page
example.com##div[class^="Banner-module__"]
! the placeholder of the video widget
example.com##div[class^="_video_"]
```

When AdLock adds rules from this repository to the user's list, it keeps the comments above them.

## Sections

A file has up to three sections. Lines before the first section header belong to `[rules]`.

### `[rules]` — goes to the user's rule list

Rules in the common rule syntax, the one AdLock uses for its own lists.

**Accepted**

- Element hiding for the site or its subdomains: `example.com##.ad`, `news.example.com##div[data-ad]`,
  extended selectors with `#?#`, removing an element with `:remove()`.
- Styles for the site or its subdomains, in any of the usual forms: `example.com#$#html { overflow: auto !important; }`,
  `example.com##html:style(overflow: auto !important)`, `example.com##html { overflow: auto !important; }`,
  `#$?#` with extended selectors. They are checked the same way in every form: a style that loads anything from
  the network (`url(`, `@import`, `image-set(`, `image(`, `cross-fade(`, `element(`, `expression(`,
  `-moz-binding`, `behavior:`) or has an escape (`\`) is rejected. Maintainers review every change, styles too.
- Blocking a request, tied to the site in one of two ways:
  - the blocked host belongs to the site: `||counter.example.com^`, `||example.com/ads/*`;
  - or the rule carries `$domain=` listing only the site and its subdomains:
    `||ads.example.net^$domain=example.com`, `/banners/*$image,domain=example.com`.
- Options: `script`, `image`, `stylesheet`, `xmlhttprequest`, `subdocument`, `font`, `media`, `websocket`,
  `ping`, `other`, `object`, `popup`, `document`, `third-party` / `3p`, `first-party` / `1p`, `match-case`,
  `domain=`.
- Conditional blocks of the common rule syntax: `!#if <condition>`, `!#else`, `!#endif`. They may be nested,
  must be closed inside `[rules]` and only group rules; every rule inside is checked like any other. A condition
  is made of `!`, `&&`, `||`, parentheses and the condition names of the common syntax (capabilities such as
  `cap_html_filtering`, environments such as `env_mobile`, `true`, `false`; the full list is in `tools/lint.py`).
  Any other name is rejected as a typo: filters would take it as false and silently drop the block. In AdLock
  the capabilities it has (`cap_html_filtering`, `cap_user_stylesheet`), `true` and the general name of the
  syntax are true; names of particular applications, browsers and environments are false on every platform.

  ```
  !#if cap_html_filtering
  example.com##.promo
  !#else
  example.com##.promo-wrapper
  !#endif
  ```

**Merged only after a maintainer's review**

- Exceptions: `@@||example.com/player.js`, `example.com#@#.ad`, `example.com#@$#…`. They switch protection off, so a person looks
  at each of them.
- Any rule for a sensitive site or service: money and payments, accounts and logins, government, health,
  security and the like (see [CONTRIBUTING.md](CONTRIBUTING.md#sensitive-sites-and-services)). The checker does
  not recognise such sites, so its `ok` is not enough there. A rule that hides a warning, a form field or a
  confirmation step on such a site, or blocks the service itself, is rejected.

**Rejected**

- Generic rules (no site): `##.ad`, `||ads.example.net^` in a file for another site.
- `$domain=` with a negation (`~example.com`) or with a domain that is not the site of the file.
- Scripts and changes of the page markup: `#%#`, `##+js(...)`, snippets (`#$#` without a `{ }` block),
  `:remove-attr()`, `:remove-class()`, HTML filtering `##^`.
- Rewriting and redirects: `$replace`, `$redirect`, `$redirect-rule`, `$csp`, `$removeparam`, `$removeheader`,
  `$urltransform`, `$header`, `$cookie`, `$jsonprune`, `$hls`.
- `$important`, `$badfilter`, `$app`, regular-expression patterns (`/…/`), directives other than `!#if`,
  `!#else` and `!#endif` (`!#include`, `!#state` …) and conditional rules (`$when=`, `$throttle…`, `$corrupt`).
- Personal data and secrets: an e-mail address; a value of the parameters `token`, `access_token`, `auth`,
  `session`, `sessionid`, `session_id`, `sid`, `sessid`, `phpsessid`, `jsessionid`, `api_key`, `apikey`,
  `password`, `passwd`, `pwd`, `email`, `phone`, `ticket` (`?token=*` is fine); a run of 24 or more letters and
  digits mixing both, which is a token or an identifier of one user, not of the site.

### `[deny]` — goes to the user's deny list of domains

One host per line. The host is blocked at DNS and at the TLS handshake, in every application, without HTTPS
inspection.

- `ads.example.com` — the host and everything under it.
- `*.ads.example.com` — only what is under it, not `ads.example.com` itself.
- Every entry must be the site of the file or its subdomain. Third-party hosts are blocked with a rule in
  `[rules]` and `$domain=`, never here: a deny entry acts on every site.
- The site itself (`example.com`) or all of its subdomains (`*.example.com`) is merged only after a
  maintainer's review: such an entry takes the whole site away.

### `[allow]` — goes to the user's allow list of domains

Same syntax and the same limit to the site of the file. An allowed host is not filtered at all, so every
`[allow]` entry is merged only after a maintainer's review.

## Example

```
! Title: example.com
! Target: site example.com
! Updated: 2026-11-12

[rules]
! banner slots
example.com##.ad-banner
example.com##div[id^="div-gpt-ad-"]
! the ad library, only on this site
||securepubads.g.doubleclick.net^$domain=example.com
! the site's own counter
||counter.example.com^

[deny]
*.ads.example.com
```

## The checker

`python tools/lint.py` checks every file, `python tools/lint.py sites/e/example.com.txt` one file.
Each line gets a verdict: `ok`, `review` (needs a maintainer) or `reject` with the reason. A pull request with a
rejected line cannot be merged.
