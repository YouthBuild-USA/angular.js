# AngularJS 1.8.3 security patches

This branch (`claude/v1.8.x-securitypatch`) is AngularJS 1.8.3 with fixes for the known security
problems that the AngularJS team never fixed (AngularJS reached end of life with 1.8.3).
Built files report the version `1.8.3-securitypatch.1`.

Each fix is its own commit with tests in the existing spec file for that area.

| CVE | Problem in 1.8.3 | Fix | Files |
|---|---|---|---|
| CVE-2026-11998 | `$sce` resource url lists: a RegExp with `\|` was only partly anchored, so part of a url could match | Wrap the RegExp in `^(?:...)$` | `src/ng/sce.js` |
| CVE-2023-26116 | `angular.copy()` of a RegExp was slow (quadratic) on a long source | Read flags without a regex | `src/Angular.js` |
| CVE-2023-26117 | `$resource` url building was slow on urls with many `/` or `?` | Loop instead of `/\/+$/`; look for `=:param` only after `?` | `src/ngResource/resource.js` |
| CVE-2023-26118 | `<input type="url">` check (`URL_REGEXP`) was slow on long runs of `/` | Slashes after the scheme can no longer be split many ways; same results as before | `src/ng/directive/input.js` |
| CVE-2022-25844 | `currency` filter was slow with long whitespace in the locale pattern | Replace the symbol without a regex | `src/ng/filter/filters.js` |
| CVE-2024-21490 | `srcset` sanitizing was slow on long whitespace | Linear parser | `src/ng/compile.js` |
| CVE-2024-8372 | `srcset` urls could hide in a "descriptor" and skip sanitizing (e.g. `ok.png 1.5x,evil:b`) | Read `srcset` the way browsers do; sanitize every url; keep only valid descriptors | `src/ng/compile.js` |
| CVE-2024-8373 | `<source srcset>` (interpolated, `ng-srcset`, `ng-attr-srcset`) was not sanitized | Sanitize like `<img srcset>` | `src/ng/compile.js` |
| CVE-2025-0716 | SVG `<image href>` / `<image ng-href>` were not sanitized | Use the image url context like `xlink:href` | `src/ng/compile.js` |
| CVE-2025-2336 | `$sanitize` checked SVG `<image href / xlink:href>` against the link list, not the image list | Check them as image urls | `src/ngSanitize/sanitize.js` |
| CVE-2025-4690 | `linky` filter was slow on long text | Linear scanner; finds the same links as before | `src/ngSanitize/filter/linky.js` |
| CVE-2022-25869 | In Internet Explorer, `{{ }}` typed into a `<textarea>` could run as an expression | In IE, do not compile `<textarea>` content | `src/ng/compile.js` |

## Behaviour changes

- `srcset` values that contain whitespace: invalid descriptors are dropped, and a url that came
  after an unrecognised descriptor is now its own sanitized candidate. Output for normal values is
  unchanged. Values with no whitespace keep the old comma split.
- In Internet Explorer only, `{{ }}` inside `<textarea>...</textarea>` is no longer interpolated.
  Use `ng-model` instead.

## Building

The build needs a version tag. In a clone without tags:

```bash
git tag v1.8.3 df41fc79f
git tag -a v1.8.3-securitypatch.1 -m "v1.8.3-securitypatch.1 codename(security-patch)"
NG1_BUILD_NO_REMOTE_VERSION_REQUESTS=1 CI=1 PATH=$PWD/node_modules/.bin:$PATH grunt minify
```

Output is in `build/`.

## Tests

Run the unit tests with `karma start karma-jqlite.conf.js --single-run` (and the jQuery configs).
Three `input[datetime-local]` tests fail on recent Chrome both before and after these patches
(Chrome now shortens milliseconds such as `.500` to `.5`); they are not related to security.

Some of the slow-input tests cannot fail on recent Chrome, because its regex engine no longer runs
the old patterns slowly. They still guard other browsers (and Node), where the old patterns took
seconds on the same inputs.
