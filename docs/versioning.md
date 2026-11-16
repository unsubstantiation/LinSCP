# Versioning

LinSCP's version is the **date of the build**. The arbitrary `0.1.0` (crate,
frontend, CMake project) and `1.0-7` (Debian package) numbers are gone.

## What a user sees

The version shown in the app - the line in the Help dialog - is
`VYYYY-MM-DD-HH-MM`, for example `V2026-11-16-11-38`: the build's Alaska
Standard Time (UTC-9, fixed; AKST does not observe daylight saving), minutes
precision, the minute the build ran. It is stamped into the frontend by
`ui/scripts/build.mjs` (`window.LinSCPBuildVersion`), which is bundled into
every host of the page: the desktop window and the Android app.

`SOURCE_DATE_EPOCH`, when set, pins the instant for reproducible builds;
otherwise the clock at build time is used.

## What a package carries

Ecosystems disagree about version grammars, so the same date is rendered
per carrier - all derived from one scheme, checked by
`tools/tests/test_build_version.py`:

| Carrier | Form | Example |
| --- | --- | --- |
| App (Help dialog) | `VYYYY-MM-DD-HH-MM` (AKST) | `V2026-11-16-11-38` |
| Cargo workspace / Tauri bundle / frontend / CMake project | date-based semver `YYYY.M.D` | `2026.11.15` |
| Debian package | the same date plus `HHMM`, dots only, no hyphens (Debian's single hyphen is unused) | `2026.11.15.1950` |

The committed `Cargo.toml`, `tauri.conf.json`, `ui/package.json`,
`ui/package-lock.json`, `CMakeLists.txt` and `debian/changelog` carry the
migration's date; builds made from that source share it. The *displayed*
build stamp is per build, not per commit.

Semver forbids leading zeros, which is why the crate/frontend/bundle
versions are date-only; minute precision survives in the Help dialog stamp
and in the Debian package version.

## Bumping for a release

Regenerate the committed carriers on the day of the release:

    date -u -d '-9 hours' '+%Y.%-m.%-d'   # semver date, AKST

and prepend a `debian/changelog` entry with the same date plus `HHMM`, dots
only. `python3 tools/tests/test_build_version.py` fails if the carriers
drift apart.
