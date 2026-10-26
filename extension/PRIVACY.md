# PhishGuard Extension — Privacy Policy

**Effective: 2026**

PhishGuard is built on one principle: *checking whether a link is safe
should not require telling anyone which links you visit.*

## What we collect

**Nothing.** PhishGuard makes no network requests of any kind.

- The machine-learning models ship inside the extension package and run
  entirely in your browser.
- URLs you visit, links on pages you read, and emails you paste into the
  scanner are processed in memory, on your device, and are never
  transmitted anywhere.
- Scan counters (total / phishing / suspicious) and the on/off setting are
  stored in your browser's local extension storage only. "Proceed anyway"
  choices are kept in session storage and vanish when the browser closes.
- There is no analytics, no telemetry, no crash reporting, no remote
  configuration, and no server component.

## Permissions explained

| Permission | Why |
|---|---|
| `tabs` | read the current tab's URL to score it and show the badge/warning |
| `storage` | keep your on/off setting and local counters |
| `contextMenus` | the right-click "Scan link with PhishGuard" item |
| `http(s)://*/*` host access | lets the content script outline dangerous links on pages you view — the script sends nothing off your device |

## Changes

Any future version that changes this policy will say so in the changelog
and bump the version number.

## Contact

Open an issue: https://github.com/shivakumar-07/PhishGuard/issues
