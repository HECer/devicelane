---
name: visual-verification
---

# Visual verification

Unit tests don't see a blank page, an unwired route, a runtime console error, or AI-slop design.
Make the loop's gate catch them by widening `verify`, since the loop trusts verify as truth.

## 1. Compose the verify pipeline

```
```

## 2. Flow-smoke with the built-in gate

```yaml
smoke:
  baseUrl: http://localhost:3000
  flows:
    - name: home
      path: /
      landmark: "main h1"
    - name: login
      path: /login
      landmark: "form"
```

fails on any console error, and **always** saves a screenshot to `.yoke/proof/<story>/`
(the loop labels the folder with the current story id via `YOKE_STORY`; standalone runs use
`latest`, or pass `--label=`). Requires Playwright in the project:
`npm i -D playwright && npx playwright install chromium`. Start the dev server before verify
(e.g. via `start-server-and-test`).

## 3. Video only when necessary

(`.yoke/proof/<story>/<flow>.webm`). When a flow goes red: watch that clip first, then use the
wired Playwright MCP to reproduce interactively. Never record every run manually — the gate
already handles the failure case.

## Rule

Green pipeline = types + units + no design-slop over budget + every flow renders without
console errors, with a screenshot to prove it. Only then is the story actually done.
