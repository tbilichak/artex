# api-recon — Reference Manual

Grep recipes, `config.json` templates, and troubleshooting. All `grep` commands run against the `js/` directory. For single-line bundles, you can run `js-beautify` or `sed 's/}/}\n/g'` first, though raw `grep` with context windows is usually sufficient.

## Script Notes

All files in `scripts/` are **reference templates** and must be adapted to the target site before running. Typical adjustment points:

| Script | Common Adjustments |
|---|---|
| `harvest_static.py` | endpoint regexes, webpack/Vite manifest parsing, micro-frontend `publicPath`, retry/concurrency |
| `runtime_harvest.js` | neutralize field names and success values, stub matching rules and body structure, routes source, WS recording, `waitUntil`/`routeTimeout`/`proxy` |
| `preload.js` | `loginPathRe`, L1 stubs, `neutralize.fields`, `apiPattern`, whether to enable L3, `recordDetail`, `observe.*`, `neutralizeVueRouter` |
| `spider_mpa.py` | `--exclude` destructive links, cookies, depth/max, same-origin filtering |
| `extract_route_map.py` | `routeMap` / `routeLink` regexes, KEY naming patterns |
| `build_perm_tree.py` | `userRouteAuth` parsing, `ROOTS`/`PREFIX_PARENT` hierarchy heuristics, stub outer field names |
| `config.json` | unified entry point for all site-specific parameters above |

Place adapted files in the task working directory (e.g., `recon/`) and note specific changes relative to the reference scripts in your report.

---

## A. Reversing the Three Gates

### A1. Render Gate — "How does it check if logged in?"

```bash
grep -rhoaE '.{0,40}(isLogin|isAuthenticated|loggedIn|hasLogin|requireAuth)\b.{0,80}' js | head
grep -rhoaE 'function (getUser|getToken|getAuth)[0-9]?\([^)]*\)\{.{0,200}' js | head
grep -rhoaE '(localStorage|sessionStorage)\.getItem\("[^"]+"\)' js | sort -u
grep -rhoaE '(Cookies?|cookie)\.(get|load)\("[^"]+"\)' js | sort -u
grep -rhoaE '\batob\(|JSON\.parse\(|jwt|decode' js | head
```

Trace the chain `isLogin = f(getUser())` → `getUser = decode(storage.read(KEY))` to determine the **storage key**, **container** (Cookie vs localStorage), and **encoding**:

| Encoding | How to forge in `config.json` |
|---|---|
| Plaintext string / `"1"` / token | `"value": "anything-truthy"` |
| `JSON.parse(x)` | `"value": "json:{\"id\":1,\"username\":\"admin\"}"` |
| `JSON.parse(atob(x))` | `"value": "b64json:{\"id\":1,\"username\":\"admin\"}"` |
| JWT | Unsigned / `alg:none` JWT, or signed with key found in bundle |
| Encrypted (SM2/AES/RSA) | Look for hardcoded key; forge if render gate only needs a decodable blob; otherwise fall back to static analysis |

→ Write to `cookies` / `localStorage`.

### A2. Interceptor Gate — "What triggers a redirect to /login?"

```bash
grep -rhoaE '.{0,60}(interceptors\.response|axios|request\.use).{0,120}' js | head
grep -rhoaE '.{0,40}(response_code|errcode|errno|\bcode\b|\bret\b|\bstatus\b)\s*[=!]==?\s*[\-0-9]{1,4}.{0,60}' js | head -20
grep -rhoaE '.{0,40}(not logged in|please login|session expired|unauthorized|token.{0,10}invalid).{0,40}' js | head
grep -rhoaE '.{0,30}(location\.href|router\.(push|replace)|navigate)\([^)]*login[^)]*\)' js | head
```

Determine: **field name**, **success value** (usually `0` or `200`), and **failure values that trigger redirect**. Verify with a junk session:

```bash
curl -sk -X POST -H 'Cookie: <fakekey>=junk' https://target/api/<protected> -d '{}' -H 'Content-Type: application/json'
```

→ Write to `neutralize.fields` + `neutralize.success`.

### A3. Content Gate — "Where do menus/permissions come from?"

```bash
grep -rhoaE '"/api[^"]*(permission|perm|role|menu|acl|resource|nav)[^"]*"' js | sort -u
grep -rhoaE '.{0,30}(menus|permissions|menuList|routeList|authList|role_permissions)\b.{0,120}' js | head
grep -rhoaE 'userRouteAuth|getResultTree|routeMap|routeLink|hasPermission|checkAuth' js | head
grep -rhoaE '([A-Z_][A-Z0-9_]*):\{name:"[^"]*",link:"/[^"]+"\}' js | head
```

**Two layers of data** (common in enterprise admin panels):

| API | Typical Payload | Consumer |
|---|---|---|
| `.../role_permissions` | `{ permissions: string[], role_type }` | Route guards, button-level ACL |
| `.../permissions/all` | `tree[{ code, position, children }]` | Sidebar menu rendering |
| Bundle `userRouteAuth` | `{ CODE: { url, name? } }` | `code` → frontend path |
| Bundle `routeMap` | `{ KEY: { name, link } }` | Alias resolution (webpack `o.DASHBOARD`) |

Read the consumer code to confirm how `getResultTree(tree, permissions)` filters items and which field `v-if` / `hasAuth(code)` checks.

**Manual forge** (small sites): construct a permissive payload → `stubs`.

**Full permission tree reconstruction** (large sites where sidebar/submodules remain blank): see **Section I**.

---

## B. `config.json` Template

```json
{
  "baseUrl": "https://target/",
  "runtimeMode": "both",
  "chromium": "/usr/bin/chromium",

  "cookies": [
    { "name": "auth", "value": "b64json:{\"id\":1,\"username\":\"admin\",\"role\":\"admin\",\"func\":{},\"permissions\":[\"*\"]}" }
  ],
  "localStorage": { "token": "faketoken", "isLogin": "1" },

  "neutralize": {
    "fields": ["response_code", "code", "errno", "ret", "status"],
    "success": 0,
    "flags": { "success": true, "message": "ok" }
  },
  "forward": true,
  "loginUrlPattern": "/login",
  "apiPattern": "/api/|/rest/|/graphql",

  "mockTier": "L1+L2",
  "recordDetail": true,
  "observe": {
    "storageReads": false,
    "cookieReads": false,
    "xhrHeaders": true
  },
  "neutralizeVueRouter": true,
  "stubs": [
    {
      "match": "permissions/all|/menu|role_permissions",
      "body": {
        "response_code": 0, "code": 0,
        "data": {
          "permissions": ["*"],
          "menus": [
            { "name": "dashboard", "path": "/dashboard", "show": true, "children": [] },
            { "name": "alert", "path": "/alert", "show": true, "children": [] }
          ]
        }
      }
    }
  ],

  "explore": {
    "clickTabs": true,
    "clickTables": true,
    "pushStateFallback": true,
    "maxMenuItems": 50
  },

  "routes": ["/dashboard", "/alert", "/asset", "/device", "/report", "/config", "/system"],
  "waitMs": 1500, "perRouteMs": 900, "headless": true,
  "waitUntil": "domcontentloaded",
  "routeTimeout": 12000,
  "proxy": "",

  "captureResponses": true, "recordWs": true, "respMax": 600
}
```

Field descriptions:
- `runtimeMode`: `depth` (Puppeteer), `coverage` (browser MCP), or `both`
- `cookies[].value` prefix: `b64json:` → base64(JSON); `json:` → raw JSON; no prefix → literal string
- `forward: true` forwards real requests and rewrites status-code fields; `false` uses fully offline stubs
- `mockTier`: preload tiers enabled in coverage mode, e.g., `L1+L2`, `L1+L2+L3`
- `routes`: sourced from `routes.txt`; after forging menus, the harness automatically appends `<a href>` links
- `captureResponses` / `recordWs`: effective only in `depth` mode
- `waitUntil`: use `domcontentloaded` for large SPAs to avoid `networkidle2` hangs
- `routeTimeout`: per-route `page.goto` timeout in milliseconds
- `proxy`: Puppeteer `--proxy-server`; can also set `HTTP_PROXY` / `HTTPS_PROXY`

### B1. Dual-Stub Template (`role_permissions` + `permissions/all`)

```json
"stubs": [
  {
    "match": "role_permissions",
    "body": {
      "response_code": 0,
      "data": {
        "permissions": ["MONITOR", "MONITOR_ALERT", "THREAT", "ASSETS_RISK"],
        "role_type": "SUPER_ADMIN"
      }
    }
  },
  {
    "match": "permissions/all",
    "body": {
      "response_code": 0,
      "data": [
        {
          "code": "MONITOR",
          "position": 1,
          "children": [
            { "code": "MONITOR_ALERT", "position": 1, "children": [] }
          ]
        }
      ]
    }
  }
]
```

Outer field names (`response_code` / `code` / `data`) must match the A2 interceptor gate; `permissions` must cover every leaf `code` in the tree.

---

## C. Coverage Mode: Preload Configuration

Edit the `CONFIG` object at the top of `scripts/preload.js`, or replace it before CDP injection:

```javascript
const CONFIG = {
  loginPathRe: /\/(login|signin)(\/|$|\?)/i,
  mockTier: 'L1+L2',
  forward: true,
  recordDetail: true,
  extractUrlsFromResponse: true,
  neutralizeVueRouter: true,
  observe: { storageReads: false, cookieReads: false, xhrHeaders: true },
  neutralize: { fields: ['response_code', 'code'], success: 0 },
  stubs: [ /* same as config.json stubs */ ],
  apiPattern: /\/(api|apis|v\d+|dev|internal|graphql)\//i,
};
```

Verify: `window.__API_RECON_PRELOAD__ === true` and `pathname` stays stable.

Export recorded results:

```javascript
JSON.stringify({
  apis: [...window.__API_RECON_LOG__],
  detail: window.__API_RECON_DETAIL__,
  routes: [...(window.__API_RECON_ROUTES__ || [])],
  observe: window.__API_RECON_OBSERVE__,
}, null, 2)
```

---

## D. Preload / Runtime Hook Capabilities

Built-in browser hook capabilities and coverage in `preload` (coverage) and `runtime_harvest` (depth):

| Hook Capability | Value for API Discovery | Coverage |
|---|---|---|
| Hook `fetch` / `XHR.open` | Record request URL/method | ✅ `recordDetail` + `__API_RECON_LOG__` |
| Hook `XHR.setRequestHeader` | Discover `Authorization` and custom headers | ✅ `observe.xhrHeaders` |
| Hook `localStorage`/cookie reads | Confirm session key names | ⚠️ Optional `observe.storageReads/cookieReads` |
| Vue router extraction | Complete `frontendRoutes` | ✅ `__API_RECON_ROUTES__` (loaded routes) |
| Vue route guard neutralization / login redirect blocking | Open modules to trigger APIs | ✅ `neutralizeVueRouter` + native redirect neutralization |
| React router extraction | Supplement routes | ⚠️ Static + clicking; no dedicated hook |
| Page redirect blocking (login path) | Stay on page for analysis | ⚠️ Blocks login paths only to avoid breaking app navigation |
| Hook crypto libraries (CryptoJS/SM, etc.) | Encrypted params → plaintext API body | ❌ Must manually hook encryption inputs; record findings in config |
| Anti-debugging bypass | Otherwise runtime cannot record APIs | ❌ Must handle manually; static analysis still works |

---

## E. Endpoint Extraction Regexes (When Static Yields Too Few)

Relax `extract_endpoints` in `harvest_static.py`, or run manually:

```bash
grep -rhoaE '"/[a-z][A-Za-z0-9_/\-]{3,}"' js | sort -u
grep -rhoaE '/api/[a-zA-Z0-9_./-]+' js | sort -u
```

---

## F. Troubleshooting

| Symptom | Cause → Fix |
|---|---|
| Very few static APIs | Endpoint pattern mismatch → relax regexes (Section E) |
| Chunk count ≪ manifest | CSS-only or undeployed chunks; 404s already retried |
| Runtime still shows login page | Render gate mismatch → recheck A1: key name, container, encoding, domain |
| Shell loads but modules are blank | Content gate → forge menus (A3); `routes` paths may be wrong |
| Only bootstrap/locale on every route | Incomplete permission codes → Section I tree reconstruction; check `role_permissions` + `permissions/all` dual stubs |
| Sidebar has items but subpages are blank | Tree missing intermediate nodes or `code` doesn't match `userRouteAuth` |
| Every API redirects to login | Interceptor gate → verify `neutralize`; nested fields may need extended walk logic |
| 0 WS frames | Subscription requires user interaction; increase `perRouteMs` |
| Empty response bodies | Real responses only appear when `forward: true` |
| Missing Chromium | Install chromium or set `config.chromium` / `CHROMIUM` |
| Many mocks yet still redirects to login | Hook injected too late or missing `location.href` setter → document-start + preload |
| All tables/lists empty | Normal for L3 empty arrays; keep clicking tabs/settings/details |
| Redux actions mistaken for routes | Filter out internal paths containing `get`/`set`/`change`/`clear`/`toggle`/`upload` |
| Vue still redirects to login | Preload not at document-start → fix injection timing; or clear guards manually if `neutralizeVueRouter: false` |
| URLs in response not in log | Enable `extractUrlsFromResponse`; or extract manually from `__API_RECON_DETAIL__` |
| Unknown `Authorization` header name | Enable `observe.xhrHeaders` or inspect request headers in DevTools |
| Runtime very slow / times out | Switch to `waitUntil: domcontentloaded`; lower `routeTimeout`; avoid `networkidle2` |
| Proxy connection failed | Check `proxy` / env vars; ensure Puppeteer and curl use the same proxy port |

---

## G. Hardened Targets

When the server validates sessions step by step (unforgeable signed cookies, server-rendered menus that cannot be stubbed), runtime harvesting will stall at the shell. Expected approach:

- **Static analysis is sufficient for endpoint enumeration** — module paths live in the bundle code.
- If authorized, run the same harness with a **real session**: `forward: true`, no neutralization needed, capturing real methods/params/responses.

---

## H. Single-Task Checklist

1. Confirm authorized scope.
2. **Read** `scripts/harvest_static.py` → adapt for target → run → inspect `api_static.txt` and `routes.txt`.
3. **Phase 1b**: path-anchor window expansion + binding layer → `param_candidates.json` (Section J).
4. Reverse A1/A2/A3 → write site-specific `config.json`.
5. **Read and adapt** `runtime_harvest.js` / `preload.js` before running.
6. `runtimeMode=depth`: `npm install` → run adapted harvest script.
7. `runtimeMode=coverage/both`: inject adapted preload at document-start → browser MCP dynamic enumeration + **parameter trigger matrix**.
8. Modules not rendering → **Section I permission tree reconstruction** → patch stubs → rerun.
9. Multi-sample parameter diff + error-based inference → `params_merged.json`.
10. Merge → `site_map.json` + `api_merged.txt`, honestly noting coverage, gaps, and script modifications.

---

## I. Permission Tree Reconstruction (Phase 4 Deep Dive)

Use when forging simple `menus: [{ path, show: true }]` does not work and submodules still fail to mount.

### I1. Locate Auth Modules

```bash
grep -l 'userRouteAuth' js/*.js
grep -l 'routeMap\|routeLink' js/*.js
grep -rhoaE 'getResultTree|role_permissions|permissions/all' js | head
```

Record: **permission API path**, **response field names**, and **consuming chunk filename**.

### I2. Extract `routeMap`

```bash
python3 scripts/extract_route_map.py recon/js recon/
# outputs recon/route_map.json
```

If `[!] no routeMap pattern found`: relax the regex in `extract_route_map.py`, or grep manually:

```bash
grep -rhoaE '([A-Z_][A-Z0-9_]*):\{name:"[^"]*",link:"/[^"]+"\}' js | head -20
```

### I3. Build Permission Tree + Stubs

```bash
python3 scripts/build_perm_tree.py recon/js recon/ --config recon/config.json
```

Script logic:
1. Parse `userRouteAuth={MONITOR:{url:...},...}` (including webpack aliases like `He=o.DASHBOARD`)
2. Resolve aliases → real paths using `route_map.json`
3. Infer parent from code prefix (`MONITOR_ALERT` → `MONITOR`)
4. Output `permissions_tree.json`, `permissions_all_stub.json`, `role_permissions_stub.json`
5. With `--config`, automatically writes `stubs` and expanded `routes` into `config.json`

**Adapt for target** (at the top of the script):
- `DEFAULT_ROOTS`: list of top-level module codes
- `DEFAULT_PREFIX_PARENT`: `PREFIX_` → parent mapping
- `DEFAULT_EXTRA_PARENT`: orphan nodes without prefix relationships

### I4. Verify Stub Consistency

```bash
# permission count should roughly match userRouteAuth entry count
wc -l recon/perm_codes_all.txt
# routes should cover all links in route_map
python3 -c "import json; m=json.load(open('recon/route_map.json')); r=set(json.load(open('recon/config.json'))['routes']); print('missing', [v['link'] for v in m.values() if v['link'] not in r])"
```

### I5. Rerun Runtime and Compare

```bash
node recon/runtime_harvest.js recon/config.json
# compare runtime_api.json count before/after forging; check whether module APIs appear on /attack, /asset, etc.
```

| Before Forging | After Forging (Success) |
|---|---|
| Same 3–5 bootstrap calls per route | Different routes trigger distinct module APIs |
| Only `/api/locale/language` | Module endpoints like `/api/web/...` appear |
| Single-digit routes in `routes.txt` | 80–110+ routes from `route_map` |

### I6. If It Still Fails

- **coverage mode**: click sidebar items + tabs; permission gating may only fire after interaction
- **stub fields**: compare real API responses (`curl` + real session) with stub nesting
- **additional guards**: grep `hasPermission|checkRole|func.` for button-level checks and expand `role_permissions.permissions`
- **static fallback**: module API paths remain in `api_static.txt`; runtime only supplements METHOD/body; keep `param_candidates.json` + recorded samples

---

## J. Parameter Reversing (Phase 1b / 5b / 5c)

**Methodology, not a one-size-fits-all script.** Find paths with regexes; find parameters via anchor window expansion + UI binding chains + multi-sample diffs + error-based inference.

### J1. Anchor Window Expansion — Finding Payload Builders from Paths

```bash
# Anchor on a known Phase 1 path
grep -n '"/api/user/list"' js/*.js
grep -rhoaE '.{0,120}("/api[^"]+").{0,200}' js | head
grep -rhoaE '(params|data|body|payload)\s*:\s*\{' js | head
grep -rhoaE '(get|post|put|delete|patch)\([^,]+,\s*\{' js | head
```

### J2. Wrapper Layer and Transport Formats

```bash
# axios / unified request wrapper
grep -rhoaE '(axios|request)\.(get|post|put|delete|patch)\(' js | head
grep -rhoaE 'interceptors\.(request|response)' js | head

# GraphQL
grep -rhoaE '(query|mutation)\s+\w+|gql`|graphql\(' js | head
grep -rhoaE '\$[a-zA-Z_]+\s*:\s*(Int|String|Boolean|\[)' js | head

# FormData / multipart
grep -rhoaE 'FormData|\.append\(' js | head

# Path parameters
grep -rhoaE 'path:\s*"/[^"]*:[^"]+"' js | head
grep -rhoaE 'useParams|route\.params|\$route\.params' js | head
```

### J3. Validation Gates — Required / Format / Enum

```bash
grep -rhoaE '(required|message|pattern|enum|validator)\s*:' js | head
grep -rhoaE 'yup\.|zod\.|async-validator|Form\.Item|a-form-item|el-form-item' js | head
grep -rhoaE 'rules\s*:\s*\[|name:\s*["\'][a-zA-Z_]+["\']' js | head
grep -rhoaE 'label.*value|options\s*:\s*\[' js | head
```

### J4. Binding Layer — Form → API

```bash
grep -rhoaE 'onFinish|handleSubmit|getFieldsValue|validateFields' js | head
grep -rhoaE '(pick|omit|transform|dayjs|moment)\(' js | head
```

Runtime supplement: DevTools → Network → Request → **Initiator** (call stack) to trace upward from `fetch`/`send` to the payload builder function.

### J5. Encrypted Parameters

```bash
grep -rhoaE 'encrypt|decrypt|sign|CryptoJS|sm2|sm3|sm4|RSA|AES' js | head
```

**Do not guess fields from ciphertext** — hook the encryption function's **input arguments** to capture plaintext payloads before encryption; record findings in `config.json` / `param_candidates.json`.

### J6. Parameter Trigger Matrix (Required in Phase 3)

Record once per action in each module and diff request body/query:

| Action | Focus |
|---|---|
| Initial list load | Default pagination values |
| Search | `keyword`, filters |
| Advanced filter | Optional fields |
| Create / Edit | Full entity |
| Batch / Export | `ids[]`, `exportType` |
| Sort / Paginate | `sortField`, `order` |

Output `param_samples.json`: `[{ "path", "method", "action": "search", "body", "query", "headers" }]`

### J7. Confidence Rules

| Confidence | Criteria |
|---|---|
| **High** | Static callsite + ≥2 consistent runtime samples |
| **Medium** | Static only, or single runtime sample |
| **Low** | Inferred from response/error without secondary verification |
| **Untriggered** | Known statically, not reached via UI/permissions |

### J8. Quick Playbooks by Scenario

| Scenario | Sequence |
|---|---|
| REST list page | J1 payload object → J6 four diffs → J3 rules |
| Create/Edit form | J3 Form names → J4 submit chain → runtime submit + intentionally leave fields blank to inspect 400 errors |
| GraphQL | J2 variable declarations → record `variables` per operation at runtime |
| Encrypted body | J5 hook encryption inputs → pre-encryption fields are the real params |

### J9. Mapping to `api-recon` Phases

| `api-recon` Phase | Parameter Recon |
|---|---|
| Phase 1 Static | J1 anchor window expansion |
| Phase 2 A2 Interceptor | Globally injected fields (`tenantId`, `sign`) |
| Phase 3 Runtime | J6 trigger matrix + `param_samples.json` |
| Phase 4 Permission Tree | Different modules have different forms → full permissions needed to trigger all fields |
| Phase 5 Merge | `params_merged.json` + confidence; never mark required from a single sample |

### J10. Troubleshooting

| Symptom | Handling |
|---|---|
| Field found statically but never seen at runtime | Mark "Untriggered"; complete permission tree / open advanced filters / toggle linked select options |
| Same path, different body shapes | Normal — record separately by `action`, do not force-merge schemas |
| Stub returns fake response but need real params | **Inspect outbound request** body/headers; do not infer from stub responses |
| 400 error reports nested field | Check outer wrappers like `data`/`bizData`/`variables` |
| GraphQL only shows operation name | Expand `variables` JSON; search statically for `$var: Type` |

---
