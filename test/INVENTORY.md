# Test inventory: adapter-free asena-auth

asena-auth is not an adapter, so its tests must not import `@asenajs/ergenecore` or `@asenajs/hono-adapter`. This
file maps every test case of the files that imported an adapter at `0118ae1` to exactly one destination:

| Destination | Meaning |
|---|---|
| `auth/unit` | Stays in this repo and needs no pipeline: plain objects, stubs or a bare service instance. |
| `auth/fake` | Stays in this repo and runs on the in-process fake adapter in `test/support/fakeAdapter.ts`, built from `@asenajs/asena/adapter` only. |
| `suite/P2.auth.NNN` | Runs in `asena-test-suite` as scenario `P2.auth.NNN` of the Part 2 ecosystem module `auth` (`ecosystem/modules/auth/auth.test.ts`), on both real adapters, because what it asserts is the adapter's own behaviour. It is no longer in this repo. |

A case goes to the suite only when its assertion is about the adapter: cookie attributes as written on the wire,
`Set-Cookie` on an error response, the middleware → validator / context-contract order, the WebSocket upgrade and
subprotocol answer, `routePattern` as the adapter reports it, `setWebSocketValue` semantics, `@OnStart` order in a real
boot, CSRF behind a real TLS-terminating proxy. Everything about auth's own logic stays here.

**Runs** counts executions, not source cases: `describe.each` over the two adapters ran a case twice. A case that ran
on both adapters and stays here runs on both fake context shapes (`plain`: `ctx.req` is the `Request` and
`routePattern` is the registered path; `wrapped`: `ctx.req.raw` is the `Request` and `routePattern` is normalized),
the two shapes `getRawRequest` and `normalizeRoutePath` handle, so the run count is kept. A case that ran on one
adapter runs on the `plain` shape.

## Totals

| | Runs |
|---|---|
| `bun test` at `0118ae1`, all 30 files | 367 |
| Files below (adapter-importing) | 264 |
| - `auth/unit` | 73 |
| - `auth/fake` | 111 |
| - `suite/...` | 80 (43 scenarios) |
| Files that never imported an adapter | 103 |
| `bun test` now (`auth/unit` + `auth/fake` + the 103) | 287 |

`CsrfProxy`, `RoutePatternProbe`, `OnStartOrderProbe`, `WebSocketValueProbe` and `WebSocketUnauthorized` held only
`suite/...` cases and are gone, with `test/wsClient.ts`, the real-socket client only they and the other suite cases
used.

## Where the cases run

- `auth/unit` cases are where they were, unchanged.
- `auth/fake` cases keep their file and test name. A describe that was `... on $name` / `... on %s` over the adapters
  is now `... on the %s context` over `contextShapes`; a describe titled `... on ergenecore` lost the suffix
  (`guard`, `session and WebSocket middlewares`, `boot errors`). They boot with `bootFake(...)` and call `app.fetch(path)`
  and `app.connect(path)` instead of `fetch(app.baseUrl + path)` and a real socket; a rejected upgrade is
  `{ opened: false, status }`, so those cases now also assert the 401.
- `suite/...` cases run in `asena-test-suite` under `ASENA_ADAPTER=ergenecore` and `ASENA_ADAPTER=hono`, one scenario
  per row below; the fixtures only they used left with them.

## AsenaAuthService.test.ts (69 runs)

| Test | Runs | Proves | Destination |
|---|---|---|---|
| @Auth registration > registers under the class name and keeps it | 1 | `@Auth` names the component after the class | auth/unit |
| @Auth registration > an explicit name wins | 1 | `name` option overrides the class name | auth/unit |
| @Auth registration > implements the core provider strategy key | 1 | provider is discoverable under `AUTH_PROVIDER_KEY` | auth/unit |
| @Auth registration > a thunk registers under the class name and runs at construction, once per instance | 1 | lazy options resolve per instance | auth/unit |
| @Auth registration > primary reflects the options | 1 | `primary` getter | auth/unit |
| @Auth registration > onStart without options names @Auth | 1 | undecorated subclass fails with a hint | auth/unit |
| sessions > createSession returns a token and the session it maps to | 1 | token format, ttl, id is the hash | auth/unit |
| sessions > the stored user is a snapshot: mutating the input or a returned session never reaches later requests | 1 | stored user is cloned in and out | auth/unit |
| sessions > a user carrying a function cannot be stored: createSession names the cause and stores nothing | 1 | non-cloneable user rejected | auth/unit |
| sessions > the stored user is data only: a class instance comes back as a plain object, Date and Map survive | 1 | structuredClone semantics | auth/unit |
| sessions > resolves from a Bearer header and from the session cookie | 1 | both token carriers | auth/unit |
| sessions > the Bearer scheme is case-insensitive | 1 | `Bearer` parsing | auth/unit |
| sessions > Bearer wins over the cookie when both carry different tokens | 1 | carrier precedence | auth/unit |
| sessions > the cookie is matched by exact name, not by suffix | 1 | cookie parsing | auth/unit |
| sessions > a garbage Authorization header and an unknown token resolve to null | 1 | fail closed | auth/unit |
| sessions > bearer: false ignores Bearer tokens | 1 | `bearer: false`, subprotocol included | auth/unit |
| sessions > a custom cookie name is honoured | 1 | `cookie.name` | auth/unit |
| sessions > an expired session resolves to null | 1 | expiry | auth/unit |
| sessions > sliding: refreshes only once less than half of the lifetime is left | 1 | slide threshold | auth/unit |
| sessions > sliding: a cookie-carried slide re-issues the cookie once, on flush; Bearer does not | 1 | `flushSlidCookie` | auth/unit |
| sessions > absoluteTtl: a slid cookie never outlives the cap, and the store row never passes it either | 1 | absolute cap on slide | auth/unit |
| sessions > sliding: false never refreshes | 1 | `sliding: false` | auth/unit |
| sessions > absoluteTtl: sliding never moves expiresAt past createdAt + absoluteTtl, and the cap ends the session | 1 | absolute cap | auth/unit |
| sessions > absoluteTtl: a store row whose expiresAt outlives the cap is still rejected once the cap passed | 1 | cap checked on read | auth/unit |
| sessions > absoluteTtl defaults to 30 days: a 7-day session slid on day 29 ends on day 30 | 1 | defaults | auth/unit |
| sessions > absoluteTtl: false lets sliding keep a session alive past any cap | 1 | `absoluteTtl: false` | auth/unit |
| sessions > absoluteTtl smaller than sessionTtl fails the start, naming both values | 1 | `onStart` validation | auth/unit |
| sessions > absoluteTtl smaller than sessionTtl fails a real boot | 1 | the `onStart` error fails `createTestApp` | auth/fake |
| sessions > an app whose boot fails on absoluteTtl < sessionTtl exits printing the reason under the core wrapper | 1 | a real process prints the reason and exits non-zero (fixture `fixtures/invertedTtlBoot.ts`) | auth/fake |
| sessions > csrf > Sec-Fetch-Site decides when present: same-origin and none pass, same-site and cross-site do not | 1 | CSRF rule | auth/unit |
| sessions > csrf > without Sec-Fetch-Site, Origin must be the request URL's origin; no header at all passes | 1 | CSRF rule | auth/unit |
| sessions > csrf > trustedOrigins admits a listed Origin, also with Sec-Fetch-Site same-site or cross-site | 1 | `trustedOrigins` | auth/unit |
| sessions > csrf > safe methods are exempt, every other method is checked | 1 | method exemption | auth/unit |
| sessions > csrf > a cross-site WebSocket upgrade (a GET) carrying only the cookie is rejected | 1 | upgrade is not a safe GET | auth/unit |
| sessions > csrf > Bearer requests are exempt: the check applies only to a token read from the cookie | 1 | Bearer exempt | auth/unit |
| sessions > csrf > on by default, and csrf: false disables it | 1 | default on | auth/unit |
| sessions > loadUser > the loaded user replaces the stored snapshot on every request, and roles follow it | 1 | `loadUser` | auth/unit |
| sessions > loadUser > a user the loader no longer finds ends the session and deletes its row | 1 | `loadUser` null | auth/unit |
| sessions > loadUser > a loader answering undefined fails closed like null: no session, row deleted | 1 | `loadUser` undefined | auth/unit |
| sessions > loadUser > listUserSessions returns the stored snapshots and never calls loadUser | 1 | listing skips the loader | auth/unit |
| sessions > loadUser > a loaded user need not be cloneable: it is handed out as loaded | 1 | loaded user not cloned | auth/unit |
| sessions > loadUser > an expired session is not loaded | 1 | loader skipped on expiry | auth/unit |
| sessions > rotateSession > getAuthSession later in the same request returns the new session (%s) | 2 | rotation updates the context | auth/unit |
| sessions > rotateSession > with loadUser, the same-request session carries the loaded user, as the next request would | 1 | rotation + loader | auth/unit |
| sessions > rotateSession > replaces the current session: the old token stops working, the new one is a fresh session | 1 | rotation | auth/unit |
| sessions > rotateSession > a given user replaces the session user | 1 | rotation with user | auth/unit |
| sessions > rotateSession > a cookie session gets the new token as its cookie | 1 | cookie re-issued | auth/unit |
| sessions > rotateSession > without a current session it throws and creates nothing | 1 | fail closed | auth/unit |
| sessions > rotateSession > with loadUser, the new session carries the stored user, so a non-cloneable loaded user does not break it | 1 | rotation stores the snapshot | auth/unit |
| sessions > rotateSession > a failed create leaves the current session working | 1 | create before revoke | auth/unit |
| sessions > revokeSession kills one token, revokeUserSessions every token of the user | 1 | revocation | auth/unit |
| sessions > revokeSessionById ends the session whose AuthSession.session.id it is given, and only that one | 1 | revocation by id | auth/unit |
| sessions > listUserSessions returns the user's live sessions only, each revocable by its id | 1 | listing | auth/unit |
| sessions > listUserSessions on a store without listByUser names the store | 1 | optional store method | auth/unit |
| sessions > passwords use the configured hashing | 1 | hashing options | auth/unit |
| sessions > the store lifecycle follows the service | 1 | store start/stop | auth/unit |
| sessions > sweepInterval is in seconds: the default MemoryAuthStore sweeps every sweepInterval * 1000 ms | 1 | `sweepInterval` unit | auth/unit |
| sessions > through the container a supplied store starts and stops once | 1 | container lifecycle drives the store once | auth/fake |
| sessions > two providers sharing one store: it stops only when the last one stops | 1 | shared store refcount | auth/unit |
| sessions > two providers starting a shared async store concurrently start it once and both wait for it | 1 | shared start | auth/unit |
| sessions > a store whose start failed is started again by the next onStart, and a failed provider never stops it | 1 | failed start | auth/unit |
| sessions > concurrent stops of two providers stop the shared store once | 1 | shared stop | auth/unit |
| cookie options > secure defaults: httpOnly, lax, secure, path /, maxAge = ttl | 1 | defaults | auth/unit |
| cookie options > overrides apply | 1 | overrides | auth/unit |
| getRoles > default resolver reads user.roles | 1 | roles | auth/unit |
| getRoles > default resolver falls back to a comma-separated user.role | 1 | role string | auth/unit |
| getRoles > default resolver returns [] when neither is present | 1 | empty | auth/unit |
| getRoles > a custom resolver wins | 1 | custom resolver | auth/unit |

## Integration.test.ts (47 runs)

`asena-auth end to end on $name` and `loadUser end to end on $name` ran on both adapters; `boot errors` on ergenecore.

| Test | Runs | Proves | Destination | Why the real adapter matters |
|---|---|---|---|---|
| end to end > login returns a token and sets an HttpOnly, SameSite=Lax session cookie on / | 2 | the session cookie's attributes as the client receives them | suite/P2.auth.001 | cookie attributes on the wire are the adapter's serialization; the options themselves are `auth/unit` (cookie options, ContextHelpers) |
| end to end > @Protected: 401 anonymous, 200 by Bearer and by cookie, 401 once revoked | 2 | guard through a pipeline | auth/fake | |
| end to end > logout ends the current session at once and clears the cookie with its attributes | 2 | the deletion cookie's attributes on the wire | suite/P2.auth.002 | ergenecore drops `Secure` on a deletion, hono keeps it: an adapter divergence; logout itself stays covered by Logout.test.ts and the fake cases below |
| end to end > logout by cookie revokes that session; logout without a session still answers and clears | 2 | logout by cookie, anonymous logout | auth/fake | |
| end to end > csrf: a cross-site cookie POST is 401 and cannot log out; same-origin, trusted and Bearer POSTs pass | 2 | CSRF through the guard | auth/fake | |
| end to end > csrf: a cross-site WebSocket upgrade with only the cookie never opens; a same-origin one does | 2 | CSRF on the upgrade, subprotocol token as the way out | auth/fake | |
| end to end > rotateSession: the old token is 401 at once, the new one works; only a cookie session gets a cookie | 2 | rotation through a pipeline | auth/fake | |
| end to end > order: the guard rejects before the route middleware and the validator ever run | 2 | guard → route middleware → validator → handler | suite/P2.auth.003 | where the validator runs relative to route middlewares is the adapter's pipeline |
| end to end > a @Protected Context.define route rejects before its contract validates the body | 2 | guard before the context contract | suite/P2.auth.004 | `Context.define` is each adapter's own context class and contract step |
| end to end > @Roles: 403 without the role, 200 with it; the Better Auth role string passes the default resolver | 2 | roles | auth/fake | |
| end to end > @Public: a method opt-out and a @Public subclass of a @Protected controller | 2 | `@Public` | auth/fake | |
| end to end > two providers: a named route takes only its provider, an unnamed one the primary | 2 | provider selection | auth/fake | |
| end to end > a third-party provider written against @asenajs/asena/auth only is selectable by name | 2 | contract-only provider | auth/fake | |
| end to end > global AuthSessionMiddleware: public routes see the session, the provider runs once per request | 2 | session middleware + guard reuse | auth/fake | |
| end to end > global AuthSessionMiddleware does not let a primary-provider session into a named-provider route | 2 | owner check in `resolveSession` | auth/fake | |
| end to end > WebSocket: subprotocol token opens and echoes `bearer`; Authorization header opens; no token never opens | 2 | the negotiated subprotocol is `bearer` | suite/P2.auth.005 | the subprotocol answer is the adapter's upgrade handling |
| end to end > WebSocket under the global AuthSessionMiddleware: the subprotocol token wins over the cookie's user | 2 | `reuse: false` on the upgrade | auth/fake | |
| end to end > Better Auth's session-refresh Set-Cookie reaches the client on a guarded route, value unchanged | 2 | `forwardSetCookies` round trip | auth/fake | |
| end to end > BetterAuthController returns the Better Auth handler Response unchanged | 2 | controller passthrough | auth/fake | |
| boot errors > two providers, none primary, only named routes: authComponents fails the boot in the middlewares | 1 | `selectAtBoot` message | auth/fake | |
| boot errors > two providers, none primary: the guard components plus a middleware subclass naming its provider boot | 1 | `providerName` subclass | auth/fake | |
| boot errors > two providers, none primary, an unnamed protected route: the boot fails naming the route | 1 | registry validation | auth/fake | |
| boot errors > a %s guard mark %j this version cannot enforce fails the boot | 4 | unknown marks fail closed | auth/fake | |
| loadUser end to end > a role demotion applies on the next request; a deleted user is 401 and its row is gone | 2 | `loadUser` through the guard | auth/fake | |

## GuardIntegration.test.ts (11 runs)

| Test | Runs | Proves | Destination | Why the real adapter matters |
|---|---|---|---|---|
| guard on ergenecore > 401 anonymous, 200 with a Bearer token, the session reaches the handler | 1 | guard | auth/fake | |
| guard on ergenecore > an anonymous request never reaches the route middlewares, the validator or the handler | 1 | guard first, validator never runs | suite/P2.auth.006 | the validator's place in the chain is the adapter's |
| guard on ergenecore > authenticated: route middleware, then validator, then handler | 1 | middleware → validator → handler | suite/P2.auth.007 | same: pure adapter order |
| guard on ergenecore > @Public method on a @Protected controller is open | 1 | `@Public` | auth/fake | |
| guard on ergenecore > @Roles: 403 without the role, 200 with it | 1 | roles | auth/fake | |
| guard on ergenecore > HEAD on a protected GET route is guarded, not a 500 | 1 | HEAD finds the GET mark | auth/fake | |
| guard on ergenecore > @Public subclass of a @Protected controller is open while the base stays guarded | 1 | inheritance | auth/fake | |
| sliding cookie on $name > a cookie session past half-life gets its cookie re-issued with a fresh Max-Age | 2 | slide re-issue | auth/fake | |
| sliding cookie on $name > a Bearer session that slides gets no cookie | 2 | no cookie for Bearer | auth/fake | |

## SlideCookie.test.ts (28 runs)

Every case ran on 2 adapters x 2 setups (`guard only`, `global AuthSessionMiddleware too`).

| Test | Runs | Proves | Destination | Why the real adapter matters |
|---|---|---|---|---|
| a slide re-issues the cookie once, its Max-Age capped at the remaining absolute lifetime | 4 | one re-issue, capped | auth/fake | |
| logout in a request that slid answers with the deletion cookie only | 4 | logout discards the slide | auth/fake | |
| rotateSession in a request that slid answers with the new cookie only | 4 | rotation discards the slide | auth/fake | |
| a handler that logs in another user in a slid request answers with its new cookie only | 4 | `applySessionCookie` discards the slide | auth/fake | |
| clearSessionCookie in a slid request answers with the deletion cookie only | 4 | `clearSessionCookie` discards the slide | auth/fake | |
| a slid request the guard answers 403 still carries the re-issued cookie | 4 | `Set-Cookie` on an error response | suite/P2.auth.008 (guard only), suite/P2.auth.009 (global middleware) | hono-adapter 5.0.2 drops the request's cookies from an error response, ergenecore keeps them: adapter behaviour |
| a WebSocket upgrade whose cookie session slides still opens, and the slide is stored | 4 | a slide does not break the upgrade | auth/fake | |

The fake writes every `setCookie` / `deleteCookie` as its own `Set-Cookie` header and never merges by name, so the
"... only" cases fail there if auth writes the cookie twice; a real adapter may hide that by keeping the last write.

## CsrfProxy.test.ts (24 runs)

Every case ran on 2 adapters x 2 setups (`without trustedOrigins`, `with the public origin in trustedOrigins`),
through a real TLS-terminating proxy in front of a real server. All move: the scenario is the proxy and the server
seeing `http://` while the browser sent `https://`; the CSRF rule itself is `auth/unit` (AsenaAuthService csrf cases).

| Test | Runs | Destination (without / with trustedOrigins) |
|---|---|---|
| precondition: the app sees the public host over plain http, so request.url's origin is not the browser's | 4 | suite/P2.auth.010 / suite/P2.auth.011 |
| a modern browser same-origin POST (Sec-Fetch-Site: same-origin, https Origin) is authenticated | 4 | suite/P2.auth.012 / suite/P2.auth.013 |
| a legacy browser same-origin POST (https Origin, no Sec-Fetch-Site) is ${legacyStatus}; X-Forwarded-Proto is not trusted | 4 | suite/P2.auth.014 / suite/P2.auth.015 |
| cross-site POSTs are 401 with and without Sec-Fetch-Site, and a same-site subdomain is not same-origin | 4 | suite/P2.auth.016 / suite/P2.auth.017 |
| a cookie POST without Origin or Sec-Fetch-Site (non-browser client) is authenticated | 4 | suite/P2.auth.018 / suite/P2.auth.019 |
| WebSocket upgrade by cookie: modern same-origin opens, cross-site never, legacy same-origin follows trustedOrigins | 4 | suite/P2.auth.020 / suite/P2.auth.021 |

## BetterAuthCookies.test.ts (8 runs)

| Test | Runs | Proves | Destination | Why the real adapter matters |
|---|---|---|---|---|
| a forwarded Set-Cookie keeps Domain, Path, Expires, Secure, HttpOnly, SameSite and Partitioned | 2 | every attribute survives the adapter's `setCookie` | suite/P2.auth.022 | which attributes an adapter's `setCookie` writes is the adapter's |
| real Better Auth: signing up through the mounted handler opens a guarded route by its cookie | 2 | real Better Auth behind the guard | auth/fake | |
| real Better Auth: a session due for refresh answers with Better Auth's refreshed token cookie | 2 | refresh cookie forwarded | auth/fake | |
| real Better Auth with cookieCache: the session_data cookie passes through, refreshed or not | 2 | cookie cache forwarded | auth/fake | |

## RoutePatternProbe.test.ts (23 runs)

Pins what each adapter reports as `routePattern` and that the guard's key meets it. All move: the assertion is the
adapter's report; `requestKeys` / `routeKey` themselves are `auth/unit` in AuthGuardMiddleware.test.ts.

| Test | Runs | Destination |
|---|---|---|
| routePattern > root route | 2 | suite/P2.auth.023 |
| routePattern > param route | 2 | suite/P2.auth.024 |
| routePattern > POST with route middlewares | 2 | suite/P2.auth.025 |
| routePattern > trailing-slash route | 2 | suite/P2.auth.026 |
| routePattern > inherited root route | 2 | suite/P2.auth.027 |
| routePattern > inherited param route | 2 | suite/P2.auth.028 |
| routePattern > no trailing slash (separate controller) | 2 | suite/P2.auth.029 |
| routePattern > HEAD on a GET route | 2 | suite/P2.auth.030 |
| routePattern > @All route, GET | 2 | suite/P2.auth.031 |
| routePattern > @All route, DELETE | 2 | suite/P2.auth.032 |
| routePattern > Context.define route: a contract context still carries routePattern and the raw request | 2 | suite/P2.auth.033 |
| routePattern on hono > a prefix without a leading slash: hono adds one, the key normalizes the same way | 1 | suite/P2.auth.034 (both adapters; ergenecore refuses the unslashed path and runs it under the divergence flag `routing.unslashedPathIsServed`) |

## OnStartOrderProbe.test.ts (1 run)

| Test | Runs | Proves | Destination | Why |
|---|---|---|---|---|
| a dependency starts before its dependent, whatever the listing order | 1 | `@OnStart` order of a middleware and its dependency in a real boot | suite/P2.auth.035 | a probe of the framework under a real adapter, not of auth |

## WebSocketValueProbe.test.ts (2 runs)

| Test | Runs | Proves | Destination | Why |
|---|---|---|---|---|
| setWebSocketValue on %s > a second write replaces the first - values do not merge | 2 | replace semantics | suite/P2.auth.036 | the adapter's `setWebSocketValue`; auth's merge is `auth/unit` in AuthWebSocketMiddleware.test.ts |

## WebSocketUnauthorized.test.ts (2 runs)

| Test | Runs | Proves | Destination | Why |
|---|---|---|---|---|
| AuthWebSocketMiddleware rejection on $name > an upgrade without a session is answered 401 with WWW-Authenticate: Bearer, like the guard | 2 | the middleware's 401 reaches the client as the upgrade answer | suite/P2.auth.037 | a raw upgrade request through the adapter's upgrade path; the `Response` the middleware returns is `auth/unit` in AuthWebSocketMiddleware.test.ts |

## GuardMarkBoot.test.ts (10 runs)

| Test | Runs | Proves | Destination | Why the real adapter matters |
|---|---|---|---|---|
| guard marks at boot on $name > a %s mark %j this version cannot enforce fails the boot | 8 | unknown marks fail the boot on each real adapter | suite/P2.auth.038 .. 041 | the same four marks fail the boot on the fake in Integration.test.ts `boot errors`; this file exists to show it per real adapter |
| guard marks at boot on $name > @Protected({ provider: undefined }) boots and guards like @Protected() | 2 | an explicit `undefined` provider | auth/fake | |

## ContextHelpers.test.ts (6 runs)

| Test | Runs | Proves | Destination | Why the real adapter matters |
|---|---|---|---|---|
| getRawRequest > ergenecore: ctx.req is the Request | 1 | plain shape | auth/unit | |
| getRawRequest > hono: ctx.req wraps it as .raw | 1 | wrapped shape | auth/unit | |
| session cookie helpers > applySessionCookie writes the token with the service cookie config | 1 | options passed through | auth/unit | |
| session cookie helpers > clearSessionCookie deletes it with the same path, domain, secure and sameSite | 1 | options passed through | auth/unit | |
| session cookie helpers > hono: a __Host- session cookie can be deleted (hono refuses a prefixed cookie without Secure) | 1 | hono accepts the deletion because `secure` is passed | suite/P2.auth.042 | hono's prefixed-cookie rule |
| session cookie helpers > accept a real AsenaAuthService without a cast | 1 | typing + options | auth/unit | |

## AuthProviderRegistry.test.ts (10 runs, ergenecore)

| Test | Runs | Proves | Destination |
|---|---|---|---|
| a single provider is selected for unnamed routes | 1 | single provider | auth/fake |
| two providers + primary: unnamed routes use the primary, a named route its own | 1 | primary | auth/fake |
| providers are keyed by registered name, not class name | 1 | naming | auth/fake |
| two providers, no primary, unnamed protected route: boot fails naming the route and both candidates | 1 | boot validation | auth/fake |
| two primaries: boot fails naming both | 1 | boot validation | auth/fake |
| an unknown provider name: boot fails listing the candidates | 1 | boot validation | auth/fake |
| guard imported, protected route, zero providers: boot fails | 1 | boot validation | auth/fake |
| the error is logged in full before the boot fails | 1 | error log | auth/fake |
| registry without the guard warns and boots | 1 | warning | auth/fake |
| select() fails descriptively when nothing fits | 1 | `select` errors | auth/fake |

## MiddlewareIntegration.test.ts (5 runs, ergenecore)

| Test | Runs | Proves | Destination | Why the real adapter matters |
|---|---|---|---|---|
| global session middleware: null when anonymous, the user with a Bearer token | 1 | `AuthSessionMiddleware` | auth/fake | |
| global session middleware re-issues a slid cookie, also on a public route | 1 | flush after the handler | auth/fake | |
| browser-style subprotocol token opens the socket, echoes `bearer` and carries the session | 1 | the negotiated subprotocol | suite/P2.auth.043 | the subprotocol answer is the adapter's |
| no token: the upgrade is rejected, the socket never opens | 1 | rejection | auth/fake | |
| a token that matches no session is rejected too | 1 | rejection | auth/fake | |

## Logout.test.ts (4 runs)

| Test | Runs | Proves | Destination |
|---|---|---|---|
| logout edge cases > Bearer plus a different cookie: the Bearer session ends, the cookie is cleared, its row is left to expire | 2 | logout with both carriers | auth/fake |
| logout edge cases > a cross-site logout POST clears the cookie but cannot end the session | 2 | CSRF on logout | auth/fake |

## Testing.test.ts (10 runs)

| Test | Runs | Proves | Destination |
|---|---|---|---|
| TestAuthProvider under createWebTest > the x-test-user header alone drives @Protected and @Roles | 2 | `TestAuthProvider` under `createWebTest` | auth/fake |
| TestAuthProvider under createTestApp > the header drives @Protected and @Roles routes | 2 | under `createTestApp` | auth/fake |
| TestAuthProvider under createTestApp > primary: true serves unnamed routes, name registers the provider a route can name | 2 | `primary` / `name` | auth/fake |
| TestAuthProvider under createTestApp > a WebSocket route behind AuthWebSocketMiddleware opens for a known header only | 2 | WebSocket | auth/fake |
| TestAuthProvider > the header name is configurable, and users is read on every request | 1 | options | auth/unit |
| TestAuthProvider > is published only as the testing subpath, never from the package entry | 1 | exports | auth/unit |

## BetterAuthController.test.ts (4 runs)

| Test | Runs | Proves | Destination |
|---|---|---|---|
| BetterAuthController on %s > %s %s reaches the Better Auth handler with the raw Request, its Response returned as is | 4 | `getRawRequest` + passthrough, `@All('/*')` | auth/fake |

## fixtures/invertedTtlBoot.ts

Not a test; the subprocess fixture of the AsenaAuthService case above. It boots on the fake adapter.
