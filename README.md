# servy

A production-ready async web framework for Nim.

## Installation

```
nimble install servy
```

## Quickstart

```nim
import servy

when isMainModule:
  var router = initRouter()

  proc handleHello(req: Request, res: Response): Future[void] {.async.} =
    res.json(%*{"message": "hello world!"})

  router.addRoute("/hello", handleHello)

  let opts = newServerOptions(port = 9000)
  var s = initServy(opts, router)
  s.run()
```

## Routing

### Basic routes

```nim
router.addRoute("/", handleIndex)
router.addRoute("/get", handleGet, HttpGet)
router.addRoute("/post", handlePost, HttpPost)
router.addRoute("/put", handlePut, HttpPut)
router.addRoute("/delete", handleDelete, HttpDelete)
```

### URL parameters

```nim
proc handleUser(req: Request, res: Response): Future[void] {.async.} =
  res.json(%*{"user": req.urlParams["user"]})

router.addRoute("/user/:user", handleUser)
router.addRoute("/multi/:first/:second", handleMultiParam)
```

### Query parameters

```nim
proc handleQuery(req: Request, res: Response): Future[void] {.async.} =
  res.json(%*{"params": req.queryParams})
```

Request: `GET /query?page=1&limit=10` gives `req.queryParams["page"]` = `"1"`.

## Request/Response

### JSON helpers

```nim
# Parse JSON body
proc handlePost(req: Request, res: Response): Future[void] {.async.} =
  let body = req.parseJsonBody()
  if body.kind != JNull:
    res.json(%*{"received": body})
  else:
    res.abortWith("invalid json", Http400)

# Send JSON response
res.json(%*{"status": "ok"})
res.json(%*{"error": "not found"}, Http404)
```

### Form data

```nim
proc handleForm(req: Request, res: Response): Future[void] {.async.} =
  let username = req.formData.getValueOrNone("username")
  res.json(%*{"user": username.get("")})
```

### Cookies

```nim
proc handleCookies(req: Request, res: Response): Future[void] {.async.} =
  let session = req.cookies.getOrDefault("session", "")
  res.headers["Set-Cookie"] = "session=abc123; Path=/"
```

### Response helpers

```nim
res.abortWith("forbidden", Http403)
res.redirectTo("/", Http302)
res.setHeader("X-Custom", "value")
res.addHeader("X-Another", "value")
```

## Server options

```nim
let opts = newServerOptions(
  address = "0.0.0.0",
  port = 8080,
  debug = true,
  maxBodySize = 10 * 1024 * 1024,  # 10MB body limit
  requestTimeout = 30,              # seconds
  keepAlive = true,
  keepAliveTimeout = 5
)
```

- **Graceful shutdown**: SIGINT/SIGTERM handled cleanly
- **Body size limits**: Returns 413 if request body exceeds `maxBodySize`
- **Keep-alive**: Connection reuse controlled by `keepAlive` and `keepAliveTimeout`
- **Error handling**: Uncaught exceptions return 500 with JSON error body

## Middleware

Middleware procs return `Future[bool]`. Return `true` to continue, `false` to short-circuit.

### Production middleware

```nim
import servy/middleware_prod

# CORS
let cors = newCorsMiddleware(newCorsConfig())

# Rate limiting
let limiter = newRateLimiter(limit = 100, windowSeconds = 60)
let rateLimit = newRateLimitMiddleware(limiter)

# Request ID (adds X-Request-ID header)
let reqId = requestIdMiddleware()

# Security headers (CSP, X-Frame-Options, HSTS, etc.)
let security = newSecurityHeadersMiddleware()

# Request timing (adds X-Response-Time header)
let timing = requestTimingMiddleware()

# Gzip compression (adds Content-Encoding: gzip for large responses)
let gzip = gzipMiddleware()

# Body size limit
let bodyLimit = newRequestSizeLimitMiddleware(maxBodyBytes = 10 * 1024 * 1024)

# Structured logging
let logger = logMiddleware(level = Info)

# Apache-style request logging
let accessLog = requestLoggerMiddleware()
```

### Use in server

```nim
var s = initServy(opts, router, @[
  reqId,
  security,
  cors,
  rateLimit,
  logger,
  timing,
  gzip
])
```

### Built-in middleware

```nim
import servy/middleware

# Logging
let logging = loggingMiddleware

# Trim trailing slashes
let trimSlash = trimTrailingSlash

# Static files
let serveStatic = newStaticMiddleware("/path/to/files", "/public")

# Basic auth
let users = {"admin": "secret"}.toTable
let auth = basicAuth(users)
```

### Custom middleware

```nim
proc myMiddleware(req: Request, res: Response): Future[bool] {.async, closure, gcsafe.} =
  let token = req.headers.getOrDefault("authorization", @[""])[0]
  if token == "Bearer secret":
    return true
  else:
    res.abortWith("unauthorized", Http401)
    return false

router.addRoute("/protected", handleGet, HttpGet, @[myMiddleware])
```

**Nim 2.x note:** Local middleware procs must use `{.async, closure, gcsafe.}` pragmas.

### Per-route vs global

```nim
# Per-route
router.addRoute("/admin", handleAdmin, HttpGet, @[auth])

# Global (applied to all routes)
var s = initServy(opts, router, @[reqId, security, logging])
```

## WebSocket

Built-in WebSocket support (no external dependencies):

```nim
proc handleWS(req: Request, res: Response): Future[void] {.async.} =
  var ws = await newServyWebSocket(req)
  await ws.send("Welcome!")
  while ws.readyState == Open:
    let packet = await ws.receiveStrPacket()
    await ws.send("echo: " & packet)

router.addRoute("/ws", handleWS, HttpGet)
```

Test with JavaScript:
```javascript
ws = new WebSocket("ws://127.0.0.1:9000/ws")
ws.onmessage = (m) => console.log(m.data)
ws.send("hello")
```

## Health check

```nim
router.addRoute("/health", healthCheckHandler)
# Returns {"status":"ok"} with 200
```

## Module structure

```
servy/
  types.nim          # Core types, JSON helpers
  router.nim         # Route matching
  parser.nim         # HTTP request parsing
  response.nim       # Response formatting
  middleware.nim      # Basic middleware (logging, static, auth)
  middleware_prod.nim # Production middleware (CORS, rate limit, security, etc.)
  websocket.nim      # Built-in WebSocket
  server.nim         # Server, graceful shutdown, timeouts
  servy.nim          # Facade
```

## Running

```bash
nim c -r examples/hello.nim
# or
nimble run servy
```

## Testing

```bash
make test    # Run 24 tests
make build   # Build all
```

## Curl examples

```bash
curl localhost:9000/hello
curl localhost:9000/user/alice
curl -X POST -d '{"name":"john"}' -H "Content-Type: application/json" localhost:9000/api
curl -b "session=xyz" localhost:9000/cookies
curl -H "Authorization: Basic YWRtaW46c2VjcmV0" localhost:9000/admin
curl localhost:9000/health
```
