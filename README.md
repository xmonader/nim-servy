# servy

Servy is a fast, simple and lightweight micro web-framework for Nim, supporting Nim 2.x.

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
    res.code = Http200
    res.content = "hello world!"

  router.addRoute("/hello", handleHello)

  let opts = ServerOptions(address: "127.0.0.1", port: 9000.Port, debug: true)
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

Use `:param` to capture URL segments:

```nim
proc handleUser(req: Request, res: Response): Future[void] {.async.} =
  res.content = "user=" & req.urlParams["user"]

router.addRoute("/user/:user", handleUser)
router.addRoute("/multi/:first/:second", handleMultiParam)
```

Captured parameters are available in `req.urlParams`.

### Query parameters

Query parameters are automatically parsed from the URL:

```nim
proc handleQuery(req: Request, res: Response): Future[void] {.async.} =
  for k, v in req.queryParams.pairs:
    res.content.add(k & "=" & v & " ")

router.addRoute("/query", handleQuery)
```

Request: `GET /query?page=1&limit=10` gives `req.queryParams["page"]` = `"1"`.

## Request data

### Form data (URL-encoded and multipart)

```nim
proc handleForm(req: Request, res: Response): Future[void] {.async.} =
  let username = req.formData.getValueOrNone("username")
  let password = req.formData.getValueOrNone("password")
  res.content = "user=" & username.get("") & " pass=" & password.get("")

router.addRoute("/login", handleForm, HttpPost)
```

### Cookies

```nim
proc handleCookies(req: Request, res: Response): Future[void] {.async.} =
  for k, v in req.cookies.pairs:
    res.content.add(k & "=" & v & " ")

router.addRoute("/cookies", handleCookies)
```

### Setting response cookies

```nim
proc handleSetCookie(req: Request, res: Response): Future[void] {.async.} =
  res.headers["Set-Cookie"] = "session=abc123; Path=/"
  res.content = "cookie set"
```

### Custom response headers

```nim
proc handleHeaders(req: Request, res: Response): Future[void] {.async.} =
  res.headers["X-Custom"] = "test-value"
  res.content = "headers set"
```

## Response helpers

### Abort (return error with status code)

```nim
proc handleAbort(req: Request, res: Response): Future[void] {.async.} =
  res.abortWith("forbidden", Http403)
```

### Redirect

```nim
proc handleRedirect(req: Request, res: Response): Future[void] {.async.} =
  res.redirectTo("/")
  # or with custom code: res.redirectTo("/", Http302)
```

## Middleware

Middleware procs return `Future[bool]`. Return `true` to continue, `false` to short-circuit.

### Built-in middleware

```nim
import servy/middleware

# Logging
proc loggingMiddleware*(request: Request, response: Response): Future[bool] {.async.} =
  echo request.httpMethod, " ", request.path
  return true

# Trim trailing slashes
proc trimTrailingSlash*(request: Request, response: Response): Future[bool] {.async.} =
  if request.path.endsWith("/"):
    request.path = request.path[0 .. ^2]
  return true
```

### Static file serving

```nim
let serveStatic = newStaticMiddleware("/path/to/files", "/public")
# Serves files from /path/to/files at URL prefix /public
```

### Basic authentication

```nim
import tables

let users = {"admin": "secret", "user": "pass"}.toTable
let authMiddleware = basicAuth(users)

proc handleProtected(req: Request, res: Response): Future[void] {.async.} =
  res.content = "welcome!"

router.addRoute("/admin", handleProtected, HttpGet, @[authMiddleware])
```

### Custom per-route middleware

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

**Important for Nim 2.x:** Local middleware procs must use `{.async, closure, gcsafe.}` pragms.

### Global middleware (applied to all routes)

```nim
var s = initServy(opts, router, @[loggingMiddleware, trimTrailingSlash, serveStatic])
```

## WebSocket support

Servy integrates with [treeform/ws](https://github.com/treeform/ws):

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

## Module structure

```
servy/
  types.nim      # Core types (Request, Response, HandlerFunc, MiddlewareFunc)
  router.nim     # Route matching and registration
  parser.nim     # HTTP request parsing
  response.nim   # Response formatting
  middleware.nim  # Built-in middleware (logging, static, auth)
  websocket.nim  # WebSocket integration
  server.nim     # Server startup and request handling
  servy.nim      # Facade that re-exports all modules
```

## Running

```bash
nim c -r examples/hello.nim
# or
nimble run servy
```

Then visit `http://localhost:9000/hello`.

## Curl examples

```bash
curl localhost:9000/hello
curl localhost:9000/user/alice
curl localhost:9000/multi/foo/bar
curl -X POST -d "username=john&password=doe" localhost:9000/login
curl -b "session=xyz" localhost:9000/cookies
curl -H "Authorization: Basic YWRtaW46c2VjcmV0" localhost:9000/admin
```
