import asyncdispatch, tables, os, strformat, strutils, options
import servy
import servy/types

when isMainModule:
  # --- Handlers ---

  proc handleIndex(req: Request, res: Response) {.async.} =
    res.code = Http200
    res.content = "Welcome to servy!"

  proc handleGet(req: Request, res: Response) {.async.} =
    res.code = Http200
    res.content = "GET request"

  proc handlePost(req: Request, res: Response) {.async.} =
    res.code = Http201
    res.content = "POST request"

  proc handlePut(req: Request, res: Response) {.async.} =
    res.code = Http200
    res.content = "PUT request"

  proc handleDelete(req: Request, res: Response) {.async.} =
    res.code = Http200
    res.content = "DELETE request"

  proc handleUser(req: Request, res: Response) {.async.} =
    res.code = Http200
    res.content = "user=" & req.urlParams["user"]

  proc handleMultiParam(req: Request, res: Response) {.async.} =
    res.code = Http200
    res.content = "first=" & req.urlParams["first"] & " second=" & req.urlParams["second"]

  proc handleQuery(req: Request, res: Response) {.async.} =
    res.code = Http200
    var params: seq[string] = @[]
    for k, v in req.queryParams.pairs:
      params.add(k & "=" & v)
    res.content = "query: " & params.join(", ")

  proc handleFormUrlEncoded(req: Request, res: Response) {.async.} =
    res.code = Http200
    let username = req.formData.getValueOrNone("username")
    let password = req.formData.getValueOrNone("password")
    res.content = "username=" & username.get("") & " password=" & password.get("")

  proc handleMultipart(req: Request, res: Response) {.async.} =
    res.code = Http200
    let name = req.formData.getValueOrNone("name")
    res.content = "name=" & name.get("")

  proc handleCookies(req: Request, res: Response) {.async.} =
    res.code = Http200
    var cookies: seq[string] = @[]
    for k, v in req.cookies.pairs:
      cookies.add(k & "=" & v)
    res.content = "cookies: " & cookies.join(", ")

  proc handleSetCookie(req: Request, res: Response) {.async.} =
    res.code = Http200
    res.headers["Set-Cookie"] = "session=abc123; Path=/"
    res.content = "cookie set"

  proc handleHeaders(req: Request, res: Response) {.async.} =
    res.code = Http200
    res.headers["X-Custom"] = "test-value"
    res.headers["X-Another"] = "another-value"
    res.content = "headers set"

  proc handleAbort(req: Request, res: Response) {.async.} =
    res.abortWith("forbidden", Http403)

  proc handleAbort404(req: Request, res: Response) {.async.} =
    res.abortWith("not found")

  proc handleRedirect(req: Request, res: Response) {.async.} =
    res.redirectTo("/")

  proc handleWS(req: Request, res: Response) {.async.} =
    var ws = await newServyWebSocket(req)
    await ws.send("Welcome to WebSocket!")
    while ws.readyState == Open:
      let packet = await ws.receiveStrPacket()
      await ws.send("echo: " & packet)

  # --- Middleware ---

  proc myLoggingMiddleware(request: Request, response: Response): Future[bool] {.async.} =
    return true

  # --- Routes ---

  var router = initRouter()

  # Basic routing
  router.addRoute("/", handleIndex)
  router.addRoute("/get", handleGet, HttpGet)
  router.addRoute("/post", handlePost, HttpPost)
  router.addRoute("/put", handlePut, HttpPut)
  router.addRoute("/delete", handleDelete, HttpDelete)

  # URL parameters
  router.addRoute("/user/:user", handleUser)
  router.addRoute("/multi/:first/:second", handleMultiParam)

  # Query parameters
  router.addRoute("/query", handleQuery)

  # Form data
  router.addRoute("/form-urlencoded", handleFormUrlEncoded, HttpPost)
  router.addRoute("/multipart", handleMultipart, HttpPost)

  # Cookies
  router.addRoute("/cookies", handleCookies)
  router.addRoute("/set-cookie", handleSetCookie)

  # Headers
  router.addRoute("/headers", handleHeaders)

  # Abort and redirect
  router.addRoute("/abort", handleAbort)
  router.addRoute("/abort404", handleAbort404)
  router.addRoute("/redirect", handleRedirect)

  # WebSocket
  router.addRoute("/ws", handleWS, HttpGet)

  # Per-route middleware
  var users = initTable[string, string]()
  users["admin"] = "secret"
  let authMiddleware: MiddlewareFunc = basicAuth(users)
  router.addRoute("/protected", handleGet, HttpGet, @[authMiddleware])

  # Static files
  let serveStatic: MiddlewareFunc = newStaticMiddleware(parentDir(currentSourcePath()) / "public", "/static")

  let port = parseInt(paramStr(1))
  let opts = ServerOptions(address: "127.0.0.1", port: Port(port), debug: false)
  var s = initServy(opts, router, @[MiddlewareFunc(myLoggingMiddleware), serveStatic])
  s.run()
