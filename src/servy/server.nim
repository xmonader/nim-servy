import asyncdispatch, asyncnet, strformat, strutils, net, os, times, posix, std/monotimes
import servy/types, servy/router, servy/parser, servy/response

type ServerOptions* = object
  address*: string
  port*: Port
  debug*: bool
  maxBodySize*: int
  requestTimeout*: int
  keepAlive*: bool
  keepAliveTimeout*: int

type Servy* = object
  options*: ServerOptions
  router*: Router
  middlewares*: seq[MiddlewareFunc]
  sock*: AsyncSocket
  running*: bool

var gShutdownRequested = false
var gServerSock: AsyncSocket

proc shutdownHandler(sig: cint) {.noconv.} =
  gShutdownRequested = true
  if gServerSock != nil:
    gServerSock.close()
  echo "\nshutting down gracefully..."

template logMsg*(s: Servy, m: string) =
  if s.options.debug:
    echo m

proc handleClient*(s: Servy, client: AsyncSocket) {.async.} =
  let startTime = getMonoTime()
  try:
    var req = await parseRequestFromConnection(client)
    var res = newResponse()
    res.headers = newHttpHeaders()

    # Enforce body size limit
    if req.body.len > s.options.maxBodySize:
      res.code = Http413
      res.headers["Content-Type"] = "application/json"
      res.content = """{"error":"request body too large","max_bytes":""" & $s.options.maxBodySize & "}"
      await client.send(res.format())
      client.close()
      return

    for m in s.middlewares:
      let usenextmiddleware = await m(req, res)
      if not usenextmiddleware:
        s.logMsg "early return from middleware..."
        await client.send(res.format())
        client.close()
        return

    s.logMsg "received request from client: " & $req

    let (routeHandler, params) = s.router.getByPath(req.path, req.httpMethod)
    req.urlParams = params
    let handler = routeHandler.handlerFunc
    let middlewares = routeHandler.middlewares

    for m in middlewares:
      let usenextmiddleware = await m(req, res)
      if not usenextmiddleware:
        s.logMsg "early return from route middleware..."
        await client.send(res.format())
        client.close()
        return
    try:
      await handler(req, res)
    except CatchableError as e:
      s.logMsg "handler error: " & e.msg
      if res.code.int == 200:
        res.code = Http500
        res.headers["Content-Type"] = "application/json"
        res.content = """{"error":"internal server error"}"""

    # Set response timing
    let elapsed = (getMonoTime() - startTime).inMilliseconds
    res.headers["X-Response-Time"] = $elapsed & "ms"

    s.logMsg "reached the handler safely.. and executing now."
    await client.send(res.format())

    # Keep-alive handling
    if s.options.keepAlive:
      let connHeader = req.headers.getOrDefault("Connection", @[""])[0]
      if connHeader.toLowerAscii() == "close":
        client.close()
    else:
      client.close()

  except CatchableError as e:
    s.logMsg "client error: " & e.msg
    try:
      var errRes = newResponse()
      errRes.code = Http500
      errRes.headers["Content-Type"] = "application/json"
      errRes.content = """{"error":"internal server error"}"""
      await client.send(errRes.format())
    except CatchableError:
      discard
    client.close()

proc serve*(s: Servy) {.async.} =
  s.sock.bindAddr(s.options.port)
  s.sock.listen()
  gServerSock = s.sock
  echo fmt"servy listening on {s.options.address}:{s.options.port}"

  while not gShutdownRequested:
    try:
      let client = await s.sock.accept()
      if gShutdownRequested:
        break
      asyncCheck s.handleClient(client)
    except CatchableError:
      if gShutdownRequested:
        break
      s.logMsg "accept error: " & getCurrentExceptionMsg()

  echo "server stopped"

proc initServy*(options: ServerOptions, router: Router, middlewares: seq[MiddlewareFunc] = @[]): Servy =
  result.options = options
  result.router = router
  result.middlewares = middlewares
  result.running = true

  result.sock = newAsyncSocket()
  result.sock.setSockOpt(OptReuseAddr, true)

  # Set up graceful shutdown
  discard signal(SIGINT, shutdownHandler)
  discard signal(SIGTERM, shutdownHandler)

proc run*(s: Servy) =
  if s.options.debug:
    s.router.printRegisteredRoutes()
  asyncCheck s.serve()
  try:
    runForever()
  except ValueError:
    discard

proc newServerOptions*(address = "127.0.0.1", port = 8080, debug = false,
                        maxBodySize = 10 * 1024 * 1024,
                        requestTimeout = 30,
                        keepAlive = true,
                        keepAliveTimeout = 5): ServerOptions =
  result.address = address
  result.port = Port(port)
  result.debug = debug
  result.maxBodySize = maxBodySize
  result.requestTimeout = requestTimeout
  result.keepAlive = keepAlive
  result.keepAliveTimeout = keepAliveTimeout
