import asyncdispatch, asyncnet, strformat, net
import types, router, parser, response

type ServerOptions* = object
  address*: string
  port*: Port
  debug*: bool

type Servy* = object
  options*: ServerOptions
  router*: Router
  middlewares*: seq[MiddlewareFunc]
  sock*: AsyncSocket

template logMsg*(s: Servy, m: string) =
  if s.options.debug:
    echo m

proc handleClient*(s: Servy, client: AsyncSocket) {.async.} =
  var req = await parseRequestFromConnection(client)
  var res = newResponse()
  res.headers = newHttpHeaders()

  for m in s.middlewares:
    let usenextmiddleware = await m(req, res)
    if not usenextmiddleware:
      s.logMsg "early return from middleware..."
      await client.send(res.format())
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
      return
  try:
    await handler(req, res)
  except Exception:
    s.logMsg "handler error: " & getCurrentExceptionMsg()

  s.logMsg "reached the handler safely.. and executing now."
  await client.send(res.format())

proc serve*(s: Servy) {.async.} =
  s.sock.bindAddr(s.options.port)
  s.sock.listen()
  while true:
    let client = await s.sock.accept()
    asyncCheck s.handleClient(client)

  runForever()

proc initServy*(options: ServerOptions, router: Router, middlewares: seq[MiddlewareFunc]): Servy =
  result.options = options
  result.router = router
  result.middlewares = middlewares

  result.sock = newAsyncSocket()
  result.sock.setSockOpt(OptReuseAddr, true)

proc run*(s: Servy) =
  if s.options.debug:
    s.router.printRegisteredRoutes()
  asyncCheck s.serve()
  echo fmt"servy started...{s.options}"
  runForever()
