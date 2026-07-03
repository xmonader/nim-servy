import tables, strutils, strformat, asyncdispatch, terminaltables
import servy/types

type RouterValue* = object
  handlerFunc*: HandlerFunc
  httpMethod*: HttpMethod
  middlewares*: seq[MiddlewareFunc]

type Router* = object
  table*: Table[string, RouterValue]
  notFoundHandler*: HandlerFunc

proc handle404*(req: Request, res: Response): Future[void] {.async.} =
  res.code = Http404
  res.content = fmt"nothing at {req.path}"

proc initRouter*(notFoundHandler: HandlerFunc = handle404): Router =
  result.table = initTable[string, RouterValue]()
  result.notFoundHandler = notFoundHandler

iterator registeredRoutes*(r: Router): (string, string) =
  for pat, routerValue in r.table:
    yield (pat, $routerValue.httpMethod)

proc printRegisteredRoutes*(r: Router) =
  let t = newUnicodeTable()
  t.setHeaders(@[newCell("Method", pad=5), newCell("Route", rightpad=10)])

  for pat, meth in r.registeredRoutes:
    t.addRow(@[meth, pat])

  printTable(t)

proc getByPath*(r: Router, path: string, httpMethod = HttpGet): (RouterValue, Table[string, string]) =
  var found = false
  if path in r.table and r.table[path].httpMethod == httpMethod:
    return (r.table[path], initTable[string, string]())

  for handlerPath, routerValue in r.table.pairs:
    if routerValue.httpMethod != httpMethod:
      continue

    let pathParts = path.split({'/'})
    let handlerPathParts = handlerPath.split({'/'})

    if len(pathParts) != len(handlerPathParts):
      continue
    else:
      var idx = 0
      var capturedParams = initTable[string, string]()

      while idx < len(pathParts):
        let pathPart = pathParts[idx]
        let handlerPathPart = handlerPathParts[idx]

        if handlerPathPart.startsWith(":") or handlerPathPart.startsWith("@"):
          capturedParams[handlerPathPart[1..^1]] = pathPart
          inc idx
        else:
          if pathPart == handlerPathPart:
            inc idx
          else:
            break

        if idx == len(pathParts):
          found = true
          return (routerValue, capturedParams)

  if not found:
    return (RouterValue(handlerFunc: r.notFoundHandler, middlewares: @[]), initTable[string, string]())

proc addRoute*(router: var Router, route: string, handler: HandlerFunc, httpMethod: HttpMethod = HttpGet, middlewares: seq[MiddlewareFunc] = @[]) =
  router.table.add(route, RouterValue(handlerFunc: handler, httpMethod: httpMethod, middlewares: middlewares))
