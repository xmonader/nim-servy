import tables, asyncnet, options, strutils, strformat, asyncdispatch, net

type
  HttpVersion* = enum
    HttpVer11,
    HttpVer10

  HttpMethod* = enum
    HttpHead,
    HttpGet,
    HttpPost,
    HttpPut,
    HttpDelete,
    HttpTrace,
    HttpOptions,
    HttpConnect,
    HttpPatch

  HttpCode* = distinct range[0 .. 599]

const
  Http100* = HttpCode(100)
  Http101* = HttpCode(101)
  Http200* = HttpCode(200)
  Http201* = HttpCode(201)
  Http202* = HttpCode(202)
  Http203* = HttpCode(203)
  Http204* = HttpCode(204)
  Http205* = HttpCode(205)
  Http206* = HttpCode(206)
  Http300* = HttpCode(300)
  Http301* = HttpCode(301)
  Http302* = HttpCode(302)
  Http303* = HttpCode(303)
  Http304* = HttpCode(304)
  Http305* = HttpCode(305)
  Http307* = HttpCode(307)
  Http400* = HttpCode(400)
  Http401* = HttpCode(401)
  Http403* = HttpCode(403)
  Http404* = HttpCode(404)
  Http405* = HttpCode(405)
  Http406* = HttpCode(406)
  Http407* = HttpCode(407)
  Http408* = HttpCode(408)
  Http409* = HttpCode(409)
  Http410* = HttpCode(410)
  Http411* = HttpCode(411)
  Http412* = HttpCode(412)
  Http413* = HttpCode(413)
  Http414* = HttpCode(414)
  Http415* = HttpCode(415)
  Http416* = HttpCode(416)
  Http417* = HttpCode(417)
  Http418* = HttpCode(418)
  Http421* = HttpCode(421)
  Http422* = HttpCode(422)
  Http426* = HttpCode(426)
  Http428* = HttpCode(428)
  Http429* = HttpCode(429)
  Http431* = HttpCode(431)
  Http451* = HttpCode(451)
  Http500* = HttpCode(500)
  Http501* = HttpCode(501)
  Http502* = HttpCode(502)
  Http503* = HttpCode(503)
  Http504* = HttpCode(504)
  Http505* = HttpCode(505)

proc `$`*(code: HttpCode): string =
  case code.int
  of 100: "100 Continue"
  of 101: "101 Switching Protocols"
  of 200: "200 OK"
  of 201: "201 Created"
  of 202: "202 Accepted"
  of 203: "203 Non-Authoritative Information"
  of 204: "204 No Content"
  of 205: "205 Reset Content"
  of 206: "206 Partial Content"
  of 300: "300 Multiple Choices"
  of 301: "301 Moved Permanently"
  of 302: "302 Found"
  of 303: "303 See Other"
  of 304: "304 Not Modified"
  of 305: "305 Use Proxy"
  of 307: "307 Temporary Redirect"
  of 400: "400 Bad Request"
  of 401: "401 Unauthorized"
  of 403: "403 Forbidden"
  of 404: "404 Not Found"
  of 405: "405 Method Not Allowed"
  of 406: "406 Not Acceptable"
  of 407: "407 Proxy Authentication Required"
  of 408: "408 Request Timeout"
  of 409: "409 Conflict"
  of 410: "410 Gone"
  of 411: "411 Length Required"
  of 412: "412 Precondition Failed"
  of 413: "413 Request Entity Too Large"
  of 414: "414 Request-URI Too Long"
  of 415: "415 Unsupported Media Type"
  of 416: "416 Requested Range Not Satisfiable"
  of 417: "417 Expectation Failed"
  of 418: "418 I'm a teapot"
  of 421: "421 Misdirected Request"
  of 422: "422 Unprocessable Entity"
  of 426: "426 Upgrade Required"
  of 428: "428 Precondition Required"
  of 429: "429 Too Many Requests"
  of 431: "431 Request Header Fields Too Large"
  of 451: "451 Unavailable For Legal Reasons"
  of 500: "500 Internal Server Error"
  of 501: "501 Not Implemented"
  of 502: "502 Bad Gateway"
  of 503: "503 Service Unavailable"
  of 504: "504 Gateway Timeout"
  of 505: "505 HTTP Version Not Supported"
  of 506: "506 Variant Also Negotiates"
  of 507: "507 Insufficient Storage"
  of 508: "508 Loop Detected"
  of 510: "510 Not Extended"
  of 511: "511 Network Authentication Required"
  of 599: "599 Network Connect Timeout Error"
  else: $(int(code))

type
  ServyError* = object of CatchableError
  RoutingError* = object of ServyError
  ParseError* = object of ServyError
  HandshakeError* = object of ServyError

type HttpHeaders* = ref object
  table*: TableRef[string, seq[string]]

type HttpHeaderValues* = seq[string]

proc newHttpHeaders*(): HttpHeaders =
  new result
  result.table = newTable[string, seq[string]]()

proc newHttpHeaders*(keyValuePairs: seq[tuple[key: string, val: string]]): HttpHeaders =
  var pairs: seq[tuple[key: string, val: seq[string]]] = @[]
  for pair in keyValuePairs:
    pairs.add((pair.key.toLowerAscii(), @[pair.val]))
  new result
  result.table = newTable[string, seq[string]](pairs)

proc `$`*(headers: HttpHeaders): string =
  return $headers.table

proc clear*(headers: HttpHeaders) =
  headers.table.clear()

proc `[]`*(headers: HttpHeaders, key: string): HttpHeaderValues =
  return headers.table[key.toLowerAscii].HttpHeaderValues

proc `[]`*(headers: HttpHeaders, key: string, i: int): string =
  return headers.table[key.toLowerAscii][i]

proc `[]=`*(headers: HttpHeaders, key, value: string) =
  headers.table[key.toLowerAscii] = @[value]

proc `[]=`*(headers: HttpHeaders, key: string, value: seq[string]) =
  headers.table[key.toLowerAscii] = value

proc add*(headers: HttpHeaders, key, value: string) =
  if not headers.table.hasKey(key.toLowerAscii):
    headers.table[key.toLowerAscii] = @[value]
  else:
    headers.table[key.toLowerAscii].add(value)

proc addMany*(headers: HttpHeaders, key: string, value: seq[string]) =
  for val in value:
    headers.add(key, val)

proc del*(headers: HttpHeaders, key: string) =
  headers.table.del(key.toLowerAscii)

iterator pairs*(headers: HttpHeaders): tuple[key, value: string] =
  for k, v in headers.table:
    for value in v:
      yield (k, value)

proc contains*(values: HttpHeaderValues, value: string): bool =
  for val in seq[string](values):
    if val.toLowerAscii == value.toLowerAscii: return true

proc hasKey*(headers: HttpHeaders, key: string): bool =
  return headers.table.hasKey(key.toLowerAscii())

proc getOrDefault*(headers: HttpHeaders, key: string,
    default = @[""].HttpHeaderValues): HttpHeaderValues =
  if headers.hasKey(key):
    return headers[key]
  else:
    return default

proc len*(headers: HttpHeaders): int = return headers.table.len

type SameSite* = enum
  None, Strict, Lax

proc `$`*(ver: HttpVersion): string =
  case ver
  of HttpVer10: result = "HTTP/1.0"
  of HttpVer11: result = "HTTP/1.1"

proc `$`*(m: HttpMethod): string =
  case m
  of HttpHead: result = "HEAD"
  of HttpGet: result = "GET"
  of HttpPost: result = "POST"
  of HttpPut: result = "PUT"
  of HttpDelete: result = "DELETE"
  of HttpTrace: result = "TRACE"
  of HttpOptions: result = "OPTIONS"
  of HttpConnect: result = "CONNECT"
  of HttpPatch: result = "PATCH"

type FormPart* = object
  name*: string
  headers*: HttpHeaders
  fileName*: string
  body*: string

proc initFormPart*(): FormPart =
  result.headers = newHttpHeaders()

proc `$`*(this: FormPart): string =
  result = fmt"name: {this.name} filename: {this.fileName} headers: {this.headers} body: {this.body}"

type FormMultiPart* = object
  parts*: Table[string, FormPart]

proc initFormMultiPart*(): FormMultiPart =
  result.parts = initTable[string, FormPart]()

proc `$`*(this: FormMultiPart): string =
  return fmt"parts: {this.parts}"

proc hasKey*(this: FormMultiPart, key: string): bool =
  result = this.parts.hasKey(key)

proc getPart*(this: FormMultiPart, name: string): Option[FormPart] =
  if this.hasKey(name):
    return some(this.parts[name])
  return none(FormPart)

proc getValueOrNone*(this: FormMultiPart, name: string): Option[string] =
  if this.hasKey(name):
    return some(this.parts[name].body.strip)
  return none(string)

proc getValue*(this: FormMultiPart, name: string): string =
  if this.hasKey(name):
    return this.parts[name].body.strip
  else:
    raise newException(KeyError, fmt"${name} not found.")

type Request* = ref object
  httpMethod*: HttpMethod
  requestURI*: string
  httpVersion*: HttpVersion
  headers*: HttpHeaders
  path*: string
  body*: string
  queryParams*: Table[string, string]
  formData*: FormMultiPart
  urlParams*: Table[string, string]
  cookies*: Table[string, string]
  asyncSock*: AsyncSocket

proc `$`*(r: Request): string =
  result.add "*******RequestInfo*******\n"
  result.add "Path: " & r.path & "\n"
  result.add "Method: " & $r.httpMethod & "\n"
  result.add "Headers: " & $r.headers & "\n"
  result.add "Cookies: " & $r.cookies & "\n"
  result.add "QueryParams: " & $r.queryParams & "\n"
  result.add "URLParams: " & $r.urlParams & "\n"
  result.add "FormData: " & $r.formData & "\n"
  result.add "***************************"

type Response* = ref object
  headers*: HttpHeaders
  httpver*: HttpVersion
  code*: HttpCode
  content*: string

proc newResponse*(): Response =
  result.new
  result.httpver = HttpVer11
  result.headers = newHttpHeaders()

type
  MiddlewareFunc* = proc(req: Request, res: Response): Future[bool] {.closure, gcsafe.}
  HandlerFunc* = proc(req: Request, res: Response): Future[void] {.closure, gcsafe.}

proc abortWith*(res: Response, msg: string, code = Http404) =
  res.code = code
  res.content = msg

proc redirectTo*(res: Response, url: string, code = Http301) =
  res.code = code
  res.headers.add("Location", url)

proc ip*(req: Request): string =
  let headers = req.headers
  if headers.hasKey("REMOTE_ADDR"):
    result = headers["REMOTE_ADDR"][0]
  if headers.hasKey("x-forwarded-for"):
    result = headers["x-forwarded-for"][0]

proc params*(req: Request): Table[string, string] =
  result = req.urlParams

proc secure*(req: Request): bool =
  if req.headers.hasKey("x-forwarded-proto"):
    let proto = req.headers["x-forwarded-proto"][0]
    case proto.toLowerAscii()
    of "https":
      result = true
    of "http":
      result = false
    else:
      result = false

proc port*(req: Request): int =
  if (let p = req.headers.getOrDefault("SERVER_PORT")[0]; p != ""):
    result = p.parseInt
  else:
    result = if req.secure: 443 else: 80

proc host*(req: Request): string =
  req.headers.getOrDefault("HOST")[0]
