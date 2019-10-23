# This is just an example to get you started. A typical binary package
# uses this file as the main entry point of the application.

import strformat, tables, json, strutils, asyncdispatch, asyncnet, strutils, parseutils, options, net
from cgi import decodeUrl


type
  HttpVersion* = enum
    HttpVer11,
    HttpVer10

  HttpMethod* = enum  ## the requested HttpMethod
    HttpHead,         ## Asks for the response identical to the one that would
                      ## correspond to a GET request, but without the response
                      ## body.
    HttpGet,          ## Retrieves the specified resource.
    HttpPost,         ## Submits data to be processed to the identified
                      ## resource. The data is included in the body of the
                      ## request.
    HttpPut,          ## Uploads a representation of the specified resource.
    HttpDelete,       ## Deletes the specified resource.
    HttpTrace,        ## Echoes back the received request, so that a client
                      ## can see what intermediate servers are adding or
                      ## changing in the request.
    HttpOptions,      ## Returns the HTTP methods that the server supports
                      ## for specified address.
    HttpConnect,      ## Converts the request connection to a transparent
                      ## TCP/IP tunnel, usually used for proxies.
    HttpPatch         ## Applies partial modifications to a resource.


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
    ## Converts the specified ``HttpCode`` into a HTTP status.
    ##
    ## For example:
    ##
    ##   .. code-block:: nim
    ##       doAssert($Http404 == "404 Not Found")
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

const headerLimit* = 10_000


type HttpHeaders* = ref object
      table*: TableRef[string, seq[string]]

type HttpHeaderValues* =  seq[string]

proc newHttpHeaders*(): HttpHeaders =
  new result
  result.table = newTable[string, seq[string]]()

proc newHttpHeaders*(keyValuePairs:
    seq[tuple[key: string, val: string]]): HttpHeaders =
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
  ## Returns the values associated with the given ``key``. If the returned
  ## values are passed to a procedure expecting a ``string``, the first
  ## value is automatically picked. If there are
  ## no values associated with the key, an exception is raised.
  ##
  ## To access multiple values of a key, use the overloaded ``[]`` below or
  ## to get all of them access the ``table`` field directly.
  return headers.table[key.toLowerAscii].HttpHeaderValues

# converter toString*(values: HttpHeaderValues): string =
#   return seq[string](values)[0]

proc `[]`*(headers: HttpHeaders, key: string, i: int): string =
  ## Returns the ``i``'th value associated with the given key. If there are
  ## no values associated with the key or the ``i``'th value doesn't exist,
  ## an exception is raised.
  return headers.table[key.toLowerAscii][i]

proc `[]=`*(headers: HttpHeaders, key, value: string) =
  ## Sets the header entries associated with ``key`` to the specified value.
  ## Replaces any existing values.
  headers.table[key.toLowerAscii] = @[value]

proc `[]=`*(headers: HttpHeaders, key: string, value: seq[string]) =
  ## Sets the header entries associated with ``key`` to the specified list of
  ## values.
  ## Replaces any existing values.
  headers.table[key.toLowerAscii] = value

proc add*(headers: HttpHeaders, key, value: string) =
  ## Adds the specified value to the specified key. Appends to any existing
  ## values associated with the key.
  if not headers.table.hasKey(key.toLowerAscii):
    headers.table[key.toLowerAscii] = @[value]
  else:
    headers.table[key.toLowerAscii].add(value)

proc del*(headers: HttpHeaders, key: string) =
  ## Delete the header entries associated with ``key``
  headers.table.del(key.toLowerAscii)

iterator pairs*(headers: HttpHeaders): tuple[key, value: string] =
  ## Yields each key, value pair.
  for k, v in headers.table:
    for value in v:
      yield (k, value)

proc contains*(values: HttpHeaderValues, value: string): bool =
  ## Determines if ``value`` is one of the values inside ``values``. Comparison
  ## is performed without case sensitivity.
  for val in seq[string](values):
    if val.toLowerAscii == value.toLowerAscii: return true

proc hasKey*(headers: HttpHeaders, key: string): bool =
  return headers.table.hasKey(key.toLowerAscii())

proc getOrDefault*(headers: HttpHeaders, key: string,
    default = @[""].HttpHeaderValues): HttpHeaderValues =
  ## Returns the values associated with the given ``key``. If there are no
  ## values associated with the key, then ``default`` is returned.
  if headers.hasKey(key):
    return headers[key]
  else:
    return default

proc len*(headers: HttpHeaders): int = return headers.table.len



proc httpMethodFromString(txt: string):  Option[HttpMethod] = 
    let s2m = {"GET": HttpGet, "POST": HttpPost, "PUT":HttpPut, "PATCH": HttpPatch, "DELETE": HttpDelete, "HEAD":HttpHead}.toTable
    if txt in s2m:
        result = some(s2m[txt.toUpper])
    else:
        result = none(HttpMethod)

proc parseList(line: string, list: var seq[string], start: int): int =
  var i = 0
  var current = ""
  while start+i < line.len and line[start + i] notin {'\c', '\l'}:
    i += line.skipWhitespace(start + i)
    i += line.parseUntil(current, {'\c', '\l', ','}, start + i)
    list.add(current)
    if start+i < line.len and line[start + i] == ',':
      i.inc # Skip ,
    current.setLen(0)

proc parseHeader*(line: string): tuple[key: string, value: seq[string]] =
  ## Parses a single raw header HTTP line into key value pairs.
  ##
  ## Used by ``asynchttpserver`` and ``httpclient`` internally and should not
  ## be used by you.
  result.value = @[]
  var i = 0
  i = line.parseUntil(result.key, ':')
  inc(i) # skip :
  if i < len(line):
    i += parseList(line, result.value, i)
  elif result.key.len > 0:
    result.value = @[""]
  else:
    result.value = @[]

const maxLine = 8*1024




type Request = object 
  httpMethod*: HTTPMethod
  requestURI*: string
  httpVersion*: HttpVersion
  headers*: HTTPHeaders
  path*: string
  body*: string
  raw_body: string
  queryParams*: TableRef[string, string]
  formData*: TableRef[string, string]
  urlParams*: TableRef[string, string]


type Response = object
  headers: HttpHeaders
  httpver: HttpVersion
  code: HttpCode
  content: string

  
proc newResponse(): ref Response =
  new result
  result.httpver = HttpVer11
  result.headers = newHttpHeaders()

type MiddlewareFunc = proc(req: var Request): (ref Response, bool) {.nimcall.}
type HandlerFunc = proc(req: var Request):ref Response {.nimcall.}
  
type RouterValue = object
  handlerFunc: HandlerFunc
  middlewares:seq[MiddlewareFunc]

type Router = object
  table: TableRef[string, RouterValue]

  

proc newRouter(): ref Router =
  result = new Router
  result.table = newTable[string, RouterValue]()


proc handle404(req: var Request): ref Response  = 
  var resp = newResponse()
  resp.code = Http404
  resp.content = fmt"nothing at {req.path}"
  return resp


proc abortWith(msg: string): ref Response =
  result = newResponse()
  result.code = Http404
  result.content = msg


proc redirectTo(url: string, code=Http301): ref Response =
  result = newResponse()
  result.code = code
  result.headers.add("Location", url)



proc getByPath(r: ref Router, path: string, notFoundHandler:HandlerFunc=handle404) : (RouterValue, TableRef[string, string]) =
  var found = false
  if path in r.table: # exact match
    return (r.table[path], newTable[string, string]())

  for handlerPath, routerValue in r.table.pairs:
    echo fmt"checking handler:  {handlerPath} if it matches {path}" 
    let pathParts = path.split({'/'})
    let handlerPathParts = handlerPath.split({'/'})
    echo fmt"pathParts {pathParts} and handlerPathParts {handlerPathParts}"

    if len(pathParts) != len(handlerPathParts):
      echo "length isn't ok"
      continue
    else:
      var idx = 0
      var capturedParams = newTable[string, string]()

      while idx<len(pathParts):
        let pathPart = pathParts[idx]
        let handlerPathPart = handlerPathParts[idx]
        echo fmt"current pathPart {pathPart} current handlerPathPart: {handlerPathPart}"

        if handlerPathPart.startsWith(":") or handlerPathPart.startsWith("@"):
          echo fmt"found var in path {handlerPathPart} matches {pathPart}"
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
    return (RouterValue(handlerFunc:notFoundHandler, middlewares: @[]), newTable[string, string]())


proc addHandler(router: ref Router, route: string, handler: HandlerFunc, httpMethod:HttpMethod=HttpGet, middlewares:seq[MiddlewareFunc]= @[]) = 
  router.table.add(route, RouterValue(handlerFunc:handler, middlewares:middlewares))

let addRoute = addHandler

type ServerOptions = object
  address: string
  port: Port

type Servy = object
  options: ServerOptions
  router: ref Router
  middlewares: seq[MiddlewareFunc]
  staticDir: string
  sock: AsyncSocket



proc parseQueryParams(content: string): TableRef[string, string] =
  ## BUG IN JESTER.
  result = newTable[string, string]()
  var consumed = 0
  if "?" notin content and "=" notin content:
    return
  if "?" in content:
    consumed += content.skipUntil({'?'}, consumed)

  inc consumed # skip ? now.

  while consumed < content.len:
    if "=" notin content[consumed..^1]:
      break

    var key = ""
    var val = ""
    consumed += content.parseUntil(key, "=", consumed)
    inc consumed # =
    consumed += content.parseUntil(val, "&", consumed)
    inc consumed
    # result[decodeUrl(key)] = result[decodeUrl(val)]
    result.add(decodeUrl(key), decodeUrl(val))
    echo "consumed:" & $consumed
    echo "contentlen:" & $content.len

type FormPart = object
      name*: string
      headers*: HttpHeaders
      body*: string


proc newFormPart(): ref FormPart = 
  new result
  result.headers = newHttpHeaders()

proc `$`(this:ref FormPart): string = 
  result = fmt"partname: {this.name} partheaders: {this.headers} partbody: {this.body}" 

type FormMultiPart = object
  parts*: TableRef[string, ref FormPart]

proc newFormMultiPart(): ref FormMultiPart = 
  new result
  result.parts = newTable[string, ref FormPart]()

proc `$`(this: ref FormMultiPart): string = 
  return fmt"parts: {this.parts}"

proc parseFormData(r: Request): ref FormMultiPart =


  discard """
received request from client: (httpMethod: HttpPost, requestURI: "", httpVersion: HTTP/1.1, headers: {"accept": @["*/*"], "content-length": @["241"], "content-type": @["multipart/form-data; boundary=------------------------95909933ebe184f2"], "host": @["127.0.0.1:9000"], "user-agent": @["curl/7.62.0-DEV"]}, path: "/post", body: "--------------------------95909933ebe184f2\c\nContent-Disposition: form-data; name=\"who\"\c\n\c\nhamada\c\n--------------------------95909933ebe184f2\c\nContent-Disposition: form-data; name=\"next\"\c\n\c\nhome\c\n--------------------------95909933ebe184f2--\c\n", raw_body: "", queryParams: {:})


  """

  result = newFormMultiPart()
  
  let contenttype = r.headers.getOrDefault("content-type")[0]
  let body = r.body
  
  if "form-urlencoded" in contenttype.toLowerAscii():
    # query params are the post body
    let postBodyAsParams = parseQueryParams(body)
    for k, v in postBodyAsParams.pairs:
      r.queryParams.add(k, v)     

  elif contenttype.startsWith("multipart/") and "boundary" in contenttype:
    var boundaryName = contenttype[contenttype.find("boundary=")+"boundary=".len..^1]
    echo "boundayName: " & boundaryName
    for partString in body.split(boundaryName & "\c\L"):
      var part = newFormPart()
      var partName = ""

      var totalParsedLines = 1
      let bodyLines = body.split("\c\L")[1..^1] # at the boundary line
      for line in bodyLines:
        if line.strip().len != 0:
          let splitted = line.split(": ")
          if len(splitted) == 2:
            part.headers.add(splitted[0], splitted[1])
          elif len(splitted) == 1:
            part.headers.add(splitted[0], "")
          
          if "content-disposition" in line.toLowerAscii and "name" in line.toLowerAscii:
            # Content-Disposition: form-data; name="next"
            var consumed = line.find("name=")+"name=".len
            discard line.skip("\"", consumed) 
            inc consumed
            consumed += line.parseUntil(partName, "\"", consumed)

        else:
          break # done with headers now for the body.

        inc totalParsedLines
      
      let content = join(bodyLines[totalParsedLines..^1], "\c\L")
      part.body = content
      part.name = partName
      result.parts.add(partName, part)
      echo $result.parts

proc parseRequestFromConnection(s: ref Servy, conn:AsyncSocket): Future[Request] {.async.} = 
    let requestline = $await conn.recvLine(maxLength=maxLine)
    var  meth, path, httpver: string
    var parts = requestLine.splitWhitespace()
    meth = parts[0]
    path = parts[1]
    httpver = parts[2]
    var contentLength = 0
    echo meth, path, httpver
    let m = httpMethodFromString(meth)
    if m.isSome:
        result.httpMethod = m.get()
    else:
        echo meth
        raise newException(OSError, "invalid httpmethod")
    if "1.1" in httpver:
        result.httpVersion = HttpVer11
    elif "1.0" in httpver:
        result.httpVersion = HttpVer10
  
    result.path = path
    result.headers = newHttpHeaders()

    result.queryParams = newTable[string, string]()
    
    result.formData = newTable[string, string]()

    if "?" in path:
      # has query params
      result.queryParams = parseQueryParams(path) 
    

    # parse headers
    var line = ""
    line = $(await conn.recvLine(maxLength=maxLine))
    echo fmt"line: >{line}< "
    while line != "\r\n":
      # a header line
      let kv = parseHeader(line)
      result.headers[kv.key] = kv.value
      if kv.key.toLowerAscii == "content-length":
        contentLength = parseInt(kv.value[0])
      line = $(await conn.recvLine(maxLength=maxLine))
      # echo fmt"line: >{line}< "



    if contentLength > 0:
      result.body = await conn.recv(contentLength)
      # FIXME: remember to add raw_body later
      # echo "ok body is : " & result.body

    result.urlParams = newTable[string, string]()
    discard result.parseFormData()
      
proc parseRequestString(input: string): Request = 
    let lines = input.splitLines()
    echo lines
    let requestLine = lines[0]
    var  meth, path, httpver: string
    var parts = requestLine.splitWhitespace()
    meth = parts[0]
    path = parts[1]
    httpver = parts[2]
    var contentLength = 0

    echo meth, path, httpver
    let m = httpMethodFromString(meth)
    if m.isSome:
        result.httpMethod = m.get()
    else:
        echo meth
        raise newException(OSError, "invalid httpmethod")
    if "1.1" in httpver:
        result.httpVersion = HttpVer11
    elif "1.0" in httpver:
        result.httpVersion = HttpVer10

    result.path = path
    result.headers = newHttpHeaders()
    # parse headers
    var curLineIdx = 1
    while curLineIdx<lines.len and lines[curLineIdx] != "\r\n":
      # a header line
      let kv = parseHeader(lines[curLineIdx])
      result.headers[kv.key] = kv.value
      if kv.key.toLowerAscii == "content-length":
        contentLength = parseInt(kv.value[0])
      inc(curLineIdx)
    if contentLength>0:
      let remainingContent = join(lines[curLineIdx..^1], "\r\n")
      echo "remaining.. " & remainingContent
      let content = remainingContent[0..contentLength] 
      echo "ok body is : " & content

proc `$`(ver:HttpVersion): string = 
      case ver
      of HttpVer10: result="HTTP/1.0"
      of HttpVer11: result="HTTP/1.1"


proc formatStatusLine(code: HttpCode, httpver: HttpVersion) : string =
  return fmt"{httpver} {code}" & "\r\n"

proc formatResponse(code:HttpCode, httpver:HttpVersion, content:string, headers:HttpHeaders): string = 
  result &= formatStatusLine(code, httpver)
  if headers.len > 0:
    for k,v in headers.pairs:
      result &= fmt"{k}: {v}" & "\r\n"
  result &= fmt"Content-Length: {content.len}" & "\r\n\r\n"
  result &= content
  echo "will send"
  echo result
  
  

proc format(resp: ref Response) : string = 
  result = formatResponse(resp.code, resp.httpver, resp.content, resp.headers)





proc newServy(options: ServerOptions, router:ref Router, middlewares:seq[MiddlewareFunc]): ref Servy =
  result = new Servy
  result.options = options
  result.router = router
  result.middlewares = middlewares

  result.sock = newAsyncSocket()
  result.sock.setSockOpt(OptReuseAddr, true)



proc handleClient(s: ref Servy, client: AsyncSocket) {.async.} =
  var req = await s.parseRequestFromConnection(client)
  
  
  for  m in s.middlewares:
    let (resp, usenextmiddleware) = m(req)
    if not usenextmiddleware:
      echo "early return from middleware..."
      await client.send(resp.format())
      return

  echo "received request from client: " & $req

  let (routeHandler, params) = s.router.getByPath(req.path)
  req.urlParams = params
  let handler = routeHandler.handlerFunc
  let middlewares = routeHandler.middlewares
  
  

  for  m in middlewares:
    let (resp, usenextmiddleware) = m(req)
    if not usenextmiddleware:
      echo "early return from route middleware..."
      await client.send(resp.format())
      return
    
  let resp = handler(req)
  echo "reached the handler safely.. and executing now."
  await client.send(resp.format())
  echo $req.formData

proc serve(s: ref Servy) {.async.} =
  s.sock.bindAddr(s.options.port)
  s.sock.listen()
  while true:
    let client = await s.sock.accept()
    asyncCheck s.handleClient(client)

  runForever()

when isMainModule:

  const sampleRequest = """GET /index.html HTTP/1.1
Host: localhost
Connection: keep-alive
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Encoding: gzip, deflate, sdch
Accept-Language: en-US,en;q=0.8
  """
  echo sampleRequest

  discard """
received request from client: (httpMethod: HttpPost, requestURI: "", httpVersion: HTTP/1.1, headers: {"accept": @["*/*"], "content-length": @["241"], "content-type": @["multipart/form-data; boundary=------------------------94f28cb187c245d8"], "host": @["127.0.0.1:9000"], "user-agent": @["curl/7.62.0-DEV"]}, path: "/post", body: "--------------------------94f28cb187c245d8\c\nContent-Disposition: form-data; name=\"who\"\c\n\c\nhamada\c\n--------------------------94f28cb187c245d8\c\nContent-Disposition: form-data; name=\"next\"\c\n\c\nhome\c\n--------------------------94f28cb187c245d8--\c\n", raw_body: "")
received request from client: (httpMethod: HttpPost, requestURI: "", httpVersion: HTTP/1.1, headers: {"accept": @["*/*"], "content-length": @["44"], "content-type": @["application/x-www-form-urlencoded"], "host": @["127.0.0.1:9000"], "user-agent": @["curl/7.62.0-DEV"]}, path: "/post", body: "{\"username\":\"ahmed\", \"password\":\"apassword\"}", raw_body: "")

"""


  # echo $parseRequestString(sampleRequest)
  # echo("Hello, World!")
  proc main() =
    var router = newRouter()
    proc handleHello(req:var Request): ref Response =
      result = newResponse()
      result.code = Http200
      result.content = "hello world from handler /hello" & $req 


    let loggingMiddleware = proc(request: var Request): (ref Response, bool) =
      let path = request.path
      let headers = request.headers
      echo "==============================="
      echo "from logger handler"
      echo "path: " & path
      echo "headers: " & $headers
      echo "==============================="
      return (newResponse(), true)

    let trimTrailingSlash = proc(request: var Request): (ref Response, bool) =
      let path = request.path
      if path.endswith("/"):
        request.path = path[0..^2]

      echo "==============================="
      echo "from slash trimmer "
      echo "path was : " & path
      echo "path: " & request.path
      echo "==============================="
      return (newResponse(), true)
      

    router.addRoute("/hello", handleHello)

    let assertJwtFieldExists =  proc(request: var Request): (ref Response, bool) =
        echo $request.headers
        let jwtHeaderVals = request.headers.getOrDefault("jwt", @[""])
        let jwt = jwtHeaderVals[0]
        echo "================\n\njwt middleware"
        if jwt.len != 0:
          echo fmt"bye bye {jwt} "
        else:
          echo fmt"sure bye but i didn't get ur name"
        echo "===================\n\n"
        return (newResponse(), true)

    router.addRoute("/bye", handleHello, HttpGet, @[assertJwtFieldExists])
    
    proc handleGreet(req:var Request): ref Response =
      result = newResponse()
      result.code = Http200
      result.content = "generic greet" & $req 

        
    router.addRoute("/greet", handleGreet, HttpGet, @[])
    router.addRoute("/greet/:username", handleGreet, HttpGet, @[])
    router.addRoute("/greet/:first/:second/:lang", handleGreet, HttpGet, @[])


    proc handleAbort(req:var Request): ref Response =
      result = abortWith("sorry mate")
    
    proc handleRedirect(req:var Request): ref Response =
      result = redirectTo("https://python.org")

    router.addRoute("/redirect", handleRedirect, HttpGet)
    router.addRoute("/abort", handleAbort, HttpGet)


    let opts = ServerOptions(address:"127.0.0.1", port:9000.Port)
    var s = newServy(opts, router, @[loggingMiddleware, trimTrailingSlash])
    asyncCheck s.serve()
    echo "servy started..."
    runForever()
  
  main()
