import strutils, tables, parseutils, options, asyncnet, asyncdispatch, cgi, strformat
import servy/types

const maxLine* = 8 * 1024

proc httpMethodFromString*(txt: string): Option[HttpMethod] =
  let s2m = {"GET": HttpGet, "POST": HttpPost, "PUT": HttpPut, "PATCH": HttpPatch, "DELETE": HttpDelete, "HEAD": HttpHead}.toTable
  if txt in s2m:
    result = some(s2m[txt.toUpper])
  else:
    result = none(HttpMethod)

proc parseList(line: string, list: var seq[string], start: int, sep = ','): int =
  var i = 0
  var current = ""
  while start + i < line.len and line[start + i] notin {'\c', '\l'}:
    i += line.skipWhitespace(start + i)
    i += line.parseUntil(current, {'\c', '\l', sep}, start + i)
    list.add(current)
    if start + i < line.len and line[start + i] == sep:
      i.inc
    current.setLen(0)

proc parseHeader*(line: string, sep = ','): tuple[key: string, value: seq[string]] =
  result.value = @[]
  var i = 0
  i = line.parseUntil(result.key, ':')
  inc(i)
  if i < len(line):
    i += parseList(line, result.value, i, sep=sep)
  elif result.key.len > 0:
    result.value = @[""]
  else:
    result.value = @[]

proc parseQueryParams*(content: string): Table[string, string] =
  result = initTable[string, string]()
  var consumed = 0
  if "?" notin content and "=" notin content:
    return
  if "?" in content:
    consumed += content.skipUntil({'?'}, consumed)

  inc consumed

  while consumed < content.len:
    if "=" notin content[consumed..^1]:
      break

    var key = ""
    var val = ""
    consumed += content.parseUntil(key, "=", consumed)
    inc consumed
    consumed += content.parseUntil(val, "&", consumed)
    inc consumed
    result.add(decodeUrl(key), decodeUrl(val))

proc parseFormUrlEncoded*(body: string): Table[string, string] =
  result = initTable[string, string]()
  if body.len == 0 or "=" notin body:
    return
  var consumed = 0
  while consumed < body.len:
    if "=" notin body[consumed..^1]:
      break
    var key = ""
    var val = ""
    consumed += body.parseUntil(key, "=", consumed)
    inc consumed
    consumed += body.parseUntil(val, "&", consumed)
    inc consumed
    result.add(decodeUrl(key), decodeUrl(val))

proc parseFormData*(r: var Request): FormMultiPart =
  result = initFormMultiPart()

  let contenttype = r.headers.getOrDefault("content-type")[0]
  let body = r.body

  if "form-urlencoded" in contenttype.toLowerAscii():
    let postBodyAsParams = parseFormUrlEncoded(body)
    for k, v in postBodyAsParams.pairs:
      var part = initFormPart()
      part.name = k
      part.body = v
      result.parts.add(k, part)

  elif contenttype.startsWith("multipart/") and "boundary" in contenttype:
    var boundaryName = contenttype[contenttype.find("boundary=") + "boundary=".len .. ^1]
    let formStart = fmt"--{boundaryName}"
    let formEnd = fmt"--{boundaryName}--"
    let partStart = formStart

    let formBody = body[body.find(formStart) .. body.find(formEnd)]

    for partString in formBody.split(partStart & "\c\L"):
      var part = initFormPart()
      var partName = ""

      var totalParsedLines = 1
      let bodyLines = partString.splitLines()
      for line in bodyLines:
        var kv: tuple[key: string, value: seq[string]]
        if line.contains(":"):
          if line.contains(";"):
            kv = parseHeader(line, sep=';')
          else:
            kv = parseHeader(line)

          part.headers.addMany(kv.key, kv.value)
          if "content-disposition" in kv.key.toLowerAscii:
            for v in kv.value:
              if v.startswith("name="):
                var consumed = "name=".len
                discard line.skip("\"", consumed)
                inc consumed
                consumed += v.parseUntil(partName, "\"", consumed)
                part.name = partName
                inc consumed
              if v.startswith("filename="):
                var consumed = v.find("filename=") + "filename=".len
                discard line.skip("\"", consumed)
                inc consumed
                var fileName = ""
                consumed += v.parseUntil(fileName, "\"", consumed)
                part.fileName = fileName
                inc consumed
        else:
          break

        inc totalParsedLines

      let content = join(bodyLines[totalParsedLines .. ^1], "\c\L")
      part.body = content
      result.parts.add(partName, part)

proc parseRequestFromConnection*(conn: AsyncSocket): Future[Request] {.async.} =
  result = Request.new
  result.asyncSock = conn
  let requestline = $await conn.recvLine(maxLength = maxLine)

  if requestline.len == 0:
    raise newException(ParseError, "empty request line")

  var parts = requestLine.splitWhitespace()
  if parts.len < 3:
    raise newException(ParseError, "invalid request line: " & requestline)

  var meth, path, httpver: string
  meth = parts[0]
  path = parts[1]
  httpver = parts[2]
  var contentLength = 0

  let m = httpMethodFromString(meth)
  if m.isSome:
    result.httpMethod = m.get()
  else:
    raise newException(ParseError, "invalid httpmethod " & meth)

  if "1.1" in httpver:
    result.httpVersion = HttpVer11
  elif "1.0" in httpver:
    result.httpVersion = HttpVer10
  else:
    raise newException(ParseError, "unsupported HTTP version: " & httpver)

  result.path = path
  result.headers = newHttpHeaders()
  result.queryParams = initTable[string, string]()
  result.cookies = initTable[string, string]()
  result.urlParams = initTable[string, string]()
  result.formData = initFormMultiPart()

  if "?" in path:
    result.queryParams = parseQueryParams(path)
    result.path = path[0 .. path.find('?') - 1]

  var line = ""
  line = $(await conn.recvLine(maxLength = maxLine))
  while line != "\r\n":
    var kv: tuple[key: string, value: seq[string]]
    if line.toLowerAscii.startsWith("cookie"):
      kv = parseHeader(line, sep=';')
    else:
      kv = parseHeader(line)
    result.headers[kv.key] = kv.value
    if kv.key.toLowerAscii == "content-length":
      try:
        contentLength = parseInt(kv.value[0])
      except ValueError:
        contentLength = 0
    if kv.key.toLowerAscii == "cookie":
      for cookieinfo in kv.value:
        let theparts = cookieinfo.split({'='}, maxsplit=1)
        if theparts.len == 2:
          let cookiename = theparts[0].strip()
          let cookieval = theparts[1].strip()
          if cookiename.len > 0:
            result.cookies[cookiename] = cookieval
    line = $(await conn.recvLine(maxLength = maxLine))

  if contentLength > 0:
    result.body = await conn.recv(contentLength)

  result.formData = result.parseFormData()
