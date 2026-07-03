import strutils, os, mimetypes, asyncdispatch, strformat, tables, base64
import servy/types

proc loggingMiddleware*(request: Request, response: Response): Future[bool] {.async.} =
  let path = request.path
  let headers = request.headers
  echo "==============================="
  echo "from logger handler"
  echo "path: " & path
  echo "headers: " & $headers
  echo "==============================="
  return true

proc trimTrailingSlash*(request: Request, response: Response): Future[bool] {.async.} =
  let path = request.path
  if path.endswith("/"):
    request.path = path[0 .. ^2]

  echo "==============================="
  echo "from slash trimmer "
  echo "path was : " & path
  echo "path: " & request.path
  echo "==============================="
  return true

proc stripLeadingSlashes*(s: string): string =
  var idx = 0
  while idx < s.len:
    if s[idx] == '/':
      inc idx
    else:
      break
  s[idx .. ^1]

proc newStaticMiddleware*(dir: string, onRoute = "/public"): proc(request: Request, response: Response): Future[bool] {.async, closure, gcsafe.} =
  result = proc(request: Request, response: Response): Future[bool] {.async, closure, gcsafe.} =
    var thepath = request.path
    if thepath.startsWith(onRoute):
      thepath = thepath[onRoute.len .. ^1]
      thepath = thepath.stripLeadingSlashes()
      if fileExists(dir / thepath):
        response.code = Http200
        let m = newMimetypes()

        let (parentName, dirName, ext) = splitFile(thepath)
        discard parentName
        discard dirName
        response.headers["Content-Type"] = m.getMimetype(ext)
        response.content = readFile(dir / thepath)
        return false
      else:
        response.abortWith("File not found.")
      return false
    else:
      return true

proc basicAuth*(users: Table[string, string], realm = "private", text = "Access denied"): proc(request: Request, response: Response): Future[bool] {.async, closure, gcsafe.} =
  result = proc(request: Request, response: Response): Future[bool] {.async, closure, gcsafe.} =
    var processedUsers = initTable[string, string]()
    for u, p in users:
      let encodedAuth = encode(fmt"{u}:{p}")
      processedUsers.add(fmt"Basic {encodedAuth}", u)

    let authHeader = request.headers.getOrDefault("authorization", @[""])[0]

    var found = authHeader in processedUsers

    if not found or authHeader.len == 0:
      let realmstring = '"' & realm & '"'
      response.headers.add("WWW-Authenticate", fmt"Basic realm={realmstring}")
      response.abortWith("Access denied", Http401)
      return false
    else:
      return true
