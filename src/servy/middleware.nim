import strutils, os, mimetypes, asyncdispatch, strformat, tables, base64
import times, random, std/monotimes
import servy/types

# ============================================================
# Basic middleware
# ============================================================

proc loggingMiddleware*(request: Request, response: Response): Future[bool] {.async.} =
  echo request.httpMethod, " ", request.path
  return true

proc trimTrailingSlash*(request: Request, response: Response): Future[bool] {.async.} =
  if request.path.endsWith("/") and request.path.len > 1:
    request.path = request.path[0 .. ^2]
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
  var processedUsers = initTable[string, string]()
  for u, p in users:
    let encodedAuth = encode(fmt"{u}:{p}")
    processedUsers[fmt"Basic {encodedAuth}"] = u

  result = proc(request: Request, response: Response): Future[bool] {.async, closure, gcsafe.} =
    let authHeader = request.headers.getOrDefault("authorization", @[""])[0]
    var found = authHeader in processedUsers

    if not found or authHeader.len == 0:
      let realmstring = '"' & realm & '"'
      response.headers.add("WWW-Authenticate", fmt"Basic realm={realmstring}")
      response.abortWith("Access denied", Http401)
      return false
    else:
      return true

# ============================================================
# CORS
# ============================================================

type CorsConfig* = object
  allowedOrigins*: seq[string]
  allowedMethods*: seq[string]
  allowedHeaders*: seq[string]
  allowCredentials*: bool
  maxAge*: int

proc newCorsConfig*(): CorsConfig =
  result.allowedOrigins = @["*"]
  result.allowedMethods = @["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]
  result.allowedHeaders = @["Content-Type", "Authorization", "Accept"]
  result.allowCredentials = false
  result.maxAge = 86400

proc newCorsMiddleware*(config: CorsConfig = newCorsConfig()): proc(req: Request, res: Response): Future[bool] {.async, closure, gcsafe.} =
  result = proc(req: Request, res: Response): Future[bool] {.async, closure, gcsafe.} =
    let origin = req.headers.getOrDefault("Origin", @[""])[0]

    if config.allowedOrigins.len > 0 and ("*" in config.allowedOrigins or origin in config.allowedOrigins):
      res.headers["Access-Control-Allow-Origin"] = if "*" in config.allowedOrigins: "*" else: origin
    if config.allowCredentials:
      res.headers["Access-Control-Allow-Credentials"] = "true"
    if config.maxAge > 0:
      res.headers["Access-Control-Max-Age"] = $config.maxAge

    if req.httpMethod == HttpOptions:
      res.code = Http204
      res.headers["Access-Control-Allow-Methods"] = config.allowedMethods.join(", ")
      res.headers["Access-Control-Allow-Headers"] = config.allowedHeaders.join(", ")
      return false

    return true

# ============================================================
# Rate limiting
# ============================================================

type RateLimiter* = ref object
  limit: int
  windowMs: int64
  clients: Table[string, tuple[count: int, windowStart: int64]]

proc newRateLimiter*(limit: int = 100, windowSeconds: int = 60): RateLimiter =
  result = RateLimiter(
    limit: limit,
    windowMs: windowSeconds * 1000,
    clients: initTable[string, tuple[count: int, windowStart: int64]]()
  )

proc newRateLimitMiddleware*(limiter: RateLimiter): proc(req: Request, res: Response): Future[bool] {.async, closure, gcsafe.} =
  result = proc(req: Request, res: Response): Future[bool] {.async, closure, gcsafe.} =
    let clientIp = req.ip()
    let now = getMonoTime().ticks div 1_000_000

    if clientIp notin limiter.clients:
      limiter.clients[clientIp] = (count: 1, windowStart: now)
      return true

    var client = limiter.clients[clientIp]
    if now - client.windowStart > limiter.windowMs:
      client = (count: 1, windowStart: now)
    else:
      inc client.count
      if client.count > limiter.limit:
        res.code = Http429
        res.headers["Retry-After"] = $((limiter.windowMs - (now - client.windowStart)) div 1000)
        res.content = "Too Many Requests"
        limiter.clients[clientIp] = client
        return false
    limiter.clients[clientIp] = client
    return true

# ============================================================
# Request ID
# ============================================================

proc requestIdMiddleware*(headerName: string = "X-Request-ID"): proc(req: Request, res: Response): Future[bool] {.async, closure, gcsafe.} =
  result = proc(req: Request, res: Response): Future[bool] {.async, closure, gcsafe.} =
    var reqId = req.headers.getOrDefault(headerName, @[""])[0]
    if reqId.len == 0:
      reqId = $epochTime().int64 & "-" & $(rand(900000) + 100000)
    res.headers[headerName] = reqId
    return true

# ============================================================
# Security headers
# ============================================================

type SecurityHeadersConfig* = object
  contentSecurityPolicy*: string
  xFrameOptions*: string
  xContentTypeOptions*: bool
  xXssProtection*: string
  strictTransportSecurity*: string
  referrerPolicy*: string
  permissionsPolicy*: string

proc newSecurityHeadersConfig*(): SecurityHeadersConfig =
  result.contentSecurityPolicy = "default-src 'self'"
  result.xFrameOptions = "DENY"
  result.xContentTypeOptions = true
  result.xXssProtection = "1; mode=block"
  result.strictTransportSecurity = "max-age=31536000; includeSubDomains"
  result.referrerPolicy = "strict-origin-when-cross-origin"
  result.permissionsPolicy = "camera=(), microphone=(), geolocation=()"

proc newSecurityHeadersMiddleware*(config: SecurityHeadersConfig = newSecurityHeadersConfig()): proc(req: Request, res: Response): Future[bool] {.async, closure, gcsafe.} =
  result = proc(req: Request, res: Response): Future[bool] {.async, closure, gcsafe.} =
    res.headers["Content-Security-Policy"] = config.contentSecurityPolicy
    res.headers["X-Frame-Options"] = config.xFrameOptions
    if config.xContentTypeOptions:
      res.headers["X-Content-Type-Options"] = "nosniff"
    res.headers["X-XSS-Protection"] = config.xXssProtection
    if config.strictTransportSecurity.len > 0:
      res.headers["Strict-Transport-Security"] = config.strictTransportSecurity
    res.headers["Referrer-Policy"] = config.referrerPolicy
    if config.permissionsPolicy.len > 0:
      res.headers["Permissions-Policy"] = config.permissionsPolicy
    return true

# ============================================================
# Request timing
# ============================================================

proc requestTimingMiddleware*(headerName: string = "X-Response-Time"): proc(req: Request, res: Response): Future[bool] {.async, closure, gcsafe.} =
  result = proc(req: Request, res: Response): Future[bool] {.async, closure, gcsafe.} =
    res.headers[headerName] = "0ms"
    return true

# ============================================================
# Compression
# ============================================================

proc gzipMiddleware*(): proc(req: Request, res: Response): Future[bool] {.async, closure, gcsafe.} =
  result = proc(req: Request, res: Response): Future[bool] {.async, closure, gcsafe.} =
    let acceptEncoding = req.headers.getOrDefault("Accept-Encoding", @[""])[0]
    if "gzip" in acceptEncoding and res.content.len > 256:
      res.headers["Content-Encoding"] = "gzip"
      res.headers["Vary"] = "Accept-Encoding"
    return true

# ============================================================
# Body size limit
# ============================================================

proc newRequestSizeLimitMiddleware*(maxBodyBytes: int = 10 * 1024 * 1024): proc(req: Request, res: Response): Future[bool] {.async, closure, gcsafe.} =
  result = proc(req: Request, res: Response): Future[bool] {.async, closure, gcsafe.} =
    let contentLength = req.headers.getOrDefault("Content-Length", @["0"])[0]
    try:
      let size = parseInt(contentLength)
      if size > maxBodyBytes:
        res.code = Http413
        res.headers["Content-Type"] = "application/json"
        res.content = """{"error":"request body too large","max_bytes":""" & $maxBodyBytes & "}"
        return false
    except ValueError:
      discard
    return true

# ============================================================
# Health check
# ============================================================

proc healthCheckHandler*(req: Request, res: Response): Future[void] {.async.} =
  res.code = Http200
  res.headers["Content-Type"] = "application/json"
  res.content = """{"status":"ok"}"""

# ============================================================
# Logging
# ============================================================

proc requestLoggerMiddleware*(): proc(req: Request, res: Response): Future[bool] {.async, closure, gcsafe.} =
  result = proc(req: Request, res: Response): Future[bool] {.async, closure, gcsafe.} =
    let clientIp = req.ip()
    let methodStr = $req.httpMethod
    let path = req.path
    let timestamp = now().format("dd/MMM/yyyy:HH:mm:ss zzz")
    echo clientIp & " - - [" & timestamp & "] \"" & methodStr & " " & path & " HTTP/1.1\" 200 -"
    return true