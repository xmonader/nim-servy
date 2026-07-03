import asyncdispatch, times, strutils, tables, os, random, strformat, std/monotimes
import servy/types

# --- CORS ---

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

# --- Rate Limiting ---

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
    let now = getMonoTime().ticks div 1_000_000  # ms

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

# --- Request ID ---

proc requestIdMiddleware*(headerName: string = "X-Request-ID"): proc(req: Request, res: Response): Future[bool] {.async, closure, gcsafe.} =
  result = proc(req: Request, res: Response): Future[bool] {.async, closure, gcsafe.} =
    var reqId = req.headers.getOrDefault(headerName, @[""])[0]
    if reqId.len == 0:
      reqId = $epochTime().int64 & "-" & $(rand(900000) + 100000)
    res.headers[headerName] = reqId
    return true

# --- Security Headers ---

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

# --- Request Timing ---

proc requestTimingMiddleware*(headerName: string = "X-Response-Time"): proc(req: Request, res: Response): Future[bool] {.async, closure, gcsafe.} =
  result = proc(req: Request, res: Response): Future[bool] {.async, closure, gcsafe.} =
    let startTime = getMonoTime()
    res.headers[headerName] = ""
    return true

# --- Compression ---

proc gzipMiddleware*(): proc(req: Request, res: Response): Future[bool] {.async, closure, gcsafe.} =
  result = proc(req: Request, res: Response): Future[bool] {.async, closure, gcsafe.} =
    let acceptEncoding = req.headers.getOrDefault("Accept-Encoding", @[""])[0]
    if "gzip" in acceptEncoding and res.content.len > 256:
      res.headers["Content-Encoding"] = "gzip"
      res.headers["Vary"] = "Accept-Encoding"
    return true

# --- Body Size Limit ---

proc bodySizeLimitMiddleware*(maxSize: int = 1024 * 1024): proc(req: Request, res: Response): Future[bool] {.async, closure, gcsafe.} =
  result = proc(req: Request, res: Response): Future[bool] {.async, closure, gcsafe.} =
    let contentLength = req.headers.getOrDefault("Content-Length", @["0"])[0]
    try:
      let size = parseInt(contentLength)
      if size > maxSize:
        res.code = Http413
        res.content = "Request Entity Too Large"
        return false
    except ValueError:
      discard
    return true

# --- Health Check ---

proc healthCheckHandler*(req: Request, res: Response): Future[void] {.async.} =
  res.code = Http200
  res.headers["Content-Type"] = "application/json"
  res.content = """{"status":"ok"}"""

# --- Structured Logging ---

type LogLevel* = enum
  Debug, Info, Warn, Error

proc logMiddleware*(level: LogLevel = Info): proc(req: Request, res: Response): Future[bool] {.async, closure, gcsafe.} =
  result = proc(req: Request, res: Response): Future[bool] {.async, closure, gcsafe.} =
    let startTime = getMonoTime()
    let methodStr = $req.httpMethod
    let path = req.path
    let clientIp = req.ip()

    let timestamp = now().format("yyyy-MM-dd HH:mm:ss")
    let logLine = fmt"{timestamp} [{level}] {clientIp} {methodStr} {path}"

    case level
    of Debug: echo logLine
    of Info: echo logLine
    of Warn: echo logLine
    of Error: echo logLine

    return true

# --- Request Size Limit ---

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

# --- Request Logger (Apache-style) ---

proc requestLoggerMiddleware*(): proc(req: Request, res: Response): Future[bool] {.async, closure, gcsafe.} =
  result = proc(req: Request, res: Response): Future[bool] {.async, closure, gcsafe.} =
    let clientIp = req.ip()
    let methodStr = $req.httpMethod
    let path = req.path
    let timestamp = now().format("dd/MMM/yyyy:HH:mm:ss zzz")
    let logLine = clientIp & " - - [" & timestamp & "] \"" & methodStr & " " & path & " HTTP/1.1\" 200 -"
    echo logLine
    return true
