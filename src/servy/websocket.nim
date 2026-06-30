import asyncdispatch, asyncnet, base64, std/sha1, strutils, strformat
import types, response

proc handshake*(ws: WebSocket, headers: HttpHeaders) {.async.} =
  ws.version = parseInt(headers["Sec-WebSocket-Version"][0])
  ws.key = headers["Sec-WebSocket-Key"][0].strip()
  if headers.hasKey("Sec-WebSocket-Protocol"):
    ws.protocol = headers["Sec-WebSocket-Protocol"][0].strip()

  let
    sh = secureHash(ws.key & "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")
    acceptKey = base64.encode(decodeBase16($sh))

  var response = "HTTP/1.1 101 Web Socket Protocol Handshake\c\L"
  response.add("Sec-WebSocket-Accept: " & acceptKey & "\c\L")
  response.add("Connection: Upgrade\c\L")
  response.add("Upgrade: webSocket\c\L")

  if ws.protocol != "":
    response.add("Sec-WebSocket-Protocol: " & ws.protocol & "\c\L")
  response.add "\c\L"

  await ws.tcpSocket.send(response)
  ws.readyState = Open

proc newServyWebSocket*(req: Request): Future[WebSocket] {.async.} =
  try:
    let headers = req.headers

    if not headers.hasKey("Sec-WebSocket-Version"):
      discard req.asyncSock.send(formatResponse(Http404, HttpVer11, "Not Found", headers))
      raise newException(WebSocketHandshakeError, "Not a valid websocket handshake.")

    var ws = WebSocket()
    ws.masked = false

    let fd = req.asyncSock.getFd
    ws.tcpSocket = newAsyncSocket(fd.AsyncFD)
    await ws.handshake(headers)
    return ws

  except ValueError, KeyError:
    raise newException(
      WebSocketHandshakeError,
      "Failed to create WebSocket from request: " & getCurrentExceptionMsg()
    )
