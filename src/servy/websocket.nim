import asyncdispatch, asyncnet, base64, std/sha1, strutils, net
import servy/types, servy/response

proc hexToBytes(hex: string): seq[byte] =
  ## Convert hex string to bytes
  result = @[]
  var i = 0
  while i < hex.len:
    if hex[i] in Whitespace:
      inc i
      continue
    let hi = hex[i].int
    let lo = hex[i + 1].int
    inc i, 2

    proc hexCharToNibble(c: int): byte =
      case c
      of '0'.ord .. '9'.ord: byte(c - '0'.ord)
      of 'a'.ord .. 'f'.ord: byte(c - 'a'.ord + 10)
      of 'A'.ord .. 'F'.ord: byte(c - 'A'.ord + 10)
      else: byte(0)

    result.add(byte((hexCharToNibble(hi) shl 4) or hexCharToNibble(lo)))

type
  WebSocketOpCode* = enum
    Continuation = 0x0,
    Text = 0x1,
    Binary = 0x2,
    Close = 0x8,
    Ping = 0x9,
    Pong = 0xA

  WebSocket* = ref object
    socket*: AsyncSocket
    readyState*: WebSocketState

  WebSocketState* = enum
    Connecting, Open, Closing, Closed

proc newWebSocket*(socket: AsyncSocket): WebSocket =
  result = WebSocket(
    socket: socket,
    readyState: Connecting
  )

proc sendFrame(ws: WebSocket, opcode: WebSocketOpCode, data: string): Future[void] {.async.} =
  var header: string

  let fin = 0x80'u8  # FIN bit set
  let opcodeByte = uint8(opcode)

  let payloadLen = data.len

  # Byte 1: FIN + opcode
  header.add(char(fin or opcodeByte))

  # Byte 2: MASK bit (server frames are unmasked) + payload length
  if payloadLen <= 125:
    header.add(char(uint8(payloadLen)))
  elif payloadLen <= 65535:
    header.add(char(126'u8))
    header.add(char(uint8((payloadLen shr 8) and 0xFF)))
    header.add(char(uint8(payloadLen and 0xFF)))
  else:
    header.add(char(127'u8))
    # For simplicity, handle up to 4GB (32-bit)
    for i in [3, 2, 1, 0]:
      header.add(char(uint8((payloadLen shr (i * 8)) and 0xFF)))
    # Pad remaining 4 bytes with zeros for values > 4GB
    for i in 0 ..< 4:
      header.add(char(0'u8))

  await ws.socket.send(header)
  if payloadLen > 0:
    await ws.socket.send(data)

proc recvFrame(ws: WebSocket): Future[tuple[opcode: WebSocketOpCode, payload: string]] {.async.} =
  # Read first 2 bytes
  var buf: array[2, byte]
  let n = await ws.socket.recvInto(addr buf[0], 2)
  if n < 2:
    raise newException(IOError, "Connection closed")

  let fin = (buf[0] and 0x80) != 0
  let opcode = WebSocketOpCode(buf[0] and 0x0F)
  let masked = (buf[1] and 0x80) != 0
  var payloadLen = int(buf[1] and 0x7F)

  # Extended payload length
  if payloadLen == 126:
    var extBuf: array[2, byte]
    let extN = await ws.socket.recvInto(addr extBuf[0], 2)
    if extN < 2:
      raise newException(IOError, "Connection closed")
    payloadLen = (int(extBuf[0]) shl 8) or int(extBuf[1])
  elif payloadLen == 127:
    var extBuf: array[8, byte]
    let extN = await ws.socket.recvInto(addr extBuf[0], 8)
    if extN < 8:
      raise newException(IOError, "Connection closed")
    # Use lower 4 bytes for simplicity (up to 4GB)
    payloadLen = (int(extBuf[4]) shl 24) or (int(extBuf[5]) shl 16) or
                 (int(extBuf[6]) shl 8) or int(extBuf[7])

  # Masking key (client frames are masked)
  var maskKey: array[4, byte]
  if masked:
    let maskN = await ws.socket.recvInto(addr maskKey[0], 4)
    if maskN < 4:
      raise newException(IOError, "Connection closed")

  # Read payload
  var payload = newString(payloadLen)
  if payloadLen > 0:
    let payloadN = await ws.socket.recvInto(addr payload[0], payloadLen)
    if payloadN < payloadLen:
      raise newException(IOError, "Connection closed")

    # Unmask if needed
    if masked:
      for i in 0 ..< payloadLen:
        payload[i] = char(byte(payload[i]) xor maskKey[i mod 4])

  # Handle control frames
  case opcode
  of Ping:
    await ws.sendFrame(Pong, payload)
  of Close:
    if ws.readyState == Open:
      ws.readyState = Closing
      await ws.sendFrame(Close, "")
      ws.readyState = Closed
  else:
    discard

  result = (opcode, payload)

proc sendText*(ws: WebSocket, data: string): Future[void] {.async.} =
  await ws.sendFrame(Text, data)

proc send*(ws: WebSocket, data: string): Future[void] {.async.} =
  await ws.sendText(data)

proc sendBinary*(ws: WebSocket, data: string): Future[void] {.async.} =
  await ws.sendFrame(Binary, data)

proc receiveStrPacket*(ws: WebSocket): Future[string] {.async.} =
  while true:
    let (opcode, payload) = await ws.recvFrame()
    case opcode
    of Text, Binary:
      return payload
    of Close:
      raise newException(IOError, "WebSocket closed")
    of Ping, Pong, Continuation:
      continue

proc close*(ws: WebSocket) {.async.} =
  if ws.readyState == Open:
    ws.readyState = Closing
    await ws.sendFrame(Close, "")
    ws.readyState = Closed
    ws.socket.close()

proc handshake*(ws: WebSocket, headers: HttpHeaders) {.async.} =
  let key = headers["Sec-WebSocket-Key"][0].strip()

  let
    sh = secureHash(key & "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")
    acceptKey = base64.encode(hexToBytes($sh))

  var response = "HTTP/1.1 101 Web Socket Protocol Handshake\c\L"
  response.add("Sec-WebSocket-Accept: " & acceptKey & "\c\L")
  response.add("Connection: Upgrade\c\L")
  response.add("Upgrade: websocket\c\L")

  if headers.hasKey("Sec-WebSocket-Protocol"):
    let protocol = headers["Sec-WebSocket-Protocol"][0].strip()
    response.add("Sec-WebSocket-Protocol: " & protocol & "\c\L")

  response.add "\c\L"

  await ws.socket.send(response)
  ws.readyState = Open

proc newServyWebSocket*(req: Request): Future[WebSocket] {.async.} =
  try:
    let headers = req.headers

    if not headers.hasKey("Sec-WebSocket-Version"):
      discard req.asyncSock.send(formatResponse(Http404, HttpVer11, "Not Found", headers))
      raise newException(HandshakeError, "Not a valid websocket handshake.")

    let fd = req.asyncSock.getFd
    let socket = newAsyncSocket(fd.AsyncFD)
    var ws = newWebSocket(socket)
    await ws.handshake(headers)
    return ws

  except ValueError, KeyError:
    raise newException(
      HandshakeError,
      "Failed to create WebSocket from request: " & getCurrentExceptionMsg()
    )
