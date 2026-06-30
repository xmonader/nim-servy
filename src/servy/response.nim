import strformat
import types

proc formatStatusLine*(code: HttpCode, httpver: HttpVersion): string =
  return fmt"{httpver} {code}" & "\r\n"

proc formatResponse*(code: HttpCode, httpver: HttpVersion, content: string, headers: HttpHeaders): string =
  result &= formatStatusLine(code, httpver)
  if headers.len > 0:
    for k, v in headers.pairs:
      result &= fmt"{k}: {v}" & "\r\n"
  result &= fmt"Content-Length: {content.len}" & "\r\n\r\n"
  result &= content

proc format*(resp: Response): string =
  result = formatResponse(resp.code, resp.httpver, resp.content, resp.headers)

proc buildSetCookieHeader*(cookiename, cookievalue: string, domain = "", expires = "", maxage = 0, path = "", sameSite = None, secure = false, httponly = false): string =
  var validSeq: seq[string] = @[]
  result = fmt"{cookiename}={cookievalue}"

  if expires.len > 0:
    validSeq.add(fmt"Expires={expires}")

  if domain.len > 0:
    validSeq.add(fmt"Domain={domain}")

  if maxage > 0:
    validSeq.add(fmt"Max-Age={maxage}")

  if path.len > 0:
    validSeq.add(fmt"Path={path}")

  if secure:
    validSeq.add("Secure")

  if httponly:
    validSeq.add("HttpOnly")

  case sameSite
  of Strict: validSeq.add("SameSite=Strict")
  of Lax: validSeq.add("SameSite=Lax")
  else: discard

  if validSeq.len > 0:
    result &= "; " & validSeq.join("; ")
