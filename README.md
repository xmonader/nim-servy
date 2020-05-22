# servy

Servy is a fast, simple and lightweight micro web-framework for Nim


## Installation

`nimble install servy`

## quickstart

### First create the router

```nim
import servy
var router = initRouter()

```

### Define your first handler function

```nim
proc handleHello(req: Request, res: Response) : Future[void] {.async.} =
    res.code = Http200
    res.content = "hello world from handler /hello" & $req


```

### Wire the handler to a path

```nim
    router.addRoute("/hello", handleHello)

```

### Running Servy

```nim
let opts = ServerOptions(address:"127.0.0.1", port:9000.Port, debug:true)
var s = initServy(opts, router)
s.run()
```

### Making first request

using curl or your web browser go to localhost:9000/hello

```
➜  servy git:(master) ✗ curl localhost:9000/hello
hello world from handler /hello%    
```



## Defining handlers and wiring them

```nim

    proc handleGreet(req: Request, res: Response) : Future[void] {.async.} =
      res.code = Http200
      res.content = "generic greet" & $req
      if "username" in req.urlParams:
        echo "username is: " & req.urlParams["username"]
      
      if "first" in req.urlParams:
        echo "first is: " & req.urlParams["first"]

      if "second" in req.urlParams:
        echo "second is: " & req.urlParams["second"]

      if "lang" in req.urlParams:
        echo "lang is: " & req.urlParams["lang"]


    router.addRoute("/greet", handleGreet, HttpGet, @[])
    router.addRoute("/greet/:username", handleGreet, HttpGet, @[])
    router.addRoute("/greet/:first/:second/:lang", handleGreet, HttpGet, @[])



```
`addRoute` takes the following params
- `pat` route pattern
- `handlerFunc` to execute on match
- `httpMethod` to only execute on a certain http method
- `middlewares` list of middlewares to execute before request (for specific route) 
the captured route variables are available in `req.urlParams` table
  

### Handling different HTTP methods

```nim
    proc handlePost(req: Request, res: Response) : Future[void] {.async.} =
      #   req.fullInfo
      echo "USERNAME: " & $(req.formData.getValueOrNone("username"))
      res.code = Http200
      res.content = $req



router.addRoute("/post", handlePost, HttpPost)

```
Here we handle `POST` on path `/post` with handler `handlePost`
- `formData` table is available on the request body handling both `multipart` and `x-www-form-urlencoded` post formats
- `req.formData.getValueOrNone` gives you access to form data.


### Abort
```nim
proc handleAbort(req: Request, res: Response) : Future[void] {.async.} =
      res.abortWith("sorry mate")

router.addRoute("/abort", handleAbort, HttpGet)

```
response object has `abortWith` proc available 


### Redirect

```nim

proc handleRedirect(req: Request, res:  Response): Future[void] {.async.} =
      res.redirectTo("https://python.org")

router.addRoute("/redirect", handleRedirect, HttpGet)

```
response object has `redirectTo` proc available, also you can set status code as optional param.



## Defining middlewares

Here's an example of a logging middleware that runs before processing any handler

### Logging Middleware
```nim
proc loggingMiddleware*(request: Request,  response: Response): Future[bool] {.async.} =
  let path = request.path
  let headers = request.headers
  echo "==============================="
  echo "from logger handler"
  echo "path: " & path
  echo "headers: " & $headers
  echo "==============================="
  return true
```
if you want to terminate the middleware chain return false


### Trim slashes Middleware

```nim
proc trimTrailingSlash*(request: Request,  response: Response): Future[bool] {.async.} =
  let path = request.path
  if path.endswith("/"):
    request.path = path[0..^2]

  echo "==============================="
  echo "from slash trimmer "
  echo "path was : " & path
  echo "path: " & request.path
  echo "==============================="
  return true

```


### Static files middleware

```nim
let serveTmpDir = newStaticMiddleware("/tmp", "/tmppublic")
let serveHomeDir = newStaticMiddleware(getHomeDir(), "/homepublic")
```
You can serve static assets from a certain directory using static middleware.

`newStaticMiddleware` takes in a directory to serve and a path `onRoute` to serve on.

### Basic Auth

Here's how it's defined
```nim

proc basicAuth*(users: Table[string, string], realm="private", text="Access denied"): proc(request: Request, response: Response): Future[bool] {.async, closure, gcsafe.} =


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

```

#### Example of HTTP Basic Auth

```nim

    proc handleBasicAuth(req: Request, res: Response) : Future[void] {.async.} =
      res.code = Http200
      res.content = "logged in!!"

    let users = {"ahmed":"password", "xmon":"xmon"}.toTable
    router.addRoute("/basicauth", handleBasicAuth, HttpGet, @[basicAuth(users)])

```

## Websockets

servy is integrated with [treeform/ws](https://github.com/treeform/ws) for websocket support, here is an example

```nim
    proc handleWS(req: Request, res: Response) : Future[void] {.async.} =
      var ws = await newServyWebSocket(req)
      await ws.send("Welcome to simple echo server")
      while ws.readyState == Open:
        let packet = await ws.receiveStrPacket()
        await ws.send(packet)

    router.addRoute("/ws", handleWS, HttpGet, @[])
```
and to test you can use nim client e.g

```nim
import ws, asyncdispatch, asynchttpserver

proc main(): Future[void]{.async.} =
    var w = await newWebSocket("ws://127.0.0.1:9000/ws")
    echo await w.receiveStrPacket()
    await w.send("Hi, how are you?")
    echo await w.receiveStrPacket()
    w.close()

waitFor main()
```

or from javascript 

```javascript
> ws = new WebSocket("ws://127.0.0.1:9000/ws")
> ws.onmessage = (m)=>console.log(m.data)
(m)=>console.log(m.data)
> ws.send("bye")
bye
```


## Running

```nim
let opts = ServerOptions(address:"127.0.0.1", port:9000.Port)
var s = initServy(opts, router, @[loggingMiddleware, trimTrailingSlash, serveTmpDir, serveHomeDir])
s.run()
```

`initServy` takes in some options for binding address and the router to use for incoming requests in a list of middlewares to execute before handlers.


## curl examples

Here are some curl examples to play with servy if you start it with `nimble run servy`

```nim
curl localhost:9000/hello
curl localhost:9000/greet
curl localhost:9000/greet/ahmed
curl localhost:9000/greet/first/sec/en
curl -XPOST localhost:9000/post
curl -X POST -F 'username=auser' -F 'password=apassword' http://localhost:9000/post
curl -X POST -F 'myfile=@servy.nimble' http://localhost:9000/post
curl -L localhost:9000/abort
curl -L localhost:9000/redirect

```