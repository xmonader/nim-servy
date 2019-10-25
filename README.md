# servy

experimentation in providing bottle/flask like framework for nim with support for middlewares

## quickstart

### First create the router

```nim
var router = initRouter()

```

### Define your first handler function

```nim

proc handleHello(req:var Request, res: var Response) =
  res.code = Http200
  res.content = "hello world from handler /hello" & $req

```

### Wire the handler to a path

```nim
router.addRoute("/hello", handleHello)
```




## Defining handlers and wiring them

```nim

proc handleGreet(req:var Request, res: var Response) =
  res.code = Http200
  res.content = "generic greet" & $req


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


proc handlePost(req:var Request, res: var Response) =
  res.code = Http200
  res.content = $req


router.addRoute("/post", handlePost, HttpPost, @[])

```
Here we handle `POST` on path `/post` with handler `handlePost`


### Abort
```nim
proc handleAbort(req:var Request, res: var Response) =
  res.abortWith("sorry mate")

router.addRoute("/abort", handleAbort, HttpGet)

```
response object has `abortWith` proc available 


### Redirect

```nim

proc handleRedirect(req:var Request, res: var Response)=
  res.redirectTo("https://python.org")

router.addRoute("/redirect", handleRedirect, HttpGet)

```
response object has `redirectTo` proc available, also you can set status code as optional param.



## Defining middlewares

Here's an example of a logging middleware that runs before processing any handler

### Logging Middleware
```nim

let loggingMiddleware = proc(request: var Request,  response: var Response): bool {.closure, gcsafe, locks: 0.} =
  let path = request.path
  let headers = request.headers
  echo "==============================="
  echo "from logger handler"
  echo "path: " & path
  # echo "headers: " & $headers
  echo "==============================="
  return true
```
if you want to terminate the middleware chain return false


### Trim slashes Middleware
```
let trimTrailingSlash = proc(request: var Request,  response: var Response): bool {.closure, gcsafe, locks: 0.} =
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


## Running

```nim
let opts = ServerOptions(address:"127.0.0.1", port:9000.Port)
var s = initServy(opts, router, @[loggingMiddleware, trimTrailingSlash, serveTmpDir, serveHomeDir])
s.run()
```

`initServy` takes in some options for binding address and the router to use for incoming requests in a list of middlewares to execute before handlers.
