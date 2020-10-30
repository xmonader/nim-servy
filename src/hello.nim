import servy
import strformat, tables, json, strutils, asyncdispatch, asyncnet, strutils, parseutils, options, net, os
import ws


when isMainModule:

    var router = initRouter()
    proc handleHello(req: Request, res: Response) : Future[void] {.async.} =
      res.code = Http200
      res.content = "hello world from handler /hello" & $req

    router.addRoute("/hello", handleHello)

    let assertJWTFieldExists = proc(req: Request, res: Response): Future[bool] {.async, closure, gcsafe.} =
        # echo $request.headers
        let jwtHeaderVals = req.headers.getOrDefault("jwt", @[""])
        let jwt = jwtHeaderVals[0]
        echo "================\n\njwt middleware"
        if jwt.len != 0:
          echo fmt"bye bye {jwt} "
        else:
          echo fmt"sure bye but i didn't get ur name"
        echo "===================\n\n"
        return true

    router.addRoute("/bye", handleHello, HttpGet, @[assertJwtFieldExists])

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


    proc handlePost(req: Request, res: Response) : Future[void] {.async.} =
      #   req.fullInfo
      echo "USERNAME: " & $(req.formData.getValueOrNone("username"))
      res.code = Http200
      res.content = $req


    router.addRoute("/post", handlePost, HttpPost, @[])

    proc handleAbort(req: Request, res: Response) : Future[void] {.async.} =
      res.abortWith("sorry mate")

    proc handleRedirect(req: Request, res:  Response): Future[void] {.async.} =
      res.redirectTo("https://python.org")


    router.addRoute("/redirect", handleRedirect, HttpGet)
    router.addRoute("/abort", handleAbort, HttpGet)


    let serveTmpDir = newStaticMiddleware("/tmp", "/tmppublic")
    let serveHomeDir = newStaticMiddleware(getHomeDir(), "/homepublic")

    proc handleBasicAuth(req: Request, res: Response) : Future[void] {.async.} =
      res.code = Http200
      res.content = "logged in!!"

    let users = {"ahmed":"password", "xmon":"xmon"}.toTable
    router.addRoute("/basicauth", handleBasicAuth, HttpGet, @[basicAuth(users)])


    proc handleWS(req: Request, res: Response) : Future[void] {.async.} =
      var ws = await newServyWebSocket(req)
      await ws.send("Welcome to simple echo server")
      while ws.readyState == Open:
        let packet = await ws.receiveStrPacket()
        await ws.send(packet)

    router.addRoute("/ws", handleWS, HttpGet, @[])

    let opts = ServerOptions(address:"127.0.0.1", port:9000.Port, debug:true)
    var s = initServy(opts, router, @[serveTmpDir, serveHomeDir, loggingMiddleware, trimTrailingSlash])
    s.run() 
    
