import ws, asyncdispatch, asynchttpserver

proc main(): Future[void]{.async.} =
    var w = await newWebSocket("ws://127.0.0.1:9000/ws")
    echo await w.receiveStrPacket()
    await w.send("Hi, how are you?")
    echo await w.receiveStrPacket()
    w.close()

waitFor main()