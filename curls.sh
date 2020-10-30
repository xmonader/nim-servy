curl localhost:9000/hello
curl localhost:9000/greet
curl localhost:9000/greet/ahmed
curl localhost:9000/greet/first/sec/en
curl -XPOST localhost:9000/post
curl -X POST -F 'username=davidwalsh' -F 'password=something' http://localhost:9000/post
curl -X POST -F 'myfile=@servy.nimble' http://localhost:9000/post
curl -L localhost:9000/abort
curl -L localhost:9000/redirect
