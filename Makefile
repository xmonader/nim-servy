.PHONY: build test lint clean examples

build:
	nim c --path:src examples/hello.nim
	nim c --path:src tests/test_app.nim

test:
	bash tests/run_tests.sh

lint:
	nimpretty --recursive src/

clean:
	rm -f examples/hello examples/hello.exe
	rm -f tests/test_app tests/test_app.exe
	rm -rf nimcache
	rm -rf tests/nimcache

examples: build
