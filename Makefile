.PHONY: test build demo
test:
	node --test track4/test/*.test.cjs
build:
	docker build -t keyguard-track4 .
demo:
	./scripts/demo.sh
