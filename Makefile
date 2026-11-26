.PHONY: test build demo review release
test:
	node --test track4/test/*.test.cjs
build:
	docker build -t keyguard-track4 .
demo:
	./scripts/demo.sh
review:
	./scripts/track4-review.sh --docker
release:
	./scripts/package-review.sh
