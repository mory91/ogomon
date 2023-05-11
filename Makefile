.PHONY: build
build:
	go1.18.2 generate ./...
	go1.18.2 build -o build/ogomon main.go

