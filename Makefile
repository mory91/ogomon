build:
	go generate ./...
	go build -o build/ogomon main.go

