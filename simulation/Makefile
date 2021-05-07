build: ap/ap.go mitm/mitm.go client/client.go
	go build -o ap/ap ap/ap.go
	go build -o mitm/mitm mitm/mitm.go
	go build -o client/client client/client.go

clean: ap/ap mitm/mitm client/client
	rm ap/ap mitm/mitm client/client