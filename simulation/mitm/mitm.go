package main

import (
	"encoding/binary"
	"log"
	"net"
)

//mitm is still to do
var ap, client net.Conn

func handleIncomingAP() {
	msg := make([]byte, 128)
	for {
		//try to read from AP
		n, err := ap.Read(msg)

		if err != nil {
			log.Fatal("Connection closed by the AP")
		}
		if n == 0 {
			continue
		}
		client.Write(msg[:n])
	}
}

func handleIncomingClient() {
	msg := make([]byte, 128)
	for {
		n, err := client.Read(msg)
		if err != nil {
			log.Fatal("Connection closed by the client")
		}
		switch msg[0] {
		case 3:
			c := binary.LittleEndian.Uint64(msg[6:14])
			switch c {
			case 4:
				log.Printf("Blocking handshake message %d/4", c)
			default:
				log.Printf("Forwarding handshake message %d/4", c)
				ap.Write(msg[:n])
			}
		case 5:
			ap.Write(msg[:n])
			//encrypted message
		}

	}
}

func run() {
	var err error
	ap, err = net.Dial("tcp", "127.0.0.1:8000")
	if err != nil {
		log.Fatal("AP unavailable")
	}
	log.Println("Connected to the real AP")
	mitm, _ := net.Listen("tcp", ":8002")
	log.Println("Waiting for client connection..")
	client, err = mitm.Accept()
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Client connected to the fake AP")
	log.Println("MitM position obtained")
	go handleIncomingClient()
	handleIncomingAP()
}

func main() {
	run()
	//recv()
	// run loop forever (or until ctrl-c)

}
