package mitm

import (
	"fmt"
	"log"
	"net"
)

var clientListener net.Listener
var apListener net.Listener

func sendToAP() {
	// connect to mitm
	conn, err := net.Dial("tcp", "127.0.0.1:8000")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer conn.Close()
}

func sendToClient() {
	// connect to mitm
	conn, err := net.Dial("tcp", "127.0.0.1:8003")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer conn.Close()
}

func recvFromClient() {
	for {
		s, _ := clientListener.Accept()
		tmp := make([]byte, 512)
		n, _ := s.Read(tmp)
		fmt.Println("Message received is ", n, " bit long")
		fmt.Print("Message Received: ", string(tmp))
	}
}

func recvFromAp() {
	for {
		s, _ := apListener.Accept()
		tmp := make([]byte, 512)
		n, _ := s.Read(tmp)
		fmt.Println("Message received is ", n, " bit long")
		fmt.Print("Message Received: ", string(tmp))
	}
}

func main() {
	var err error
	apListener, err = net.Listen("tcp", ":8001")
	clientListener, err = net.Listen("tcp", ":8002")
	fmt.Println(("Initialized..."))
	if err != nil {
		log.Fatal(err)
	}
	// accept connection

	//recv()
	// run loop forever (or until ctrl-c)

}
