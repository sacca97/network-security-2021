package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/crypto/pbkdf2"
)

//a lot of functions can be abstracted into a separated module
//but for now let's just keep them this way
var client net.Listener

type handshakeState struct {
	msgcount     int
	ptkinstalled bool
	pmk          []byte
	ptk          []byte
	Anonce       []byte
	Snonce       []byte
	replay       uint64
}

var hs handshakeState

const (
	password = "abcdefgh"
	ssid     = "wpa2simulation"
)

func send(msg []byte, conn net.Conn) {
	conn.Write(msg)
	hs.replay++
}

func recv(s net.Conn) {

	//defer conn.Close()
	msg := make([]byte, 256)
	for {
		n, err := s.Read(msg)

		if err != nil {
			log.Println("Connection closed by the server")
			return
		}
		if n == 0 {
			continue
		}
		switch msg[0] {
		case 1:
			initialize()
			handleMsg1(msg[:n])
			m := buildMsg2()
			send(m, s)
			log.Println("Sent msg 2/4")
		case 3:
			handleMsg3(msg[:n])
			m := buildMsg4()
			send(m, s)
			log.Println("Sent msg 4/4")
			go sendDataPacket(s)
		default:
			fmt.Println("Wait...")
		}
	}
}

func nonce() []byte {
	n := make([]byte, 32)
	_, err := rand.Read(n)
	if err != nil {
		log.Fatal(err)
	}
	return n
}

func hmac_hash(msg, key []byte) []byte {
	h := hmac.New(sha1.New, key)
	h.Write(msg)
	return h.Sum(nil)
}

func initialize() {
	hs = handshakeState{
		msgcount:     0,
		ptkinstalled: false,
		pmk:          pbkdf2.Key([]byte(password), []byte(ssid), 4096, 32, sha1.New),
		ptk:          []byte{},
		Anonce:       make([]byte, 32),
		Snonce:       nonce(),
		replay:       0,
	}
}

func handleMsg1(tmp []byte) {
	//tmp[0] is message type
	//tmp[1:9] is the counter
	copy(hs.Anonce, tmp[9:41])
	rnd := make([]byte, 98)
	copy(rnd[:32], hs.Anonce)
	copy(rnd[32:64], hs.Snonce)
	copy(rnd[64:81], []byte("BD:B2:12:3F:18:F9"))
	copy(rnd[81:], []byte("6D:BF:EC:03:F0:2B"))

	hs.ptk = pbkdf2.Key(hs.pmk, rnd, 4096, 64, sha1.New)
}

func buildMsg2() []byte {
	msg := make([]byte, 57)
	msg[0] = 2
	binary.BigEndian.PutUint64(msg[1:9], hs.replay)
	copy(msg[9:41], hs.Snonce)
	//msg := append([]byte{2}, hs.Snonce...)
	mic := hmac_hash(msg[:41], hs.ptk[:16])[:16]
	copy(msg[41:], mic)

	return msg
	//s.Write(append(msg, mic...)) //msg 2 of 4
}

func handleMsg3(tmp []byte) {
	log.Println("Received msg 3/4")
	if !verifyMIC(tmp[:len(tmp)-16], tmp[len(tmp)-16:]) {
		log.Fatal("MIC check failed")
	}
	log.Println("MIC check valid")
}

func buildMsg4() []byte {
	//installing current PTK
	msg := make([]byte, 44)
	msg[0] = 4
	binary.BigEndian.PutUint64(msg[1:9], hs.replay)
	copy(msg[9:28], []byte("install_key_confirm"))
	mic := hmac_hash(msg[:28], hs.ptk[:16])[:16]
	copy(msg[28:], mic)
	hs.ptkinstalled = true
	log.Println("PTK installed")

	hs.replay = 0
	return msg

	//msg := append([]byte{4}, []byte("key_installation_confirm")...)
	//mic := hmac_hash(msg, hs.ptk[:16])[:16]
	//s.Write(append(msg, mic...))
	//log.Println("Sent handshake message 4/4")
	//go sendData()
}

func sendDataPacket(s net.Conn) {
	time.Sleep(5 * time.Second)
	m := []byte("thisisatestmessage")
	msg := make([]byte, 9)
	msg[0] = 5
	binary.LittleEndian.PutUint64(msg[1:9], hs.replay)
	enc := encrypt(m)
	log.Println("Sending encrypted packet...")

	send(append(msg, enc...), s)
}

func installPTK() {
	//on msg3 receive verify the MIC and install the PTK

	//send msg 4 of 4 telling AP to install the PTK with a MIC
}

func verifyMIC(data, recvMic []byte) bool {
	mic := hmac_hash(data, hs.ptk[:16])[:16]
	return cmp.Equal(mic, recvMic)
}

func encrypt(msg []byte) []byte {
	key := append([]byte{}, hs.ptk[32:48]...)
	n := make([]byte, 12)
	binary.LittleEndian.PutUint64(n, hs.replay)
	log.Println(hs.replay)
	b, _ := aes.NewCipher(key)
	c, _ := cipher.NewGCM(b)
	ct := c.Seal(nil, n, msg, nil)
	return ct
}

func main() {
	//var err error
	//client, err = net.Listen("tcp", ":8003")
	//if err != nil {
	//	log.Fatal(err)
	//	return
	//}
	s, err := net.Dial("tcp", "127.0.0.1:8000")

	if err != nil {
		log.Fatal("Server unavailable")
	}
	recv(s)
}
