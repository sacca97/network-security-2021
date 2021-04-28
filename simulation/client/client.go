package main

import (
	"crypto/aes"
	"github.com/google/go-cmp/cmp"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"time"
	"crypto/cipher"
	"golang.org/x/crypto/pbkdf2"
)

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

func send(msg []byte) {
	// connect to mitm
	conn, err := net.Dial("tcp", "127.0.0.1:8000")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer conn.Close()
	conn.Write(msg)

}

func recv() {
	for {
		s, _ := client.Accept()
		msg := make([]byte, 512)
		n, _ := s.Read(msg)
		msg = msg[:n]
		//tmp contains the actual message
		switch msg[0] {
		case 1:
			initialize()
			handleMsg1(msg)
			sendMsg2()
		case 3:
			handleMsg3(msg)
			sendMsg4()
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

func initialize(){
	hs = handshakeState{
		msgcount:     0,
		ptkinstalled: false,
		pmk:          pbkdf2.Key([]byte("arandompassword"), []byte("testnetwork"), 4096, 32, sha1.New),
		ptk:          []byte{},
		Anonce:       []byte{},
		Snonce:       nonce(),
		replay:       1,
	}
}

func handleMsg1(tmp []byte) {
	log.Println("Received handshake message 1/4")
	hs.Anonce = append([]byte{}, tmp[1:33]...)
	t := append(hs.Anonce, hs.Snonce...)
	t1 := append([]byte("BD:B2:12:3F:18:F9"), []byte("6D:BF:EC:03:F0:2B")...)
	t2 := append(t, t1...)
	hs.ptk = pbkdf2.Key(hs.pmk, t2, 4096, 64, sha1.New)
}

func sendMsg2(){
	log.Println("Sent handshake message 2/4")
	msg := append([]byte{2}, hs.Snonce...)
	mic := hmac_hash(msg, hs.ptk[:16])[:16]
	send(append(msg, mic...))//msg 2 of 4
}

func handleMsg3(tmp []byte) {
	log.Println("Received handshake message 3/4")
	if !verifyMIC(tmp[:len(tmp)-16],tmp[len(tmp)-16:]) {
		log.Fatal("MIC check failed")
	}
	log.Println("MIC check valid")
}

func sendMsg4() {
	//installing current PTK
	hs.replay = 0
	hs.ptkinstalled = true
	log.Println("PTK installed")
	msg := append([]byte{4}, []byte("key_installation_confirm")...)
	mic := hmac_hash(msg, hs.ptk[:16])[:16]
	send(append(msg, mic...))
	log.Println("Sent handshake message 4/4")
	go sendData()
}

func sendData(){
	time.Sleep(5*time.Second)
	send(encrypt([]byte("Simolachecazzoesimola")))
}

func installPTK(){
	//on msg3 receive verify the MIC and install the PTK


	//send msg 4 of 4 telling AP to install the PTK with a MIC
}

func verifyMIC(data, recvMic []byte) bool{
	mic := hmac_hash(data, hs.ptk[:16])[:16]
	return cmp.Equal(mic,recvMic)
}

func encrypt(msg []byte) []byte{
	key := append([]byte{}, hs.ptk[32:48]...)
	nonce := make([]byte, 12)
	binary.LittleEndian.PutUint64(nonce, hs.replay)
	b, _ := aes.NewCipher(key)
	c, _ := cipher.NewGCM(b)
	hs.replay++
	ct := c.Seal(nil, nonce, msg, nil)
	log.Println("Data: ", ct)
	return ct
}


func main() {
	var err error
	client, err = net.Listen("tcp", ":8003")
	if err != nil {
		log.Fatal(err)
		return
	}
	recv()
}
