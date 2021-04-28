package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"log"
	"net"
	"golang.org/x/crypto/pbkdf2"
	"github.com/google/go-cmp/cmp"
)

var ap net.Listener

type handshakeState struct {
	msgcount int
	ptkinstalled bool
	pmk      []byte
	ptk      []byte
	Anonce   []byte
	Snonce   []byte
	replay   uint64
}

type packet struct {
	descr         uint8
	info          uint16
	keylen        uint16
	replaycounter uint64
	nonce         int
	mic           int
}

var hs handshakeState

func send(msg []byte) {
	// connect to mitm
	conn, err := net.Dial("tcp", "127.0.0.1:8003")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer conn.Close()
	conn.Write(msg)

}

func recv() {
	for {
		s, _ := ap.Accept()
		msg := make([]byte, 512)
		n, _ := s.Read(msg)
		msg = msg[:n]
		switch msg[0] {
		case 2:
			handleMsg2(msg)
			sendMsg3()
			//hs.msgcount++
		case 4:
			handleMsg4(msg)
		default:
			pt, _ := decrypt(msg)
			log.Println("Data: ", string(pt))

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

func init() {
	//intializing values
	hs = handshakeState{
		msgcount: 0,
		ptkinstalled: false,
		pmk:      pbkdf2.Key([]byte("arandompassword"), []byte("testnetwork"), 4096, 32, sha1.New),
		ptk:      []byte{},
		Anonce:   nonce(),
		Snonce:   []byte{},
		replay:   1,
	}
}

func handleMsg2(tmp []byte) {
	log.Println("Received handshake message 2/4")
	hs.Snonce = append([]byte{}, tmp[1:33]...) //probably to cut the size
	t := append(hs.Anonce, hs.Snonce...)
	t1 := append([]byte("BD:B2:12:3F:18:F9"), []byte("6D:BF:EC:03:F0:2B")...)
	t2 := append(t, t1...)
	hs.ptk = pbkdf2.Key(hs.pmk, t2, 4096, 64, sha1.New) //actually md5
	//tk is hs.ptk[64:192]
	if !verifyMIC(tmp[:33],tmp[33:]){
		log.Fatal("MIC check failed")
	}
	log.Println("MIC check valid")
	//client is auth here...
}

func encrypt(msg []byte) []byte{
	key := append([]byte{}, hs.ptk[32:48]...)
	nonce := make([]byte, 12)
	binary.LittleEndian.PutUint64(nonce, hs.replay)
	b, _ := aes.NewCipher(key)
	c, _ := cipher.NewGCM(b)
	hs.replay++
	return c.Seal(nil, nonce, msg, nil)
}

func decrypt(msg []byte) ([]byte, error) {
	key := append([]byte{}, hs.ptk[32:48]...)
	nonce := make([]byte, 12)
	binary.LittleEndian.PutUint64(nonce, hs.replay)
	b, _ := aes.NewCipher(key)
	c, _ := cipher.NewGCM(b)
	hs.replay++
	return c.Open(nil, nonce, msg, nil)
}


func sendMsg3() {
	msg := append([]byte{3}, []byte("key_installation")...)
	mic := hmac_hash(msg, hs.ptk[:16])[:16]
	send(append(msg, mic...))//msg 3 of 4 must be stopped from attacker
	log.Println("Sent handshake message 3/4")
}

func handleMsg4(tmp []byte) {
	log.Println("Received handshake message 4/4")

	if !verifyMIC(tmp[:len(tmp)-16],tmp[len(tmp)-16:]) {
		log.Fatal("MIC check failed")
	}
	//installing current PTK
	hs.replay = 0
	hs.ptkinstalled = true
	//setting 48bit nonce to zero
	log.Println("PTK installed")
}

func verifyMIC(data, recvMic []byte) bool{
	mic := hmac_hash(data, hs.ptk[:16])[:16]
	return cmp.Equal(mic,recvMic)
}

func main() {

	fmt.Println("Start access point...")
	var err error
	ap, err = net.Listen("tcp", ":8000")
	if err != nil {
		log.Fatal(err)
		return
	}

	go recv()
	msg1 := append([]byte{1}, hs.Anonce...)
	send(msg1)//msg 1 of 4
	fmt.Println("Sent handshake message 1/4")
	for {
		if hs.msgcount == 5 {
			break
		}
	}
}
