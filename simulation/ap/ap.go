package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/crypto/pbkdf2"
)

//ap is listening on port 8000
//mitm on port 8001 from ap and 8002 from client to simplify
//client is port 8003
var ap net.Listener

type handshakeState struct {
	msgcount     int
	ptkinstalled bool
	pmk          []byte
	ptk          []byte
	Anonce       []byte
	Snonce       []byte
	replay       uint64
}

//I don't think I'll implement a packet structure but just let this here
type packet struct {
	descr         uint8
	info          uint16
	keylen        uint16
	replaycounter uint64
	nonce         int
	mic           int
}

var hs handshakeState

const (
	password = "abcdefgh"
	ssid     = "wpa2simulation"
)

func recv(s net.Conn) {
	msg := make([]byte, 256)
	for {
		n, err := s.Read(msg)
		if err != nil {
			log.Println("Connection closed by the client")
			return
		}
		switch msg[0] {
		case 2:
			handleMsg2(msg[:n])
			hs.msgcount++
			m := buildMsg3()
			send(m, s)
			log.Println("Sent msg 3/4")
		case 4:
			handleMsg4(msg[:n])
			hs.msgcount++
		case 5: //encrypted data packet
			pt, err := handleEncrypted(msg[:n])
			if err != nil {
				log.Println(err)
			}
			log.Println("Data: ", string(pt))
		}
	}
}

func send(msg []byte, conn net.Conn) {
	conn.Write(msg)
	hs.replay++
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
		msgcount:     0,
		ptkinstalled: false,
		pmk:          pbkdf2.Key([]byte(password), []byte(ssid), 4096, 32, sha1.New),
		ptk:          []byte{},
		Anonce:       nonce(),
		Snonce:       make([]byte, 32),
		replay:       0,
	}
}

func handleMsg2(tmp []byte) {
	//tmp[0] is message type
	//tmp[1:9] is the counter
	copy(hs.Snonce, tmp[9:41])
	rnd := make([]byte, 98)
	copy(rnd[:32], hs.Anonce)
	copy(rnd[32:64], hs.Snonce)
	copy(rnd[64:81], []byte("BD:B2:12:3F:18:F9"))
	copy(rnd[81:], []byte("6D:BF:EC:03:F0:2B"))

	hs.ptk = pbkdf2.Key(hs.pmk, rnd, 4096, 64, sha1.New)
	//mic := hmac_hash(tmp[:41], hs.ptk[:16])[:16]

	if !verifyMIC(tmp[:len(tmp)-16], tmp[len(tmp)-16:]) {
		log.Fatal("MIC check failed")
	}
	log.Println("MIC check valid")
	//client is auth here...
}

func encrypt(msg []byte) []byte {
	//Ecnryption key in WPA2 is the TK, taken from those bits of the PTK
	key := append([]byte{}, hs.ptk[32:48]...)
	nonce := make([]byte, 12)
	binary.LittleEndian.PutUint64(nonce, hs.replay)
	b, _ := aes.NewCipher(key)
	c, _ := cipher.NewGCM(b)
	return c.Seal(nil, nonce, msg, nil)
}

func handleEncrypted(msg []byte) ([]byte, error) {
	remoteCounter := binary.LittleEndian.Uint64(msg[1:9])
	log.Println(msg)
	if remoteCounter == hs.replay+1 {
		hs.replay++
		return decrypt(msg[9:])
	}
	return []byte{}, errors.New("Replay counter mismatch")
}

func decrypt(msg []byte) ([]byte, error) {
	key := append([]byte{}, hs.ptk[32:48]...)
	nonce := make([]byte, 12)
	binary.LittleEndian.PutUint64(nonce, hs.replay)
	log.Println(hs.replay, msg)
	b, _ := aes.NewCipher(key)
	c, _ := cipher.NewGCM(b)
	return c.Open(nil, nonce, msg, nil)
}

func buildMsg1() []byte {
	msg := make([]byte, 41)
	msg[0] = 1
	binary.BigEndian.PutUint64(msg[1:9], hs.replay)
	copy(msg[9:], hs.Anonce)
	return msg
}

func buildMsg3() []byte {
	msg := make([]byte, 36)
	msg[0] = 3
	binary.BigEndian.PutUint64(msg[1:9], hs.replay)
	copy(msg[9:20], []byte("install_key"))
	//msg := append([]byte(hs.replay), []byte("install key")...)
	mic := hmac_hash(msg[:20], hs.ptk[:16])[:16]
	copy(msg[20:], mic)
	return msg
}

func sendMsg3(s net.Conn) {
	msg := append([]byte{3}, []byte("key_installation")...)
	mic := hmac_hash(msg, hs.ptk[:16])[:16]
	s.Write(append(msg, mic...))
	//send(append(msg, mic...)) //msg 3 of 4 must be stopped from attacker
	log.Println("Sent handshake message 3/4")
}

func handleMsg4(tmp []byte) {

	if !verifyMIC(tmp[:len(tmp)-16], tmp[len(tmp)-16:]) {
		log.Fatal("MIC check failed")
	}
	//installing current PTK
	hs.replay = 0
	hs.ptkinstalled = true
	//setting 48bit nonce to zero
	log.Println("PTK installed")
}

func verifyMIC(data, recvMic []byte) bool {
	mic := hmac_hash(data, hs.ptk[:16])[:16]
	return cmp.Equal(mic, recvMic)
}

func main() {

	fmt.Println("Start access point...")
	var err error
	ap, err = net.Listen("tcp", ":8000")
	if err != nil {
		log.Fatal(err)
		return
	}

	fmt.Println("Waiting for conn..")
	s, _ := ap.Accept()
	fmt.Println("Connected")

	go recv(s)

	m := buildMsg1()
	hs.msgcount++
	send(m, s)
	log.Println("Sent msg 1/4")
	for {
		if hs.msgcount == 5 {
			break
		}
	}
}
