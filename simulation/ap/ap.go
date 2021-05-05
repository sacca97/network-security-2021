package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"log"
	"net"
	"os"
	"time"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
)

//ap is listening on port 8000
//mitm on port 8001 from ap and 8002 from client to simplify
//client is port 8003
var ap net.Listener

type handshakeState struct {
	ptkinstalled bool
	pmk          []byte
	ptk          []byte
	Anonce       []byte
	Snonce       []byte
	Counter      uint64
}

//EAPOL key more or less
type header struct {
	PacketType     uint8
	DescriptorType uint8
	KeyInformation uint16
	KeyLength      uint16
	Counter        uint64
	Nonce          []byte //256 bit, 32 byte
	Reserved       uint64
	Mic            []byte //16 byte, 128 bit
}

func EncodeHeader(pt, dt uint8, ki, kl uint16, c uint64, n []byte) []byte {
	h := make([]byte, 70)
	h[0] = byte(pt)
	h[1] = byte(dt)
	binary.LittleEndian.PutUint16(h[2:4], ki)
	binary.LittleEndian.PutUint16(h[4:6], kl)
	binary.LittleEndian.PutUint64(h[6:14], c)
	copy(h[14:46], n)
	binary.LittleEndian.PutUint64(h[46:54], 0)
	return h
}

var hs handshakeState

const (
	PWD        = "abcdefgh"
	SSID       = "wpa2simulation"
	LOCAL_MAC  = "BD:B2:12:3F:18:F9"
	REMOTE_MAC = "6D:BF:EC:03:F0:2B"
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
		case 3: //handshake
			c := binary.LittleEndian.Uint64(msg[6:14])
			switch c {
			case 0:
				handleMsg2(msg[:n]) //check your counter also which should be 1
				m := buildMsg3()
				send(m, s)
				log.Println("Sent handshake message 3/4")
				//start a routine to check if after x seconds we got msg 4
				go checkAck(s)
			case 1:
				handleMsg4(msg[:n])
			}
		case 5:
			log.Println(msg[:n])
			m, _ := handleEncrypted(msg[:n])
			log.Println(string(m))
		}
	}
}

func checkAck(s net.Conn) {
	time.Sleep(5 * time.Second)
	if !hs.ptkinstalled {
		m := buildMsg3()
		send(m, s)
		log.Println("Sent handshake message 3/4")
	}
}

func send(msg []byte, conn net.Conn) {
	conn.Write(msg)
	hs.Counter++
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
	return h.Sum(nil)[:16]
}

func initialize() {
	hs = handshakeState{
		ptkinstalled: false,
		pmk:          pbkdf2.Key([]byte(PWD), []byte(SSID), 4096, 32, sha1.New),
		ptk:          nil,
		Anonce:       nonce(),
		Snonce:       make([]byte, 32),
		Counter:      0,
	}
}

func handleMsg2(tmp []byte) {
	copy(hs.Snonce, tmp[14:46])
	rnd := make([]byte, 98)
	copy(rnd[:32], hs.Anonce)
	copy(rnd[32:64], hs.Snonce)
	copy(rnd[64:81], []byte(LOCAL_MAC))
	copy(rnd[81:], []byte(REMOTE_MAC))

	hs.ptk = prf384(hs.pmk, rnd) //384 bit per gcm o ccm
	recvMic := append([]byte{}, tmp[54:70]...)
	copy(tmp[54:70], make([]byte, 16))
	if !verifyMIC(tmp, recvMic) {
		log.Fatal("MIC check failed")
	}
}

func prf384(key, data []byte) []byte {
	//non è veramente così ma ok
	k := make([]byte, 48)
	f := hkdf.New(sha512.New384, key, data, nil)
	f.Read(k)
	return k
}

func encrypt(msg []byte) []byte {
	//Ecnryption key in WPA2 is the TK, taken from those bits of the PTK
	key := append([]byte{}, hs.ptk[32:]...)
	nonce := make([]byte, 12)
	binary.LittleEndian.PutUint64(nonce, hs.Counter)
	b, _ := aes.NewCipher(key)
	c, _ := cipher.NewGCM(b)
	return c.Seal(nil, nonce, msg, nil)
}

func handleEncrypted(msg []byte) ([]byte, error) {
	rCounter := binary.LittleEndian.Uint64(msg[1:9])
	log.Println(msg)
	if rCounter == hs.Counter {
		hs.Counter++
		n := make([]byte, 12)
		copy(n[:8], msg[1:9])
		copy(n[8:], []byte(REMOTE_MAC)[:4])
		log.Println(msg)
		return decrypt(msg[9:], n)
	}
	return []byte{}, errors.New("replay counter mismatch")
}

func decrypt(msg, nonce []byte) ([]byte, error) {
	key := hs.ptk[32:]
	b, _ := aes.NewCipher(key)
	c, _ := cipher.NewGCM(b)
	return c.Open(nil, nonce, msg, nil)
}

func buildMsg1() []byte {
	h := EncodeHeader(3, 2, 0, 16, hs.Counter, hs.Anonce)
	return h
}

func buildMsg3() []byte {
	h := EncodeHeader(3, 2, 0, 16, hs.Counter, hs.Anonce)
	msg := append(h, []byte("key_installation")...)
	mic := hmac_hash(msg, hs.ptk[:16])
	copy(msg[54:70], mic)
	return msg
}

func handleMsg4(tmp []byte) {
	recvMic := append([]byte{}, tmp[54:70]...)
	copy(tmp[54:70], make([]byte, 16))
	if !verifyMIC(tmp, recvMic) {
		log.Fatal("MIC check failed")
	}
	hs.Counter = 0
	hs.ptkinstalled = true
	log.Println("PTK installed")
}

func verifyMIC(data, recvMic []byte) bool {
	mic := hmac_hash(data, hs.ptk[:16])
	return cmp.Equal(mic, recvMic)
}

func run() {
	var err error
	ap, err = net.Listen("tcp", ":8000")
	if err != nil {
		log.Fatal(err)
		return
	}
	log.Println("Waiting for connection..")
	s, _ := ap.Accept()
	log.Println("Connected")

	go recv(s)
	//insert commang to start handshake
	r := bufio.NewReader(os.Stdin)
	log.Print("Press ENTER to start the simulation...")
	r.ReadString('\n')
	initialize()
	msg := buildMsg1()
	hs.Counter++
	send(msg, s)
	for {
	} //do nothing
}

func main() {
	run()
}
