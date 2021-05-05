package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/binary"
	"log"
	"net"
	"time"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
)

//a lot of functions can be abstracted into a separated module
//but for now let's just keep them this way
var client net.Listener

type handshakeState struct {
	ptkinstalled bool
	pmk          []byte
	ptk          []byte
	Anonce       []byte
	Snonce       []byte
	Counter      uint64
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
	//copy(h[54:70], m) mic is empty here
	return h
}

var hs handshakeState

const (
	PWD        = "abcdefgh"
	SSID       = "wpa2simulation"
	LOCAL_MAC  = "6D:BF:EC:03:F0:2B"
	REMOTE_MAC = "BD:B2:12:3F:18:F9"
)

func send(msg []byte, conn net.Conn) {
	conn.Write(msg)
	hs.Counter++
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
		case 3: //handshake
			c := binary.LittleEndian.Uint64(msg[6:14])
			switch c {
			case 0:
				initialize()
				handleMsg1(msg[:n])
				m := buildMsg2()
				send(m, s)
				log.Println("Sent handshake message 2/4")
			case 1:
				handleMsg3(msg[:n])
				m := buildMsg4()
				send(m, s)
				hs.Counter = 0
				log.Println("Sent handshake message 4/4")
				//start sending data packets
				sendDataPacket(s)
				//sendDataPacket(s)
				//sendDataPacket(s)
			case 4:
				//no
			}
		case 5:
			//handleEncrypted(msg[:n])
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
	return h.Sum(nil)[:16]
}

func initialize() {
	hs = handshakeState{
		ptkinstalled: false,
		pmk:          pbkdf2.Key([]byte(PWD), []byte(SSID), 4096, 32, sha1.New),
		ptk:          nil,
		Anonce:       make([]byte, 32),
		Snonce:       nonce(),
		Counter:      0,
	}
}

func prf384(key, data []byte) []byte {
	k := make([]byte, 48)
	f := hkdf.New(sha512.New384, key, data, nil)
	f.Read(k)
	return k
}

func handleMsg1(tmp []byte) {
	copy(hs.Anonce, tmp[14:46])
	rnd := make([]byte, 98)
	copy(rnd[:32], hs.Anonce)
	copy(rnd[32:64], hs.Snonce)
	copy(rnd[64:81], []byte(REMOTE_MAC))
	copy(rnd[81:], []byte(LOCAL_MAC))

	hs.ptk = prf384(hs.pmk, rnd)
}

func buildMsg2() []byte {
	h := EncodeHeader(3,
		2, 0, 16, hs.Counter, hs.Snonce)
	mic := hmac_hash(h, hs.ptk[:16])
	copy(h[54:70], mic)
	return h
}

func handleMsg3(msg []byte) {
	//parse header
	recvMic := append([]byte{}, msg[54:70]...)
	copy(msg[54:70], make([]byte, 16))

	if !verifyMIC(msg, recvMic) {
		log.Fatal("MIC check failed")
	}
}

func buildMsg4() []byte {
	h := EncodeHeader(3, 2, 0, 16, hs.Counter, hs.Snonce)
	msg := append(h, []byte("confirm_key_installation")...)
	mic := hmac_hash(msg, hs.ptk[:16])
	copy(msg[54:70], mic)
	hs.ptkinstalled = true
	log.Println("PTK installed")
	return msg
}

func sendDataPacket(s net.Conn) {
	time.Sleep(2 * time.Second)
	m := []byte("thisisatestmessage")
	msg := make([]byte, 9)
	msg[0] = byte(5)
	binary.LittleEndian.PutUint64(msg[1:9], hs.Counter)
	n := make([]byte, 12)
	copy(n[:8], msg[1:9])
	copy(n[8:], []byte(LOCAL_MAC)[:4])
	log.Println(n)
	enc := encrypt(m, n)
	log.Println("Sending encrypted packet...")
	send(append(msg, enc...), s)
}

func verifyMIC(data, recvMic []byte) bool {
	mic := hmac_hash(data, hs.ptk[:16])
	return cmp.Equal(mic, recvMic)
}

func encrypt(msg, nonce []byte) []byte {
	key := hs.ptk[32:]
	b, e := aes.NewCipher(key)
	if e != nil {
		log.Fatal(e)
	}
	c, err := cipher.NewGCM(b)
	if err != nil {
		log.Fatal(err)
	}
	ct := c.Seal(nil, nonce, msg, nil)
	log.Println(ct)
	return ct
}

func run() {
	var err error
	client, err = net.Listen("tcp", ":8003")
	if err != nil {
		log.Fatal(err)
		return
	}
	s, err := net.Dial("tcp", "127.0.0.1:8002")
	if err != nil {
		log.Fatal("Server unavailable")
	}
	recv(s)

}

func prf(k, a, b []byte) []byte {
	blen := 64
	var r []byte
	for len(r) < blen {
		f := hmac.New(sha1.New, k)
		data := append(a, b...) //e altra roba
		f.Write(data)
		r = append(r, f.Sum(nil)...)
	}
	return r[:blen]
}

func main() {
	//log.Println(len(prf([]byte("SIMOLAPORCODIO"), []byte("lucamerlivocalist"), []byte("marcomalatestaluomochepiace"))))

	run()
}
