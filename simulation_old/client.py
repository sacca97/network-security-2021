import socket
import sys
import struct
import random

server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_socket.bind(("0.0.0.0", 19991))


def send(c):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # ss = struct.pack("!50si", c.encode())
    s.sendto(c.encode(), ("127.0.0.1", 19992))
    s.close()
    print("Send: %s\n" % c)


def recv():
    global server_socket
    data, addr = server_socket.recvfrom(1024)
    # s = struct.unpack("!50si", data)
    s = data.decode("utf-8").replace("\0", "")
    print("Received: %s\n" % s)
    return s


def recv_2():
    global server_socket
    data, addr = server_socket.recvfrom(1024)
    # s = struct.unpack("!50si", data)
    s = data.decode("utf-8").replace("\0", "")
    return s


def make_ptk(ANonce, SNonce):
    return ANonce + SNonce


def encrypt(ptk, msg):
    # transform msg to hex
    msg_hex = msg.encode('utf-8').hex()

    # xor packet key and msg
    encrypted_msg = ptk ^ int(msg_hex, 16)
    print("plaintext: ", msg, " encrypted_msg: ", encrypted_msg)
    return encrypted_msg


def block():
    while True:
        msg = recv_2()
        if msg == "restart":
            break


if __name__ == "__main__":
    # Receive msg 1
    print("Waiting ANonce from AP...")
    msg1 = recv()

    block()

    # Send msg 2
    print("Sending Snonce to AP")
    send("Msg2(r, SNonce)")

    block()

    # Receive msg 3
    print("Waiting GTK from AP...")
    msg3 = recv()

    block()

    # Receive two more messages which will be part of a new handshake
    msg1_2 = recv()

    block()

    msg3_2 = recv()

    block()

    # Send msg 4
    print("Sending message 4 to AP")
    send("Msg4(r+1)")

    block()

    print("Installing PTK & GTK")

    # After reading msg1_2 the client answers with an encrypted message 2
    print("Sending message 2 to AP")
    send("Enc-1 ptk{ Msg2(r+2, SNonce) }")

    block()

    # After reading msg3_2 the client answers with an encrypted message 4
    print("Sending message 4 to AP")
    send("Enc-2 ptk{ Msg4(r+3) }")

    block()

    print("Installing PTK & GTK")

    print("Sending data to the AP")
    send("Enc-1 ptk{ Data(...) }")

    block()

    print("Client done.")
    server_socket.close()
