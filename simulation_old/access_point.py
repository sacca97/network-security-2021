import errno
import socket
import sys
import struct
import random

server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_socket.bind(("0.0.0.0", 19990))


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


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


def decrypt(ptk, e_msg):
    # msg in asci

    # xor packet key and msg
    decrypted_msg = ptk ^ int(e_msg)
    sd_msg = hex(decrypted_msg)[2:]

    msg = bytes.fromhex(sd_msg).decode('utf-8')
    print("Decrypted msg ", msg, '\n')
    return msg


def block():
    while True:
        msg = recv_2()
        if msg == "restart":
            break


if __name__ == "__main__":

    input(bcolors.OKGREEN + "Press any key to start." + bcolors.ENDC)

    # Send msg 1
    print('Sending the ANonce to supplicant ')
    send("Msg1(r, ANonce)")

    block()

    # Receive msg 2
    print('Waiting SNonce from supplicant...')
    msg2 = recv()

    block()

    # Send msg 3
    print("Sending GTK to supplicant ")
    send("Msg3(r+1; GTK)")

    block()

    print('Waiting message 4 from supplicant...\n')

    print("Resending GTK to supplicant ")
    send("Msg3(r+2; GTK)")

    block()

    print('Waiting message 4 from supplicant...\n')

    print("Resending GTK to supplicant ")
    send("Msg3(r+3; GTK)")

    block()

    # Receive msg 4
    print('Waiting message 4 from supplicant..')
    msg4 = recv()

    block()

    recv()

    block()

    recv()

    block()

    # Receive data
    print("Waiting data from supplicant")
    data = recv()

    block()

    print("Server Done.")
    server_socket.close()
