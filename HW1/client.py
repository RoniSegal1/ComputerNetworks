#!/usr/bin/python3
import socket
import sys

DEFAULT_HOST = "localhost"
DEFAULT_PORT = 1337


def print_usage_and_exit():
    print(f"Usage: {sys.argv[0]} [hostname [port]]", file=sys.stderr)  #check if error is correct or change
    sys.exit(1)


def parse_args():
    argc = len(sys.argv)
    host = DEFAULT_HOST
    port = DEFAULT_PORT

    if argc >= 2:
        host = sys.argv[1]
    if argc == 3:
        try:
            port = int(sys.argv[2])
        except ValueError:
            print("Port must be an integer", file=sys.stderr) #check if error is correct or change
            print_usage_and_exit()
    if argc > 3:
        print_usage_and_exit()

    return host, port


def recv_line(connectionSock):
    data = b""
    while not data.endswith(b"\n"):
        chunk = connectionSock.recv(1)
        if not chunk:
            return ""
        data += chunk
    return data.decode("utf-8", errors="replace").rstrip("\r\n")


def send_line(connectionSock, text):
    msg = (text + "\n").encode("utf-8")
    connectionSock.sendall(msg)


def do_login(connectionSock):
    while True:
        username = input("User: ")
        password = input("Password: ")
        send_line(connectionSock, f"User: {username}")
        send_line(connectionSock, f"Password: {password}")
        reply = recv_line(connectionSock)

        if reply == "":
            print("Server closed connection during login.") #check if need to change
            return False

        print(reply)

        if reply.startswith("Hi "):
            return True


def command_loop(connectionSock):
    while True:
        try:
            command = input()
        except EOFError: #check if need to change
            break

        if command == "":
            continue

        send_line(connectionSock, command)

        if command == "quit":
            break

        reply = recv_line(connectionSock)

        if reply == "":
            print("Server closed connection.") #check if need to change
            break

        print(reply)


def main():
    host, port = parse_args()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connectionSock:
        try:
            connectionSock.connect((host, port))
        except OSError as e: #check if error needed
            print(f"Failed to connect to {host}:{port}: {e}", file=sys.stderr)
            sys.exit(1)

        welcome = recv_line(connectionSock)

        if welcome == "":
            print("Server closed connection.")
            return
        print(welcome)

        if not do_login(connectionSock):
            return

        command_loop(connectionSock)


if __name__ == "__main__":
    main()
