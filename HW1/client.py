#!/usr/bin/python3
import socket
import ipaddress
import sys
import re

DEFAULT_HOST = "localhost"
DEFAULT_PORT = 1337
USER_PREFIX = "User: "
PASSWORD_PREFIX = "Password: "
PARENTHESES_PREFIX = "parentheses: "
LCM_PREFIX = "lcm: "
CAESAR_PREFIX = "caesar: "


def print_error_and_exit(err_msg):
    print(err_msg)
    sys.exit(1)


def print_error_and_close(con_socket, err_msg):
    con_socket.close()
    print_error_and_exit(err_msg)


def validate_hostname(hostname):
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        pass

    domain_regex = re.compile(r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z]{2,6})+$')
    if domain_regex.match(hostname) or hostname == 'localhost':
        return True

    return False


def validate_port(port):
    try:
        port = int(port)
        if not 0 <= port <= 65535:
            return False
        return True
    except ValueError:
        return False


def parse_args():
    argc = len(sys.argv)
    host = DEFAULT_HOST
    port = DEFAULT_PORT

    if argc >= 2:
        host = sys.argv[1]

        if not validate_hostname(host):
            print_error_and_exit("Error: invalid hostname")
    if argc == 3:
        port = sys.argv[2]

        if not validate_port(port):
            print_error_and_exit("Error: invalid port")
        port = int(port)
    if argc > 3:
        print_error_and_exit("Error: invalid number of arguments")
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


def validate_login_input(user, password):
    return user.startswith(USER_PREFIX) and password.startswith(PASSWORD_PREFIX)


def do_login(connectionSock):
    while True:
        username = input()
        password = input()

        if not validate_login_input(username, password):
            print_error_and_close(connectionSock, "Unexpected login format")

        send_line(connectionSock, f"{username}")
        send_line(connectionSock, f"{password}")
        reply = recv_line(connectionSock)

        if reply == "":
            print_error_and_close(connectionSock, "Server closed connection during login.")

        print(reply)

        if reply.startswith("Hi "):
            break


def validate_parentheses(command):
    parentheses = command[len(PARENTHESES_PREFIX):].strip()

    for ch in parentheses:
        if ch != '(' and ch != ')':
            return False

    return True


def validate_lcm(command):
    rest = command[len(LCM_PREFIX):].strip()
    parts = rest.split()
    if len(parts) != 2:
        return False
    try:
        x = int(parts[0])
        y = int(parts[1])
    except ValueError:
        return False

    return True


def validate_caesar(command):
    rest = command[len(CAESAR_PREFIX):].strip()
    parts = rest.split()
    if len(parts) != 2:
        return False
    try:
        y = int(parts[1])
    except ValueError:
        return False

    return True


def validate_command(connectionSock, command):
    if command.startswith(PARENTHESES_PREFIX):
        return validate_parentheses(command)
    elif command.startswith(LCM_PREFIX):
        return validate_lcm(command)
    elif command.startswith(CAESAR_PREFIX):
        return validate_caesar(command)
    elif command == "":
        return False
    elif command == "quit":
        return True

    print_error_and_close(connectionSock, "Invalid command")


def command_request(connectionSock):
    while True:
        try:
            command = input()
        except EOFError:
            print_error_and_close(connectionSock, "Invalid error")

        if not validate_command(connectionSock, command):
            print("error: invalid input")
            continue

        send_line(connectionSock, command)

        if command == "quit":
            connectionSock.close()
            sys.exit(0)

        reply = recv_line(connectionSock)

        if reply == "":
            print_error_and_close(connectionSock, "Server closed connection during command request.")

        print(reply)


def main():
    host, port = parse_args()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connectionSock:
        try:
            connectionSock.connect((host, port))
        except OSError as e:
            print_error_and_exit("Failed to connect")

        welcome = recv_line(connectionSock)

        if welcome == "":
            print_error_and_close(connectionSock, "Server closed connection.")

        print(welcome)
        do_login(connectionSock)
        command_request(connectionSock)


if __name__ == "__main__":
    main()

