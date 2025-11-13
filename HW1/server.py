#!/usr/bin/python3
import socket
import sys
import select
import math

DEFAULT_PORT = 1337
BACKLOG = 5
HOST = ""
WELCOME_MSG = "Welcome! Please log in.\n"
FAILED_LOGIN_MSG = "Failed to login.\n"


def print_usage_and_exit():
    print(f"Usage: {sys.argv[0]} users_file [port]", file=sys.stderr)  #check if need to change name of error
    sys.exit(1)


def parse_args():
    argc = len(sys.argv)

    if argc < 2 or argc > 3:
        print_usage_and_exit()

    users_file = sys.argv[1]

    if argc == 3:
        try:
            port = int(sys.argv[2])
        except ValueError:
            print("Port must be an integer", file=sys.stderr) #check if need to change name of error
            print_usage_and_exit()
    else:
        port = DEFAULT_PORT

    return users_file, port


def load_users(users_file_path):
    users = {}
    try:
        with open(users_file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts = line.split()
                if len(parts) < 2:
                    continue
                username, password = parts[0], parts[1]
                users[username] = password
    except OSError as e:
        print(f"Failed to open users file '{users_file_path}': {e}", file=sys.stderr)
        sys.exit(1)

    return users


def recv_line(connectionSock):
    data = b""
    while not data.endswith(b"\n"):
        try:
            chunk = connectionSock.recv(1)
        except ConnectionError:
            return ""
        if not chunk:
            return ""
        data += chunk

    return data.decode("utf-8", errors="replace").rstrip("\r\n")


def parse_prefixed_value(line, prefix):
    if (not line) or (not line.startswith(prefix)):
        return ""
    value = line[len(prefix):].lstrip()
    return value


def check_user_correct(user, password, users_dict):
    if user not in users_dict:
        return False
    return users_dict[user] == password


def parentheses_balanced(s):
    count = 0
    for ch in s:
        if ch == '(':
            count += 1
        elif ch == ')':
            count -= 1
            if count < 0:
                return False
    return count == 0


def compute_lcm(x, y):
    if x == 0 or y == 0:
        return 0
    g = math.gcd(x, y)
    return abs(x // g * y)


def caesar_cipher(plaintext, shift):
    for ch in plaintext:
        if ch == ' ':
            continue
        if not ('a' <= ch <= 'z' or 'A' <= ch <= 'Z'):
            return None

    shift = shift % 26
    res_chars = []

    for ch in plaintext:
        if ch == ' ':
            res_chars.append(' ')
        elif 'a' <= ch <= 'z':
            base = ord('a')
            res_chars.append(chr(base + (ord(ch) - base + shift) % 26))
        elif 'A' <= ch <= 'Z':
            base = ord('A')
            res_chars.append(chr(base + (ord(ch) - base + shift) % 26))
        else:
            return None

    return ''.join(res_chars)


def handle_command(sock, client_state, line):
    line = line.strip()
    prefix_parentheses = "parentheses: "
    prefix_lcm = "lcm: "
    prefix_caesar = "caesar: "

    if line == "quit":
        return True

    #parentheses
    if line.startswith(prefix_parentheses):
        ans = "no"
        expr = line[len(prefix_parentheses):].lstrip()
        balanced = parentheses_balanced(expr)
        if (balanced):
            ans = "yes"
        resp = f"the parentheses are balanced: {ans}\n"
        sock.sendall(resp.encode("utf-8"))
        return False

    # lcm
    if line.startswith(prefix_lcm):
        rest = line[len(prefix_lcm):].strip()
        parts = rest.split()
        if len(parts) != 2:
            sock.sendall(b"error: invalid input\n")
            return False
        try:
            x = int(parts[0])
            y = int(parts[1])
        except ValueError:
            sock.sendall(b"error: invalid input\n")
            return False
        l = compute_lcm(x, y)
        resp = f"the lcm is: {l}\n"
        sock.sendall(resp.encode("utf-8"))
        return False

    # caesar
    if line.startswith(prefix_caesar):
        rest = line[len(prefix_caesar):].lstrip()
        if " " not in rest:
            sock.sendall(b"error: invalid input\n")
            return False
        plaintext_part, shift_str = rest.rsplit(" ", 1)
        try:
            shift = int(shift_str)
        except ValueError:
            sock.sendall(b"error: invalid input\n")
            return False

        cipher = caesar_cipher(plaintext_part, shift)
        if cipher is None:
            sock.sendall(b"error: invalid input\n")
        else:
            resp = f"the ciphertext is: {cipher}\n"
            sock.sendall(resp.encode("utf-8"))
        return False

    sock.sendall(b"error: invalid input\n")
    return True


def main():
    users_file, port = parse_args()
    users_dict = load_users(users_file)

    clients = {}

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
        server_sock.bind((HOST, port))
        server_sock.listen(BACKLOG)
        sockets_list = [server_sock]
        while True:
            readable, _, _ = select.select(sockets_list, [], [], 10.0)
            if not readable:
                continue

            for current_sock in readable:
                if current_sock is server_sock:
                    connection, addr = server_sock.accept()
                    sockets_list.append(connection)
                    clients[connection] = {
                        "addr": addr,
                        "logged_in": False,
                        "login_stage": "user",
                        "pending_username": None,
                    }
                    connection.sendall(WELCOME_MSG.encode("utf-8"))
                else:
                    client_state = clients.get(current_sock)
                    if client_state is None:
                        if current_sock in sockets_list:
                            sockets_list.remove(current_sock)
                        current_sock.close()
                        continue

                        if not client_state["logged_in"]:
                            line = recv_line(current_sock)
                            if not line:
                                addr = client_state["addr"]
                                if current_sock in sockets_list:
                                    sockets_list.remove(current_sock)
                                del clients[current_sock]
                                current_sock.close()
                                continue

                            if client_state["login_stage"] == "user":
                                username = parse_prefixed_value(line, "User:")
                                if username == "":
                                    current_sock.sendall(FAILED_LOGIN_MSG.encode("utf-8"))
                                else:
                                    client_state["pending_username"] = username
                                    client_state["login_stage"] = "password"

                            elif client_state["login_stage"] == "password":
                                password = parse_prefixed_value(line, "Password:")
                                username = client_state["pending_username"]
                                if password == "" or username is None:
                                    current_sock.sendall(FAILED_LOGIN_MSG.encode("utf-8"))
                                    client_state["pending_username"] = None
                                    client_state["login_stage"] = "user"
                                else:
                                    if not check_user_correct(username, password, users_dict):
                                        current_sock.sendall(FAILED_LOGIN_MSG.encode("utf-8"))
                                        client_state["pending_username"] = None
                                        client_state["login_stage"] = "user"
                                    else:
                                        hi_msg = f"Hi {username}, good to see you.\n"
                                        current_sock.sendall(hi_msg.encode("utf-8"))
                                        client_state["logged_in"] = True
                                        client_state["login_stage"] = None
                                        client_state["pending_username"] = None
                            continue

                    line = recv_line(current_sock)

                    if not line:
                        addr = client_state["addr"]
                        if current_sock in sockets_list:
                            sockets_list.remove(current_sock)
                        del clients[current_sock]
                        current_sock.close()
                        continue

                    result = handle_command(current_sock, client_state, line)
                    if result:
                        addr = client_state["addr"]
                        if current_sock in sockets_list:
                            sockets_list.remove(current_sock)
                        del clients[current_sock]
                        current_sock.close()
                        continue


if __name__ == "__main__":
    main()

