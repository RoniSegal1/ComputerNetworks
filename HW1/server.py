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
PARENTHESES_PREFIX = "parentheses: "
LCM_PREFIX = "lcm: "
CAESAR_PREFIX = "caesar: "


def print_error_and_exit(err_msg):
    print(err_msg)
    sys.exit(1)


def print_error_and_close(con_socket, err_msg):
    con_socket.close()
    print_error_and_exit(err_msg)

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
    if argc < 2 or argc > 3:
        print_error_and_exit("Error: invalid number of arguments")

    users_file = sys.argv[1]

    if argc == 3:
        port = sys.argv[2]
        if not validate_port(port):
            print_error_and_exit("Error: invalid port")
        port = int(port)
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
        print_error_and_exit("Failed to open users file ")

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
    shift = shift % 26
    res_chars = []

    for ch in plaintext:
        if ch == ' ':
            res_chars.append(' ')
        else:
            lower_ch = ch.lower()
            base = ord('a')
            res_chars.append(chr(base + (ord(lower_ch) - base + shift) % 26))

    return ''.join(res_chars)


def handle_parentheses_command(sock, line):
    ans = "no"
    expr = line[len(PARENTHESES_PREFIX):].lstrip()
    balanced = parentheses_balanced(expr)
    if balanced:
        ans = "yes"
    resp = f"the parentheses are balanced: {ans}\n"
    sock.sendall(resp.encode("utf-8"))


def handle_lcm_command(sock, line):
    rest = line[len(LCM_PREFIX):].strip()
    parts = rest.split()
    x = int(parts[0])
    y = int(parts[1])
    lcm = compute_lcm(x, y)
    resp = f"the lcm is: {lcm}\n"
    sock.sendall(resp.encode("utf-8"))


def handle_caesar_command(sock, line):
    rest = line[len(CAESAR_PREFIX):].lstrip()
    plaintext_part, shift_str = rest.rsplit(" ", 1)
    shift = int(shift_str)

    for ch in plaintext_part:
        if ch == ' ':
            continue
        if not ch.isalpha():
            sock.sendall(b"error: invalid input\n")
            return

    cipher = caesar_cipher(plaintext_part, shift)
    resp = f"the ciphertext is: {cipher}\n"
    sock.sendall(resp.encode("utf-8"))


def handle_command(sock, line):
    line = line.strip()

    if line == "quit":
        return True

    if line.startswith(PARENTHESES_PREFIX):
        handle_parentheses_command(sock, line)
        return False
    elif line.startswith(LCM_PREFIX):
        handle_lcm_command(sock, line)
        return False
    elif line.startswith(CAESAR_PREFIX):
        handle_caesar_command(sock, line)
        return False
    #Not possible with our client because handled in client
    else:
        sock.sendall(b"error: invalid input\n")
        return True


def disconnect_client(sock, sockets_list, clients):
    if sock in sockets_list:
        sockets_list.remove(sock)
    del clients[sock]
    sock.close()


def accept_new_client(server_sock, sockets_list, clients):
    connection, addr = server_sock.accept()
    sockets_list.append(connection)
    clients[connection] = {
        "addr": addr,
        "logged_in": False,
        "login_stage": "user",
        "pending_username": None,
    }
    connection.sendall(WELCOME_MSG.encode("utf-8"))

def handle_logged_in_client(current_sock, sockets_list, clients):
    line = recv_line(current_sock)
    if not line:
        disconnect_client(current_sock, sockets_list, clients)
        return

    should_quit = handle_command(current_sock, line)
    if should_quit:
        disconnect_client(current_sock, sockets_list, clients)


def handle_login_line(current_sock, client_state, users_dict):
    line = recv_line(current_sock)
    if not line:
        return False

    normalized = line.strip()
    forbidden_prefixes = ("parentheses:", "lcm:", "caesar:")
    if normalized == "quit" or any(normalized.startswith(p) for p in forbidden_prefixes):
        return False
    stage = client_state["login_stage"]

    if stage == "user":
        username = parse_prefixed_value(line, "User:")
        if username == "":
            current_sock.sendall(FAILED_LOGIN_MSG.encode("utf-8"))
        else:
            client_state["pending_username"] = username
            client_state["login_stage"] = "password"
        return True

    if stage == "password":
        password = parse_prefixed_value(line, "Password:")
        username = client_state["pending_username"]
        if password == "" or username is None:
            current_sock.sendall(FAILED_LOGIN_MSG.encode("utf-8"))
            client_state["pending_username"] = None
            client_state["login_stage"] = "user"
            return True

        if not check_user_correct(username, password, users_dict):
            current_sock.sendall(FAILED_LOGIN_MSG.encode("utf-8"))
            client_state["pending_username"] = None
            client_state["login_stage"] = "user"
            return True

        hi_msg = f"Hi {username}, good to see you.\n"
        current_sock.sendall(hi_msg.encode("utf-8"))
        client_state["logged_in"] = True
        client_state["login_stage"] = None
        client_state["pending_username"] = None
        return True

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
                    accept_new_client(server_sock, sockets_list, clients)
                    continue

                client_state = clients.get(current_sock)
                if client_state is None:
                    if current_sock in sockets_list:
                        sockets_list.remove(current_sock)
                    current_sock.close()
                    continue

                if not client_state["logged_in"]: #add if i add a new command while im not logged in
                    result = handle_login_line(current_sock, client_state, users_dict)
                    if not result:
                        disconnect_client(current_sock, sockets_list, clients)
                    continue

                handle_logged_in_client(current_sock, sockets_list, clients)


if __name__ == "__main__":
    main()

