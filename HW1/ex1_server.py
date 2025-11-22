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
    """
    Print an error message and terminate the program.

    Args:
           err_msg (str): The error message to display.
    """
    print(err_msg)
    sys.exit(1)


def print_error_and_close(con_socket, err_msg):
    """
        Close a client socket, then print error and exit server.

        Args:
            con_socket (socket.socket): Client socket.
            err_msg (str): The error message.
        """
    con_socket.close()
    print_error_and_exit(err_msg)

def validate_port(port):
    """
        Validate that the provided port is numeric and within range.

        Args:
            port (str): Port as string.

        Returns:
            bool: True if valid, else False.
        """
    try:
        port = int(port)
        if not 0 <= port <= 65535:
            return False
        return True
    except ValueError:
        return False


def parse_args():
    """
        Parse command line arguments:
        - users file path
        - optional port

        Returns:
            (str, int): Tuple (users_file_path, port)
        """
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
    """
        Load users and passwords from a tab-delimited file.

        Args:
            users_file_path (str): Path to users file.

        Returns:
            dict: Mapping username -> password.
        """
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
    """
        Receive a line from a socket until newline ('\n').

        Args:
            connectionSock (socket.socket): Client socket.

        Returns:
            str: The decoded line or empty string on disconnect.
        """
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
    """
        Extract data after a specific prefix.

        Args:
            line (str): Input line.
            prefix (str): Expected prefix.

        Returns:
            str: The extracted value or empty string if invalid.
        """
    if (not line) or (not line.startswith(prefix)):
        return ""
    value = line[len(prefix):].lstrip()
    return value


def check_user_correct(user, password, users_dict):
    """
        Compare provided login credentials to stored users list.

        Args:
            user (str): Username.
            password (str): Password.
            users_dict (dict): Loaded user database.

        Returns:
            bool: True if credentials match.
        """
    if user not in users_dict:
        return False
    return users_dict[user] == password


def parentheses_balanced(s):
    """
        Check whether parentheses are balanced in a string.

        Args:
            s (str): String containing parentheses.

        Returns:
            bool: True if balanced, False otherwise.
        """
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
    """
        Compute least common multiple of two integers.

        Args:
            x (int)
            y (int)

        Returns:
            int: The LCM.
        """
    if x == 0 or y == 0:
        return 0
    g = math.gcd(x, y)
    return abs(x // g * y)


def caesar_cipher(plaintext, shift):
    """
        Apply a Caesar cipher shift on alphabetical characters.

        Args:
            plaintext (str): Input text.
            shift (int): Shift amount.

        Returns:
            str: The shifted cipher text.
        """
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
    """
        Handle parentheses command and send result to client.

        Args:
            sock (socket.socket): Client socket.
            line (str): Full command line.
        """
    ans = "no"
    expr = line[len(PARENTHESES_PREFIX):].lstrip()
    balanced = parentheses_balanced(expr)
    if balanced:
        ans = "yes"
    resp = f"the parentheses are balanced: {ans}\n"
    sock.sendall(resp.encode("utf-8"))


def handle_lcm_command(sock, line):
    """
        Handle LCM command and send result.

        Args:
            sock (socket.socket)
            line (str)
        """
    rest = line[len(LCM_PREFIX):].strip()
    parts = rest.split()
    x = int(parts[0])
    y = int(parts[1])
    lcm = compute_lcm(x, y)
    resp = f"the lcm is: {lcm}\n"
    sock.sendall(resp.encode("utf-8"))


def handle_caesar_command(sock, line):
    """
       Handle Caesar cipher command.

       Args:
           sock (socket.socket)
           line (str)
       """
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
    """
        Route a logged-in client's command to the appropriate handler.

        Args:
            sock (socket.socket)
            line (str)

        Returns:
            bool: True if client should disconnect.
        """
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
    """
       Remove client from tracking structures and close socket.

       Args:
           sock (socket.socket)
           sockets_list (list)
           clients (dict)
       """
    if sock in sockets_list:
        sockets_list.remove(sock)
    if sock in clients:
        del clients[sock]
    sock.close()


def accept_new_client(server_sock, sockets_list, clients):
    """
       Accept a new client and send the welcome message.

       Args:
           server_sock (socket.socket)
           sockets_list (list)
           clients (dict)
       """
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
    """
        Handle commands from logged-in clients.

        Args:
            current_sock (socket.socket)
            sockets_list (list)
            clients (dict)
        """
    line = recv_line(current_sock)
    if not line:
        disconnect_client(current_sock, sockets_list, clients)
        return

    should_quit = handle_command(current_sock, line)
    if should_quit:
        disconnect_client(current_sock, sockets_list, clients)


def handle_login_line(current_sock, client_state, users_dict):
    """
        Process login lines ("User: ..." then "Password: ...") until success.

        Args:
            current_sock (socket.socket)
            client_state (dict)
            users_dict (dict)

        Returns:
            bool: False if login should terminate client.
        """
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
    """
        Main server loop:
        - load users
        - open server socket
        - accept new clients
        - handle login and commands using select()
        """
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

