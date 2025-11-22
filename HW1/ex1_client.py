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
    """
    Print an error message and terminate the program.

    Args:
           err_msg (str): The error message to display.
    """
    print(err_msg)
    sys.exit(1)


def print_error_and_close(con_socket, err_msg):
    """
    Close the socket, print an error message, and exit.

    Args:
        con_socket (socket.socket): The socket to close.
        err_msg (str): The error message to display.
    """
    con_socket.close()
    print_error_and_exit(err_msg)


def validate_hostname(hostname):
    """
    Validate a hostname or IP address format.

    Args:
        hostname (str): The hostname to validate.

    Returns:
        bool: True if valid, False otherwise.
    """
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
    """
    Validate a port number.

    Args:
        port (str): The port number in string format.

    Returns:
        bool: True if valid, False otherwise.
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
    Parse command-line arguments for hostname and port.

    Returns:
        (str, int): Tuple of (host, port).
    """
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
    """
    Receive a full line from the server socket, ending with '\n'.

    Args:
        connectionSock (socket.socket): The connection socket.

    Returns:
        str: The received line, or empty string if connection closed.
    """
    data = b""
    while not data.endswith(b"\n"):
        chunk = connectionSock.recv(1)
        if not chunk:
            return ""
        data += chunk
    return data.decode("utf-8", errors="replace").rstrip("\r\n")


def send_line(connectionSock, text):
    """
    Send a line to the server with a trailing newline.

    Args:
        connectionSock (socket.socket): The connection socket.
        text (str): The text to send.
    """
    msg = (text + "\n").encode("utf-8")
    connectionSock.sendall(msg)


def validate_login_input(input, prefix):
    """
    Check whether the login input starts with the expected prefix.

    Args:
        input (str): The user-entered line.
        prefix (str): Expected prefix.

    Returns:
        bool: True if valid, False otherwise.
    """
    return input.startswith(prefix)


def do_login(connectionSock):
    """
    Handle the login flow: validate user and password input.
    if valid send to the server until succeed login

    Args:
        connectionSock (socket.socket): Connection to server.
    """
    while True:
        username = input()

        if not validate_login_input(username, USER_PREFIX):
            print_error_and_close(connectionSock, "Unexpected login format")

        password = input()

        if not validate_login_input(password, PASSWORD_PREFIX):
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
    """
    Validate parentheses command contains only '(' and ')'.

    Args:
        command (str): The command starting with "parentheses: ".

    Returns:
        bool: True if valid, False otherwise.
    """
    parentheses = command[len(PARENTHESES_PREFIX):].strip()

    for ch in parentheses:
        if ch != '(' and ch != ')':
            return False

    return True


def validate_lcm(command):
    """
    Validate LCM command format: exactly two integers.

    Args:
        command (str): The command starting with "lcm: ".

    Returns:
        bool: True if valid, False otherwise.
    """
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
    """
    Validate caesar command format: plaintext + shift integer.

    Args:
        command (str): The command starting with "caesar: ".

    Returns:
        bool: True if valid, False otherwise.
    """
    rest = command[len(CAESAR_PREFIX):].strip()
    if " " not in rest:
        return False
    plaintext, shift_str = rest.rsplit(" ", 1)
    if plaintext.strip() == "":
        return False
    try:
        int(shift_str)
    except ValueError:
        return False

    return True


def validate_command(connectionSock, command):
    """
        Validate a user command before sending it to server.
        If command is not valid - invalid command or valid command with invalid input exits program

        Args:
            connectionSock (socket.socket): The socket.
            command (str): The user-entered command.
        """
    res = True

    if command.startswith(PARENTHESES_PREFIX):
        res = validate_parentheses(command)
    elif command.startswith(LCM_PREFIX):
        res = validate_lcm(command)
    elif command.startswith(CAESAR_PREFIX):
        res = validate_caesar(command)
    elif command != "quit":
        res = False

    if not res:
        print_error_and_close(connectionSock, "Invalid command")


def command_request(connectionSock):
    """
    Handle post-login command loop:
    read user input, validate, send, receive reply.

    Args:
        connectionSock (socket.socket): The connection socket.
    """
    while True:
        try:
            command = input()
        except EOFError:
            print_error_and_close(connectionSock, "Invalid error")

        validate_command(connectionSock, command)
        send_line(connectionSock, command)

        if command == "quit":
            connectionSock.close()
            sys.exit(0)

        reply = recv_line(connectionSock)

        if reply == "":
            print_error_and_close(connectionSock, "Server closed connection during command request.")

        print(reply)


def main():
    """
    Main entry point:
    - parse args
    - connect to server
    - login
    - start command loop
    """
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

