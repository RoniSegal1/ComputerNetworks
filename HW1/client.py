#!/usr/bin/python3
import socket
import sys

DEFAULT_HOST = "localhost"
DEFAULT_PORT = 1337


def print_usage_and_exit():
    print(f"Usage: {sys.argv[0]} [hostname [port]]", file=sys.stderr)
    sys.exit(1)


def parse_args():
    argc = len(sys.argv)
    host = DEFAULT_HOST
    port = DEFAULT_PORT

    if argc >= 2:
        host = sys.argv[1]
    if argc >= 3:
        try:
            port = int(sys.argv[2])
        except ValueError:
            print("Port must be an integer", file=sys.stderr)
            print_usage_and_exit()
    if argc > 3:
        print_usage_and_exit()

    return host, port


def recv_line(sock):
    data = b""
    while not data.endswith(b"\n"):
        chunk = sock.recv(1)
        if not chunk:
            return ""
        data += chunk
    return data.decode("utf-8", errors="replace").rstrip("\r\n")


def send_line(sock, text):
    msg = (text + "\n").encode("utf-8")
    sock.sendall(msg)


def do_login(sock):
    """מטפלת בלוגין עד הצלחה או ניתוק. מחזירה True אם הצליח, False אחרת."""
    while True:
        username = input("User: ")
        password = input("Password: ")

        send_line(sock, f"User: {username}")
        send_line(sock, f"Password: {password}")

        reply = recv_line(sock)
        if reply == "":
            print("Server closed connection during login.")
            return False

        print(reply)

        if reply.startswith("Hi "):
            return True
        # אחרת זה כנראה "Failed to login", חוזרים לסיבוב נוסף


def command_loop(sock):
    """לולאת הפקודות אחרי שהתחברנו בהצלחה."""
    while True:
        try:
            cmd = input()
        except EOFError:
            break

        if cmd == "":
            continue

        send_line(sock, cmd)

        if cmd == "quit":
            # לפי הפרוטוקול: השרת יסגור את החיבור, אין תשובה
            break

        reply = recv_line(sock)
        if reply == "":
            print("Server closed connection.")
            break
        print(reply)


def main():
    host, port = parse_args()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.connect((host, port))
        except OSError as e:
            print(f"Failed to connect to {host}:{port}: {e}", file=sys.stderr)
            sys.exit(1)

        # welcome מהשרת
        welcome = recv_line(sock)
        if welcome == "":
            print("Server closed connection.")
            return
        print(welcome)

        # לוגין
        if not do_login(sock):
            return

        # פקודות
        command_loop(sock)


if __name__ == "__main__":
    main()
