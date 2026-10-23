"""Separate local timestamp authority; only this service reads its private key."""
from common import *


def issue_ticket(request, key):
    value = request["digest"]
    expected_length = len(hash_bytes(b"timestamp digest length check"))
    if len(value) != expected_length or any(c not in "0123456789abcdef" for c in value):
        raise ValueError(f"Expected a {HASH_ALGORITHM} digest.")
    body = {"digest": value, "issued_at": stamp()}
    return {"body": body, "signature": rsa_sign(key, body)}


def main():
    config = load(BASE / "config.json")
    key = RSA.import_key((DATA / "tsa" / "private.pem").read_bytes())
    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((config["tsa_host"], config["tsa_port"]))
        listener.listen(8)
        print("Timestamp authority listening on", listener.getsockname())
        while True:
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(15)
                try:
                    send(connection, issue_ticket(receive(connection), key))
                except (ValueError, KeyError, TypeError, OSError) as exc:
                    print("Timestamp request rejected:", type(exc).__name__)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nTimestamp service stopped.")
