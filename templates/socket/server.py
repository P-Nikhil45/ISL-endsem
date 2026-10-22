"""Receive, verify, search and homomorphically tally encrypted ballots."""
from common import *

SERVER_STATE = {"accepted_count": 0}


def load_ballots():
    if not BALLOTS_PATH.exists():
        return []
    values = load(BALLOTS_PATH)
    if not isinstance(values, list):
        raise ValueError("Ballot storage is invalid.")
    return values


def verify_and_store(packet, public, server_key):
    if not isinstance(packet, dict) or packet.get("operation") != "submit":
        raise ValueError("Expected an encrypted ballot submission.")
    session_key = PKCS1_OAEP.new(server_key, hashAlgo=SHA256).decrypt(bytes.fromhex(packet["wrapped_key"]))
    if len(session_key) != symmetric_key_bytes():
        raise ValueError("Ballot encryption key has an invalid length.")
    signed_record = json.loads(cbc_decrypt(packet["encrypted"], session_key))
    ballot = signed_record["ballot"]
    if not isinstance(ballot, dict):
        raise ValueError("Ballot format is invalid.")
    constituency = ballot.get("constituency_id")
    ballot_id = ballot.get("ballot_id")
    timestamp = ballot.get("timestamp")
    encrypted_votes = ballot.get("encrypted_votes")
    if not isinstance(constituency, str) or not constituency.strip() or len(constituency) > 100:
        raise ValueError("Constituency ID is invalid.")
    if not isinstance(ballot_id, str) or len(ballot_id) != 32:
        raise ValueError("Ballot receipt is invalid.")
    datetime.fromisoformat(timestamp)
    if not isinstance(encrypted_votes, list) or len(encrypted_votes) != len(public["candidate_ids"]):
        raise ValueError("Encrypted vote vector does not match the candidate list.")
    n = int(public["paillier"]["n"])
    if any(not isinstance(value, str) or not 0 < int(value) < n * n for value in encrypted_votes):
        raise ValueError("Invalid encrypted vote value.")
    actual_hash = hash_bytes(canonical(ballot))
    if not hmac.compare_digest(actual_hash, signed_record["hash"]):
        raise ValueError("Ballot hash verification failed.")
    if not user_verify(actual_hash, signed_record["signature"], public["client_signature"]):
        raise ValueError("Ballot signature verification failed.")
    ballots = load_ballots()
    if any(item.get("ballot_id") == ballot_id for item in ballots):
        raise ValueError("Duplicate ballot receipt.")
    received_at = stamp()
    record = {**ballot, "hash": actual_hash, "received_at": received_at}
    ballots.append(record)
    save(BALLOTS_PATH, ballots)
    SERVER_STATE["accepted_count"] = len(ballots)
    print("Verified ballot", ballot_id, "for constituency", constituency, "at", received_at)
    return {"verified": True, "ballot_id": ballot_id, "received_at": received_at, "hash": actual_hash}


def search_ballots(query):
    constituency = query.get("constituency_id", "").strip()
    if not constituency:
        raise ValueError("Enter a constituency ID to search.")
    matches = []
    for ballot in load_ballots():
        if ballot["constituency_id"] != constituency:
            continue
        matches.append({"ballot_id": ballot["ballot_id"], "timestamp": ballot["received_at"],
                        "hash": ballot["hash"]})
    return {"count": len(matches), "ballots": matches}


def tally_votes(query, public, paillier_private):
    constituency = query.get("constituency_id", "").strip()
    if not constituency:
        raise ValueError("Enter a constituency ID to tally.")
    ballots = [ballot for ballot in load_ballots() if ballot["constituency_id"] == constituency]
    candidates = public["candidate_ids"]
    totals = []
    for index, candidate in enumerate(candidates):
        encrypted_total = paillier_add([ballot["encrypted_votes"][index] for ballot in ballots], public["paillier"])
        totals.append((candidate, paillier_decrypt(encrypted_total, paillier_private)))
    return {"constituency_id": constituency, "total": len(ballots),
            "counts": {candidate: count for candidate, count in totals}}


def handle_connection(connection, public, server_key, paillier_private):
    connection.settimeout(30)
    outer = receive(connection)
    transport_key = PKCS1_OAEP.new(server_key, hashAlgo=SHA256).decrypt(bytes.fromhex(outer["wrapped_key"]))
    payload = json.loads(unseal(transport_key, outer["payload"]))
    try:
        operation = payload.get("operation")
        if operation == "submit":
            result = verify_and_store(payload, public, server_key)
        elif operation == "search":
            result = search_ballots(payload)
        elif operation == "tally":
            result = tally_votes(payload, public, paillier_private)
        elif operation == "status":
            result = {"accepted_count": len(load_ballots())}
        else:
            raise ValueError("Choose a supported client menu action.")
        response = {"ok": True, "result": result}
    except (ValueError, KeyError, TypeError, OSError, OverflowError) as exc:
        response = {"ok": False, "error": str(exc) if isinstance(exc, ValueError)
                    else "Invalid ballot or storage error."}
        print("Rejected request:", response["error"])
    send(connection, seal(transport_key, canonical(response)))


def main():
    public = PUBLIC
    server_key = RSA.import_key(SERVER_RSA_PRIVATE_PEM)
    paillier_private = PAILLIER_PRIVATE_KEY
    SERVER_STATE["accepted_count"] = len(load_ballots())
    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((CONFIG["host"], CONFIG["port"]))
        listener.listen(16)
        print(public["title"], "listening on", listener.getsockname())
        print("\nServer menu / supported operations")
        print("1. Receive and verify signed ballots")
        print("2. Search stored receipts by constituency ID")
        print("3. Homomorphically tally encrypted votes by constituency")
        print("4. Return ballot count")
        print("The server keeps candidate selections encrypted; constituency IDs remain searchable.")
        print("Press Ctrl+C to stop the server.")
        while True:
            connection, _ = listener.accept()
            with connection:
                try:
                    handle_connection(connection, public, server_key, paillier_private)
                except (ValueError, KeyError, TypeError, OSError, OverflowError) as exc:
                    print("Rejected connection:", type(exc).__name__)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyboardInterrupt) as exc:
        print("Server stopped:", exc)
