"""Receive, verify, search and homomorphically tally encrypted ballots."""
import argparse
from common import *

SERVER_STATE = {"accepted_count": 0, "sessions": {}}
VOTERS_PATH = DATA / "voters.json"
VOTED_PATH = DATA / "voted_voters.json"
AGGREGATE_PATH = DATA / "pending_aggregate.json"


def load_voters():
    return load(VOTERS_PATH) if VOTERS_PATH.exists() else {}


def register_voter(payload):
    username = payload.get("username", "")
    password = payload.get("password", "")
    if not isinstance(username, str):
        raise ValueError("Enter a valid username.")
    username = username.strip().casefold()
    if not 3 <= len(username) <= 32 or not username.replace("_", "").isalnum():
        raise ValueError("Username must be 3-32 letters, digits or underscores.")
    if not isinstance(password, str) or len(password) < 8:
        raise ValueError("Password must contain at least 8 characters.")
    voters = load_voters()
    if username in voters:
        raise ValueError("That voter account already exists.")
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
    voters[username] = {"salt": salt.hex(), "password_hash": digest.hex()}
    save(VOTERS_PATH, voters)
    return {"registered": True}


def login_voter(payload):
    username = payload.get("username", "")
    password = payload.get("password", "")
    if not isinstance(username, str):
        raise ValueError("Invalid username or password.")
    username = username.strip().casefold()
    record = load_voters().get(username)
    if not record or not isinstance(password, str):
        raise ValueError("Invalid username or password.")
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                                 bytes.fromhex(record["salt"]), 200_000).hex()
    if not hmac.compare_digest(digest, record["password_hash"]):
        raise ValueError("Invalid username or password.")
    token = secrets.token_urlsafe(32)
    SERVER_STATE["sessions"][token] = {"username": username, "expires": time.time() + 3600}
    return {"session_token": token, "expires_in_seconds": 3600}


def require_voter(payload):
    token = payload.get("session_token")
    session = SERVER_STATE["sessions"].get(token)
    if not session or session["expires"] <= time.time():
        SERVER_STATE["sessions"].pop(token, None)
        raise ValueError("Please log in again.")
    return session["username"]


def load_ballots():
    if not BALLOTS_PATH.exists():
        return []
    values = load(BALLOTS_PATH)
    if not isinstance(values, list):
        raise ValueError("Ballot storage is invalid.")
    for ballot in values:
        if "constituency_index" not in ballot and isinstance(ballot.get("constituency_id"), str):
            ballot["constituency_index"] = constituency_index(ballot.pop("constituency_id"))
    return values


def verify_and_store(packet, public, server_key, username):
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
    voted = load(VOTED_PATH) if VOTED_PATH.exists() else []
    if username in voted:
        raise ValueError("This voter account has already cast a ballot.")
    ballots = load_ballots()
    if any(item.get("ballot_id") == ballot_id for item in ballots):
        raise ValueError("Duplicate ballot receipt.")
    received_at = stamp()
    record = {key: value for key, value in ballot.items() if key != "constituency_id"}
    record.update({"constituency_index": constituency_index(constituency),
                   "hash": actual_hash, "received_at": received_at})
    ballots.append(record)
    save(BALLOTS_PATH, ballots)
    voted.append(username)
    save(VOTED_PATH, voted)
    SERVER_STATE["accepted_count"] = len(ballots)
    print("Verified ballot", ballot_id, "at", received_at)
    return {"verified": True, "ballot_id": ballot_id, "received_at": received_at, "hash": actual_hash}


def search_ballots(query, server_key=None):
    token = query.get("constituency_token")
    if token is None and query.get("constituency_id", "").strip():
        # Compatibility for local callers and older clients; network clients send tokens.
        token = constituency_index(query["constituency_id"])
    if not isinstance(token, str) or len(token) != 64:
        raise ValueError("Enter a constituency ID to search.")
    matches = []
    for ballot in load_ballots():
        if not hmac.compare_digest(ballot.get("constituency_index", ""), token):
            continue
        matches.append({"ballot_id": ballot["ballot_id"], "timestamp": ballot["received_at"],
                        "hash": ballot["hash"]})
    return {"count": len(matches), "ballots": matches}


def prepare_tally(query, public, server_key):
    token = query.get("constituency_token")
    if token is None and query.get("constituency_id", "").strip():
        token = constituency_index(query["constituency_id"])
    if not isinstance(token, str) or len(token) != 64:
        raise ValueError("Enter a constituency ID to tally.")
    ballots = [ballot for ballot in load_ballots()
               if hmac.compare_digest(ballot.get("constituency_index", ""), token)]
    aggregate = [paillier_add([ballot["encrypted_votes"][index] for ballot in ballots], public["paillier"])
                 for index, _ in enumerate(public["candidate_ids"])]
    body = {"count": len(ballots), "aggregate": aggregate, "created_at": stamp()}
    signature = pss.new(server_key).sign(SHA256.new(canonical(body))).hex()
    manifest = {"body": body, "signature": signature}
    fingerprint = hashlib.sha256(canonical(manifest)).hexdigest()
    manifest_path = DATA / f"pending_aggregate_{fingerprint}.json"
    save(manifest_path, manifest)
    return {"aggregate_ready": True, "ballots": len(ballots),
            "manifest": str(manifest_path), "fingerprint": fingerprint}


def finalize_tally(manifest, partial):
    body = manifest["body"]
    pss.new(RSA.import_key(PUBLIC["server_rsa"])).verify(
        SHA256.new(canonical(body)), bytes.fromhex(manifest["signature"]))
    partial_body = partial["body"]
    manifest_hash = hashlib.sha256(canonical(manifest)).hexdigest()
    pss.new(RSA.import_key(PUBLIC["authority_rsa"])).verify(
        SHA256.new(canonical(partial_body)), bytes.fromhex(partial["signature"]))
    if partial_body["manifest_hash"] != manifest_hash:
        raise ValueError("Authority partial belongs to a different aggregate.")
    if len(body["aggregate"]) != len(PUBLIC["candidate_ids"]) or len(partial_body["values"]) != len(body["aggregate"]):
        raise ValueError("Aggregate or authority partial has the wrong candidate count.")
    counts = {}
    for index, candidate in enumerate(PUBLIC["candidate_ids"]):
        encrypted_total = body["aggregate"][index]
        server_partial = paillier_partial_decrypt(
            encrypted_total, PAILLIER_SERVER_SHARE["lambda_share"], PUBLIC["paillier"])
        counts[candidate] = paillier_combine_partials(
            encrypted_total, server_partial, partial_body["values"][index],
            PAILLIER_SERVER_SHARE["mu"], PUBLIC["paillier"])
    if sum(counts.values()) != body["count"]:
        raise ValueError("Candidate totals do not match the ballot count.")
    return {"total": body["count"], "counts": counts}


def process_ready_tallies():
    for manifest_path in DATA.glob("pending_aggregate_*.json"):
        fingerprint = manifest_path.stem.removeprefix("pending_aggregate_")
        partial_path = DATA / f"authority_partial_{fingerprint}.json"
        output_path = DATA / f"final_tally_{fingerprint}.json"
        if not partial_path.exists() or output_path.exists():
            continue
        try:
            result = finalize_tally(load(manifest_path), load(partial_path))
            save(output_path, result)
            save(DATA / "final_tally.json", result)
            print("Automatically finalized aggregate", fingerprint)
            print("Verified votes:", result["total"])
            for candidate, count in result["counts"].items():
                print(f"Candidate {candidate}: {count}")
        except (ValueError, KeyError, TypeError, OSError, OverflowError) as exc:
            print("Could not finalize aggregate", fingerprint, ":", exc)


def handle_connection(connection, public, server_key):
    connection.settimeout(30)
    outer = receive(connection)
    transport_key = PKCS1_OAEP.new(server_key, hashAlgo=SHA256).decrypt(bytes.fromhex(outer["wrapped_key"]))
    payload = json.loads(unseal(transport_key, outer["payload"]))
    try:
        operation = payload.get("operation")
        if operation == "register":
            result = register_voter(payload)
        elif operation == "login":
            result = login_voter(payload)
        elif operation == "submit":
            username = require_voter(payload)
            result = verify_and_store(payload, public, server_key, username)
        elif operation == "search":
            require_voter(payload)
            result = search_ballots(payload, server_key)
        elif operation == "tally":
            require_voter(payload)
            result = prepare_tally(payload, public, server_key)
        elif operation == "status":
            require_voter(payload)
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
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--finalize", nargs=2, metavar=("MANIFEST", "AUTHORITY_PARTIAL"))
    args = parser.parse_args()
    public = PUBLIC
    server_key = RSA.import_key(SERVER_RSA_PRIVATE_PEM)
    if args.finalize:
        manifest = load(args.finalize[0])
        partial = load(args.finalize[1])
        result = finalize_tally(manifest, partial)
        save(DATA / "final_tally.json", result)
        print("Verified votes:", result["total"])
        for candidate, count in result["counts"].items():
            print(f"Candidate {candidate}: {count}")
        return
    SERVER_STATE["accepted_count"] = len(load_ballots())
    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((CONFIG["host"], CONFIG["port"]))
        listener.listen(16)
        listener.settimeout(1)
        print(public["title"], "listening on", listener.getsockname())
        print("\nServer menu / supported operations")
        print("1. Receive and verify signed ballots")
        print("2. Search stored receipts by constituency ID")
        print("3. Homomorphically tally encrypted votes by constituency")
        print("4. Return ballot count")
        print("The server keeps candidate selections encrypted; constituency IDs remain searchable.")
        print("Press Ctrl+C to stop the server.")
        while True:
            process_ready_tallies()
            try:
                connection, _ = listener.accept()
            except socket.timeout:
                continue
            with connection:
                try:
                    handle_connection(connection, public, server_key)
                except (ValueError, KeyError, TypeError, OSError, OverflowError) as exc:
                    print("Rejected connection:", type(exc).__name__)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyboardInterrupt) as exc:
        print("Server stopped:", exc)
