"""Cast votes and request ballot searches or encrypted tallies."""
from getpass import getpass
from common import *


def prepare_vote(candidate_id, constituency_id, public, signing_key):
    candidate_ids = public["candidate_ids"]
    if candidate_id not in candidate_ids:
        raise ValueError("Select a candidate ID shown in the menu.")
    constituency_id = constituency_id.strip()
    if not constituency_id or len(constituency_id) > 100:
        raise ValueError("Enter a constituency ID from 1 to 100 characters.")
    encrypted_votes = [paillier_encrypt(int(candidate == candidate_id), public["paillier"])
                       for candidate in candidate_ids]
    ballot = {"ballot_id": secrets.token_hex(16),
              "constituency_id": constituency_id,
              "timestamp": stamp(),
              "encrypted_votes": encrypted_votes}
    digest = hash_bytes(canonical(ballot))
    signed_record = {"ballot": ballot, "hash": digest,
                     "signature": user_sign(digest, signing_key)}
    key = new_symmetric_key()
    encrypted = cbc_encrypt(canonical(signed_record), key)
    wrapped_key = PKCS1_OAEP.new(RSA.import_key(public["server_rsa"]), hashAlgo=SHA256).encrypt(key).hex()
    return {"encrypted": encrypted, "wrapped_key": wrapped_key,
            "hash": digest, "signature": signed_record["signature"]}


def authenticate(config, public):
    while True:
        print("\nAccount menu")
        print("1. Register voter account")
        print("2. Log in")
        action = input("Choose an option: ").strip()
        if action not in {"1", "2"}:
            print("Choose 1 or 2.")
            continue
        username = input("Username: ").strip()
        password = getpass("Password: ")
        try:
            result = request(config, public,
                             {"operation": "register" if action == "1" else "login",
                              "username": username, "password": password})
            if action == "1":
                print("Account registered. Log in to continue.")
            else:
                print("Logged in as", username)
                return result["session_token"]
        except (ValueError, KeyError, TypeError, OSError) as exc:
            print("Account request failed:", exc)


def main():
    config, public = CONFIG, PUBLIC
    signing_key = CLIENT_SIGNING_KEY
    session_token = authenticate(config, public)
    print(public["title"])
    print("Crypto:", public["symmetric"], "+", public["hash"], "+", public["signature"], "+ Paillier tally")
    while True:
        print("\nClient menu")
        print("1. Cast a vote")
        print("2. Search ballots by constituency ID")
        print("3. Tally votes for a constituency")
        print("4. Check server status")
        print("5. Exit")
        choice = input("Choose an option: ").strip()
        try:
            if choice == "1":
                print("Candidate IDs:", ", ".join(public["candidate_ids"]))
                candidate_id = input("Candidate ID: ").strip()
                constituency_id = input("Constituency ID: ").strip()
                packet = prepare_vote(candidate_id, constituency_id, public, signing_key)
                print("Encrypted ballot text (hex):", packet["encrypted"]["ciphertext"][:120] + "...")
                print("Ballot hash:", packet["hash"])
                result = request(config, public,
                                 {"operation": "submit", "session_token": session_token, **packet})
                print("Server verification:", "PASSED" if result["verified"] else "FAILED")
                print("Ballot receipt:", result["ballot_id"])
                print("Received at:", result["received_at"])
            elif choice == "2":
                constituency_id = input("Constituency ID: ").strip()
                result = request(config, public,
                                 {"operation": "search",
                                  "session_token": session_token,
                                  "constituency_token": constituency_index(constituency_id)})
                print("Matching ballots:", result["count"])
                for item in result["ballots"]:
                    print(item["ballot_id"], item["timestamp"], "hash:", item["hash"])
            elif choice == "3":
                constituency_id = input("Constituency ID to tally: ").strip()
                result = request(config, public,
                                 {"operation": "tally",
                                  "session_token": session_token,
                                  "constituency_token": constituency_index(constituency_id)})
                print("Encrypted aggregate prepared for", result["ballots"], "ballots.")
                print("Aggregate file:", result["manifest"])
                print("Fingerprint:", result["fingerprint"])
                print("The background authority will process it automatically.")
                print("The server saves the completed tally to data/final_tally.json.")
            elif choice == "4":
                result = request(config, public,
                                 {"operation": "status", "session_token": session_token})
                print("Accepted ballots:", result["accepted_count"])
            elif choice == "5":
                print("Client closed.")
                break
            else:
                print("Choose 1, 2, 3, 4, or 5.")
        except (ValueError, KeyError, TypeError, OSError) as exc:
            print("Request failed:", exc)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, EOFError, KeyboardInterrupt) as exc:
        print("Client stopped:", exc)
