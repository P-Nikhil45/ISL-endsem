# Encrypted socket voting demo

This generator creates a menu-driven client/server voting demonstration. It has no accounts or voter login, so it cannot enforce one vote per person.

## Generate and run

Use Python 3.10 or later. Create and activate a virtual environment, then install PyCryptodome:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install "pycryptodome>=3.20,<5"
```

The generator reuses fixed demonstration keys, so generation is quick and needs no setup step. Generated programs need PyCryptodome. Candidate IDs are comma-separated:

```powershell
python generate_socket_solution.py --output generated/voting_demo --title "Secure Voting Demo" --candidates 101,102,103 --encryption AES-128 --hashing SHA512 --verification ElGamal
cd generated/voting_demo
```

The output folder has only `server.py` and `client.py`. The generator embeds the fixed RSA transport key, Paillier tally key pair, and client signing key from `templates/socket/hardcoded_keys.json`, keeping each private key only in its role's source file. Keep each file with its intended role and do not share the server file with clients or the client file with the server operator.

Open two terminals in the generated folder. Start the server in one:

```powershell
python server.py
```

Then start the client in the other:

```powershell
python client.py
```

The client menu supports:

1. Cast a vote by entering a candidate ID and constituency ID.
2. Search ballot receipts using only a constituency ID.
3. Tally votes for a constituency.
4. Check the total accepted ballot count.
5. Exit.

The server creates `data/ballots.json` on first submission. It verifies each ballot's hash and signature, then saves its receipt, timestamp, a keyed HMAC-SHA256 constituency search token, and the Paillier-encrypted one-hot candidate vector. New records do not store the plaintext constituency ID. The client turns search and tally queries into the same token before sending them; the server matches that token against the stored index. Older records with plaintext constituency IDs are converted to tokens in memory when loaded and remain searchable. For a tally, the server multiplies ciphertexts for each candidate (Paillier addition) and returns the aggregate counts. Search returns receipt IDs, timestamps and hashes, not candidate selections. Stop the server with Ctrl+C.

## Privacy and limitations

Candidate choices stay Paillier-encrypted in ballot storage. The deterministic keyed index hides constituency text in the ballot file and search query, but reveals when records share a constituency and how often each token occurs. The index key is embedded in both role files for this educational demo, so a holder of either file can guess likely constituency IDs and calculate their tokens. The server sees the constituency when it decrypts a submitted ballot. Timestamps remain visible. The server holds the Paillier private key and can decrypt individual vote vectors; this demonstration does not implement threshold decryption. Every generated copy uses the same hardcoded keys, so anyone with the template or either role file can recover those keys and forge messages. Since there is no voter identity or login, duplicate voting by a person cannot be prevented. These fixed keys are for an educational demonstration only, not a production election system.
