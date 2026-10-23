# Encrypted socket voting demo

This separate generator creates an educational voting demo with account login and two-party Paillier decryption. The original `generate_socket_solution.py` remains available.

## Generate and run

Use Python 3.10 or later. Create and activate a virtual environment, then install PyCryptodome:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install "pycryptodome>=3.20,<5"
```

The generator reuses fixed demonstration keys, so generation is quick and needs no setup step. Generated programs need PyCryptodome. Candidate IDs are comma-separated:

```powershell
python generate_authenticated_socket_solution.py --output generated/voting_demo --title "Secure Voting Demo" --candidates 101,102,103 --encryption AES-128 --hashing SHA512 --verification ElGamal
cd generated/voting_demo
```

The output folder contains `server.py`, `client.py`, and `authority.py`. The server source has one Paillier exponent share, the authority source has the other share, and neither role contains the complete Paillier decryption exponent. Keep `authority.py` separate from the server operator. These are fixed educational keys, not production credentials.

Open two terminals in the generated folder. Start the server in one:

```powershell
python server.py
```

Then start the client in the other:

```powershell
python client.py
```

The client menu supports:

1. Register a voter account or log in, then cast one vote by entering a candidate ID and constituency ID.
2. Search ballot receipts using only a constituency ID.
3. Tally votes for a constituency.
4. Check the total accepted ballot count.
5. Exit.

The server stores salted PBKDF2 password verifiers in `data/voters.json`, issues one-hour in-memory sessions, and records used voter names separately from ballots to reject a second submission. It does not put a voter name in a ballot record. Ballots keep the Paillier-encrypted one-hot vote vector and a keyed constituency index. Start the server, then start the authority watcher in another terminal from the same project folder:

```powershell
python authority.py
```

The watcher automatically approves every valid server-signed aggregate request. The running server combines the authority's signed partial decryption with its own share, prints the candidate totals, and saves them to `data/final_tally.json` (with a fingerprint-specific copy). Search returns receipt IDs, timestamps and hashes, not candidate selections.

## Privacy and limitations

The server alone cannot decrypt stored vote ciphertexts because it has only one exponent share. In automatic mode the authority releases its share for every valid server-signed aggregate without human review, so anyone able to submit tally requests can trigger aggregate decryption. This is a teaching demonstration of two-party additive exponent sharing, not a production verifiable threshold Paillier scheme. Account registration is open self-registration, not proof of real-world eligibility. The username used to enforce one vote is stored separately from ballot contents, but server logs and timing can still allow correlation. The index leaks equality/frequency, and its key is in both role programs. Existing hardcoded keys, passwords, local storage, and transport are not production security.
