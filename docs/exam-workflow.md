# Socket exam workflow

The reference question describes a remote e-voting system with client-side encryption/signing, timestamp validation, homomorphic aggregation and searchable audit records. This document transcribes only the functional requirements; it excludes personal details from the photograph.

| Requirement | Generated implementation |
| --- | --- |
| Candidate selection and constituency | Voter client creates a canonical JSON ballot |
| SHA-512 ballot hash | Computed before AES encryption; recomputed by the server |
| AES-256-CBC confidentiality | Fresh 32-byte session key and IV for every ballot |
| RSA-4096 key protection | OAEP wraps the AES key under the election server's public key |
| ElGamal signature of ballot hash | Enrolled per-voter public key verifies the hash signature |
| Bind encrypted fields | Additional ElGamal envelope signature covers the encrypted tally vector and identity |
| Paillier-encrypted candidate choice | One encrypted 0/1 value per candidate enables meaningful candidate counts |
| Trusted timestamp | Separate local RSA-signing timestamp service, with pinned public key |
| Voting-period checks | Reject early, late, future, expired or incorrectly bound timestamp receipts |
| Aggregate without decrypting votes | Multiply Paillier ciphertexts per candidate |
| Encrypted constituency/time search | Authenticated auditor/admin lookup returns metadata only |
| Threshold final decryption | Two password-protected authority shares produce signed partial aggregate decryptions |
| Role-based access | Server-enforced voter, auditor and admin operation permissions |
| Outputs | Receipts, operation timings, search results, signed aggregate and final counts |

## Client/server sequence

1. Offline setup creates enrolled identities and separate server, TSA and authority bundles.
2. A voter builds and signs the encrypted envelope. The TSA signs its digest and current UTC time.
3. A length-prefixed request travels to the server inside a fresh RSA-wrapped AES-GCM envelope. This outer layer also protects login credentials; the inner ballot retains the required AES-CBC format.
4. The server authenticates the voter, checks the ticket and signatures, and decrypts the AES ballot temporarily to verify its SHA-512 hash and one-hot vote construction. It persists ciphertexts with a signed receipt and encrypted index metadata.
5. Auditors search only ballot metadata. Reopening the server preserves keys, accepted ballots and duplicate-voter protection.
6. After the deadline, an administrator exports a signed aggregate. Each authority independently approves its fingerprint and creates a signed partial decryption. The server combines two distinct valid partials and checks that counts sum to the accepted-ballot count.

## Interpretation and limits

Adding numeric candidate IDs, as the question informally suggests, cannot distinguish candidate counts. The implementation uses an encrypted one-hot vector instead. It checks that vector against the authenticated AES ballot using encrypted randomness witnesses. This is a local teaching check, not a zero-knowledge validity proof.

The TSA is simulated, and initial setup generates all bundles on one computer. True trust separation requires independent provisioning and distribution. Two-of-two decryption is an additive-exponent demonstration, not a production verifiable threshold Paillier implementation. Authorities approve signed aggregates; the protocol does not prove the server included all and only valid ballots.

The server necessarily sees plaintext while checking the plaintext hash. This design does not promise anonymity or secrecy against the server. Neither the custom transport nor the voting protocol is intended for deployment.

PKSE in the socket preset follows the manual's RSA public-key sample using a separate RSA/AES hybrid encrypted index. The existing file generator follows the Paillier exercise. Randomized ciphertexts are never compared directly for equality; authorized private-key scans perform the comparisons.
