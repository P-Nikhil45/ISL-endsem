"""Approve an aggregate and produce the authority's Paillier decryption share."""
import argparse
import time
from common import *


def partial_decrypt(public, manifest):
    body = manifest["body"]
    pss.new(RSA.import_key(public["server_rsa"])).verify(
        SHA256.new(canonical(body)), bytes.fromhex(manifest["signature"]))
    if len(body["aggregate"]) != len(public["candidate_ids"]):
        raise ValueError("Invalid aggregate candidate count.")
    if type(body["count"]) is not int or body["count"] < 0:
        raise ValueError("Invalid aggregate ballot count.")
    values = [paillier_partial_decrypt(value, AUTHORITY_SHARE["lambda_share"], public["paillier"])
              for value in body["aggregate"]]
    partial_body = {"manifest_hash": hashlib.sha256(canonical(manifest)).hexdigest(),
                    "values": values}
    signature = pss.new(RSA.import_key(AUTHORITY_SIGNING_PRIVATE_PEM)).sign(
        SHA256.new(canonical(partial_body))).hex()
    return {"body": partial_body, "signature": signature}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--watch", action="store_true",
                        help="automatically approve signed aggregate requests in DATA")
    parser.add_argument("--aggregate", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    watch = args.watch or (args.aggregate is None and args.output is None)
    if watch:
        print("Automatic authority watcher running for", PUBLIC["title"])
        print("It approves every valid server-signed aggregate request. Ctrl+C stops it.")
        while True:
            for manifest_path in DATA.glob("pending_aggregate_*.json"):
                fingerprint = manifest_path.stem.removeprefix("pending_aggregate_")
                output = DATA / f"authority_partial_{fingerprint}.json"
                if output.exists():
                    continue
                try:
                    manifest = load(manifest_path)
                    actual = hashlib.sha256(canonical(manifest)).hexdigest()
                    if actual != fingerprint:
                        print("Skipped aggregate with mismatched fingerprint:", manifest_path.name)
                        continue
                    save(output, partial_decrypt(PUBLIC, manifest))
                    print("Automatically approved aggregate", fingerprint, "->", output)
                except (ValueError, KeyError, TypeError, OSError) as exc:
                    print("Could not process", manifest_path.name, ":", exc)
            time.sleep(1)
    else:
        if args.aggregate is None or args.output is None:
            parser.error("provide --watch, or both --aggregate and --output")
        if args.output.exists():
            raise ValueError("Output already exists. Choose a new partial file.")
        manifest = load(args.aggregate)
        print("Election:", PUBLIC["title"], "\nBallots:", manifest["body"]["count"])
        print("Aggregate fingerprint:", hashlib.sha256(canonical(manifest)).hexdigest())
        if input("Approve this aggregate? Type YES: ").strip() != "YES":
            print("Not approved.")
            return
        result = partial_decrypt(PUBLIC, manifest)
        save(args.output, result)
        print("Signed partial decryption saved to", args.output)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, EOFError, KeyboardInterrupt) as exc:
        print("Authority operation stopped:", exc)
