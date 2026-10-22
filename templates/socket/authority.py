"""Each authority independently approves a signed closed-election aggregate."""
import argparse
from getpass import getpass
from common import *


def partial_decrypt(public, manifest, protected_share, password):
    rsa_verify(RSA.import_key(public["server_rsa"]), manifest["body"], manifest["signature"])
    body = manifest["body"]
    if body["election_id"] != public["election_id"]:
        raise ValueError("Aggregate belongs to another election.")
    if now() < parse_time(public["closes_at"]) or parse_time(body["closed_at"]) < parse_time(public["closes_at"]):
        raise ValueError("The election has not ended.")
    if len(body["aggregate"]) != len(public["candidates"]) or type(body["count"]) is not int or body["count"] < 0:
        raise ValueError("Invalid aggregate manifest.")
    share = unlock(protected_share, password)
    if share["election_id"] != public["election_id"]:
        raise ValueError("Authority share belongs to another election.")
    n = int(public["paillier_n"])
    partials = []
    for value in body["aggregate"]:
        ciphertext = int(value)
        validate_ciphertext(ciphertext, n)
        partials.append(str(pow(ciphertext, int(share["share"]), n * n)))
    result = {"authority": share["number"], "manifest_hash": digest(manifest), "values": partials}
    return {"body": result, "signature": rsa_sign(RSA.import_key(share["signing_key"]), result)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--number", type=int, choices=[1, 2], required=True)
    parser.add_argument("--aggregate", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError("Output already exists. Choose a new partial file.")
    public = load(DATA / "public.json")
    manifest = load(args.aggregate)
    print("Election:", public["title"], "\nBallots:", manifest["body"]["count"])
    print("Aggregate fingerprint:", digest(manifest))
    if input("Approve this aggregate? Type YES: ").strip() != "YES":
        print("Not approved.")
        return
    result = partial_decrypt(public, manifest, load(DATA / "authorities" / f"{args.number}.json"),
                             getpass(f"Authority {args.number} password: "))
    save(args.output, result)
    print("Signed partial decryption saved to", args.output)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, EOFError, KeyboardInterrupt) as exc:
        print("Authority operation stopped:", exc)
