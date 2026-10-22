import contextlib
import copy
import importlib.util
import io
import json
import socket
import struct
import sys
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import generate_solution
import generate_socket_solution


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    sys.modules[name] = result
    spec.loader.exec_module(result)
    return result


class FileGeneratorTests(unittest.TestCase):
    def test_options_and_runtime_search(self):
        defaults = {k: values[0] for k, values in generate_solution.OPTIONS.items()}
        for category, choices in generate_solution.OPTIONS.items():
            for choice in choices:
                source, _ = generate_solution.build_source("Syntax", dict(defaults, **{category: choice}))
                compile(source, "solution.py", "exec")
        for scheme in ("SSE", "PKSE"):
            with self.subTest(search=scheme), tempfile.TemporaryDirectory(dir=ROOT, prefix=".test-") as directory:
                path = generate_solution.create_solution("Test", dict(defaults, search=scheme, signature="ElGamal"), Path(directory) / "lab")
                lab = module("file_lab", path)
                key, lab.SEARCH_KEY = lab.initialize()
                with contextlib.redirect_stdout(io.StringIO()):
                    lab.student("report.txt", "fever fever café", 7, 3, key, None)
                index = lab.create_index({"report.txt": "fever fever café"}, key)
                self.assertEqual(lab.search(index, " FEVER ", key), [("report.txt", "fever fever café")])
                self.assertEqual(lab.search(index, "missing", key), [])
                lab = module("file_lab", path)
                key, lab.SEARCH_KEY = lab.initialize()
                self.assertEqual(len(lab.search(json.loads((path.parent / "index.json").read_text()), "CAFÉ", key)), 1)
                with contextlib.redirect_stdout(io.StringIO()) as output:
                    lab.show_search_result("report.txt", "fever fever café")
                self.assertNotIn("Verification time", output.getvalue())
                self.assertIn("Homomorphic time (at creation)", output.getvalue())
                (path.parent / "hashes" / "report.txt").write_text("tampered")
                with self.assertRaises(ValueError):
                    lab.search(index, "fever", key)
                with self.assertRaises(FileExistsError):
                    generate_solution.create_solution("Test", defaults, path.parent)


class SocketGeneratorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(dir=ROOT, prefix=".test-")
        cls.folder = generate_socket_solution.create_solution("Test election", Path(cls.temporary.name) / "lab", search="PKSE")
        cls.common = module("common", cls.folder / "common.py")
        cls.setup = module("socket_setup", cls.folder / "setup.py")
        cls.server = module("socket_server", cls.folder / "server.py")
        cls.client = module("socket_client", cls.folder / "client.py")
        cls.tsa = module("socket_tsa", cls.folder / "timestamp_server.py")
        cls.authority = module("socket_authority", cls.folder / "authority.py")
        cls.config = cls.common.load(cls.folder / "config.json")
        cls.accounts = {"admin": {"role": "admin", "password": "admin-password"},
                        "auditor": {"role": "auditor", "password": "auditor-password"},
                        **{f"voter{i}": {"role": "voter", "password": f"voter{i}-password"} for i in range(1, 4)}}
        # Tests use small keys for speed; the CLI always uses 4096/2048/2048.
        cls.public = cls.setup.create_setup(cls.config, cls.accounts, ["trustee-one", "trustee-two"],
                                            rsa_bits=1024, paillier_bits=512, signature_bits=256)
        cls.initial = cls.common.load(cls.common.DATA / "server" / "state.json")
        cls.tsa_key = cls.common.RSA.import_key((cls.common.DATA / "tsa" / "private.pem").read_bytes())

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def setUp(self):
        self.common.save(self.common.DATA / "server" / "state.json", copy.deepcopy(self.initial))
        self.election = self.server.Election()

    def payload(self, user, operation, **kwargs):
        return {"username": user, "password": self.accounts[user]["password"], "operation": operation, **kwargs}

    def ballot(self, user="voter1", candidate=0, constituency="North"):
        signing = self.common.unlock(self.common.load(self.common.DATA / "voters" / f"{user}.json"), self.accounts[user]["password"])
        packet, _ = self.client.prepare_ballot(self.public, user, signing, candidate, constituency)
        ticket = self.tsa.issue_ticket({"digest": self.common.digest(packet)}, self.tsa_key)
        return {"packet": packet, "timestamp": ticket}

    def exchange(self, handler, invoke):
        errors = []
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(10)
            port = listener.getsockname()[1]

            def serve():
                try:
                    connection, _ = listener.accept()
                    with connection:
                        handler(connection)
                except Exception as exc:
                    errors.append(exc)

            thread = threading.Thread(target=serve)
            thread.start()
            try:
                result = invoke(port)
            finally:
                thread.join(12)
            self.assertFalse(thread.is_alive())
            self.assertEqual(errors, [])
            return result

    def test_real_socket_submission_and_tsa(self):
        ballot = self.ballot()
        ticket = self.exchange(
            lambda conn: self.common.send(conn, self.tsa.issue_ticket(self.common.receive(conn), self.tsa_key)),
            lambda port: self.common.get_timestamp(dict(self.config, tsa_port=port), self.public, ballot["packet"]))
        ballot["timestamp"] = ticket
        result = self.exchange(lambda conn: self.server.handle_connection(conn, self.election),
            lambda port: self.common.request(dict(self.config, port=port), self.public,
                self.payload("voter1", "cast", ballot=ballot)))
        self.assertIn("verified_at", result["receipt"])
        self.common.rsa_verify(self.election.key.publickey(), result["receipt"], result["signature"])
        reloaded = self.server.Election()
        self.assertEqual(len(reloaded.state["ballots"]), 1)
        with self.assertRaises(ValueError):
            reloaded.dispatch(self.payload("voter1", "cast", ballot=ballot))

    def test_roles_tampering_and_timestamps(self):
        for invalid in ([], {}, {"username": "voter1", "password": [], "operation": "status"}):
            with self.assertRaises(ValueError):
                self.election.dispatch(invalid)
        with self.assertRaises(ValueError):
            self.election.dispatch(dict(self.payload("admin", "status"), password="wrong"))
        with self.assertRaises(ValueError):
            self.election.dispatch(self.payload("voter1", "search", constituency="North"))
        with self.assertRaises(ValueError):
            self.election.dispatch(self.payload("auditor", "close"))
        with self.assertRaises(ValueError):
            self.election.dispatch(self.payload("admin", "close"))
        ballot = self.ballot()
        bad = copy.deepcopy(ballot)
        bad["packet"]["hash"] = "0" * 128
        with self.assertRaises(ValueError):
            self.election.dispatch(self.payload("voter1", "cast", ballot=bad))
        bad = copy.deepcopy(ballot)
        bad["timestamp"]["body"]["issued_at"] = "2099-01-01T00:00:00+00:00"
        with self.assertRaises(ValueError):
            self.election.dispatch(self.payload("voter1", "cast", ballot=bad))
        bad["timestamp"]["signature"] = self.common.rsa_sign(self.tsa_key, bad["timestamp"]["body"])
        with self.assertRaises(ValueError):
            self.election.dispatch(self.payload("voter1", "cast", ballot=bad))
        self.assertEqual(self.election.state["ballots"], [])

    def test_search_and_encrypted_storage(self):
        self.election.dispatch(self.payload("voter1", "cast", ballot=self.ballot()))
        results = self.election.dispatch(self.payload("auditor", "search", constituency="NORTH"))
        self.assertEqual(len(results), 1)
        self.assertEqual(set(results[0]), {"ballot_id", "constituency", "submitted_at"})
        self.assertEqual(self.election.search("South"), [])
        self.assertEqual(len(self.election.search("", self.public["opens_at"], self.public["closes_at"])), 1)
        # Exercise the SSE index path as well as the PKSE preset.
        self.election.search_rsa = None
        entry = self.election.make_index_entry("id", "North", results[0]["submitted_at"])
        self.assertEqual(self.election.read_index_entry(entry)["constituency"], "north")
        stored = self.common.canonical(self.election.state).decode()
        self.assertNotIn('"candidate":', stored)
        self.assertNotIn('"randomizers":', stored)
        self.assertNotIn('"constituency":', stored)
        self.election.state["ballots"][0]["ballot"]["packet"]["hash"] = "0" * 128
        with self.assertRaises(ValueError):
            self.election.verify_saved(self.election.state["ballots"][0])

    def test_signed_but_inconsistent_vote_is_rejected(self):
        ballot = self.ballot()
        n = int(self.public["paillier_n"])
        ballot["packet"]["votes"][0] = str(self.common.paillier_encrypt(9, n)[0])
        signing = self.common.unlock(self.common.load(self.common.DATA / "voters" / "voter1.json"), "voter1-password")
        unsigned = {k: v for k, v in ballot["packet"].items() if k != "envelope_signature"}
        ballot["packet"]["envelope_signature"] = self.common.elgamal_sign(self.common.digest(unsigned), signing)
        ballot["timestamp"] = self.tsa.issue_ticket({"digest": self.common.digest(ballot["packet"])}, self.tsa_key)
        with self.assertRaisesRegex(ValueError, "tally vector"):
            self.election.dispatch(self.payload("voter1", "cast", ballot=ballot))
        self.assertEqual(self.election.state["ballots"], [])

    def test_sse_audit_and_deadline(self):
        self.election.search_rsa = None
        self.election.dispatch(self.payload("voter1", "cast", ballot=self.ballot()))
        self.assertEqual(len(self.election.search("north")), 1)
        self.assertEqual(self.election.search("south"), [])
        after_deadline = self.common.parse_time(self.public["closes_at"]) + timedelta(seconds=1)
        with patch.object(self.server, "now", return_value=after_deadline):
            with self.assertRaisesRegex(ValueError, "outside"):
                self.election.dispatch(self.payload("voter2", "cast", ballot=self.ballot("voter2")))

    def test_two_authority_tally(self):
        for user, candidate in (("voter1", 0), ("voter2", 1), ("voter3", 0)):
            self.election.dispatch(self.payload(user, "cast", ballot=self.ballot(user, candidate)))
        after_deadline = self.common.parse_time(self.public["closes_at"]) + timedelta(seconds=1)
        with patch.object(self.server, "now", return_value=after_deadline), patch.object(self.server, "stamp", return_value=after_deadline.isoformat()):
            manifest = self.election.close()
        partials = []
        with patch.object(self.authority, "now", return_value=after_deadline):
            for number, password in ((1, "trustee-one"), (2, "trustee-two")):
                share = self.common.load(self.common.DATA / "authorities" / f"{number}.json")
                partials.append(self.authority.partial_decrypt(self.public, manifest, share, password))
        with self.assertRaises(ValueError):
            self.election.finalize(partials[:1])
        with self.assertRaises(ValueError):
            self.election.finalize([partials[0], partials[0]])
        corrupted = copy.deepcopy(partials)
        corrupted[0]["body"]["values"][0] = "1"
        with self.assertRaises(ValueError):
            self.election.finalize(corrupted)
        result = self.election.finalize(partials)
        self.assertEqual(list(result["counts"].values()), [2, 1, 0])
        self.assertEqual(result["total"], 3)

    def test_framing_and_generator_validation(self):
        class Frame:
            def __init__(self, data):
                self.data = io.BytesIO(data)

            def recv(self, size):
                return self.data.read(min(size, 1))

        with self.assertRaises(ValueError):
            self.common.receive(Frame(struct.pack("!I", self.common.MAX_FRAME + 1)))
        value = self.common.canonical({"message": "fragmented"})
        self.assertEqual(self.common.receive(Frame(struct.pack("!I", len(value)) + value)), {"message": "fragmented"})
        with self.assertRaises(FileExistsError):
            generate_socket_solution.create_solution("Again", self.folder)
        with self.assertRaises(ValueError):
            generate_socket_solution.create_solution("Bad", self.folder / "bad", port=8765, tsa_port=8765)


if __name__ == "__main__":
    unittest.main()
