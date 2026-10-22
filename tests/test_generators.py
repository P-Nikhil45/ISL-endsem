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
        cls.folder = generate_socket_solution.create_solution(
            "Test election", Path(cls.temporary.name) / "lab", candidates=["A", "B", "C"])
        cls.server_source = (cls.folder / "server.py").read_text(encoding="utf-8")
        cls.client_source = (cls.folder / "client.py").read_text(encoding="utf-8")
        cls.server = module("socket_server", cls.folder / "server.py")
        cls.client = module("socket_client", cls.folder / "client.py")

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def setUp(self):
        self.server.save(self.server.BALLOTS_PATH, [])
        self.server.SERVER_STATE["accepted_count"] = 0

    def submit(self, candidate="B", constituency="North"):
        packet = self.client.prepare_vote(candidate, constituency, self.client.PUBLIC,
                                           self.client.CLIENT_SIGNING_KEY)
        private_key = self.server.RSA.import_key(self.server.SERVER_RSA_PRIVATE_PEM)
        return self.server.verify_and_store({"operation": "submit", **packet}, self.server.PUBLIC, private_key)

    def test_generator_emits_two_role_files_and_embeds_keys(self):
        self.assertEqual({path.name for path in self.folder.glob("*.py")}, {"server.py", "client.py"})
        compile(self.server_source, "server.py", "exec")
        compile(self.client_source, "client.py", "exec")
        self.assertIn("SERVER_RSA_PRIVATE_PEM", self.server_source)
        self.assertNotIn("SERVER_RSA_PRIVATE_PEM", self.client_source)
        self.assertIn("CLIENT_SIGNING_KEY", self.client_source)
        self.assertNotIn("CLIENT_SIGNING_KEY", self.server_source)

    def test_ballot_verification_storage_search_and_homomorphic_tally(self):
        receipt = self.submit()
        self.assertTrue(receipt["verified"])
        stored = self.server.load_ballots()
        self.assertEqual(len(stored), 1)
        self.assertEqual(stored[0]["constituency_id"], "North")
        self.assertNotIn("candidate_id", stored[0])

        results = self.server.search_ballots({"constituency_id": "North"})
        self.assertEqual(results["count"], 1)
        self.assertEqual(len(self.server.search_ballots({"constituency_id": "South"})["ballots"]), 0)
        self.assertEqual(self.server.search_ballots({"constituency_id": "North",
                                                     "start_date": "2099-01-01"})["count"], 1)

        tally = self.server.tally_votes({"constituency_id": "North"}, self.server.PUBLIC,
                                        self.server.PAILLIER_PRIVATE_KEY)
        self.assertEqual(tally["total"], 1)
        self.assertEqual(tally["counts"], {"A": 0, "B": 1, "C": 0})

    def test_tampering_and_generator_validation(self):
        packet = self.client.prepare_vote("A", "North", self.client.PUBLIC,
                                          self.client.CLIENT_SIGNING_KEY)
        packet["encrypted"]["ciphertext"] = "00"
        private_key = self.server.RSA.import_key(self.server.SERVER_RSA_PRIVATE_PEM)
        with self.assertRaises((ValueError, KeyError, TypeError)):
            self.server.verify_and_store({"operation": "submit", **packet}, self.server.PUBLIC, private_key)
        self.assertEqual(self.server.load_ballots(), [])

        with self.assertRaises(FileExistsError):
            generate_socket_solution.create_solution("Again", self.folder)
        with self.assertRaises(ValueError):
            generate_socket_solution.create_solution("Bad", self.folder.parent / "bad",
                                                     port=8765, candidates=["same", "same"])


if __name__ == "__main__":
    unittest.main()

