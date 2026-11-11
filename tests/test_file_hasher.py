import unittest
from unittest.mock import patch

import tempfile
import subprocess
import sys

import hashlib
import file_hasher
import json
from pathlib import Path

class TestCalculateSHA256(unittest.TestCase):
	def test_calculate_sha256(self):
		test_content = b"FileSentry test\n"

		expected_hash = ("a81af8329ac149c37653aac6c185de5df8bd7ce49491052ec5df95bb66d1fbc5")

		with tempfile.TemporaryDirectory() as temp_dir:
			test_file = Path(temp_dir) / "test.txt"

			test_file.write_bytes(test_content)

			with test_file.open("rb") as file:
				actual_hash = file_hasher.calculate_sha256(file)

			self.assertEqual(actual_hash, expected_hash)

	def test_different_content_different_hashes(self):
		with tempfile.TemporaryDirectory() as temp_dir:
			file1 = Path(temp_dir) / "one.txt"
			file2 = Path(temp_dir) / "two.txt"

			file1.write_bytes(b"1st content")
			file2.write_bytes(b"2nd content")

			with file1.open("rb") as file:
				hash_one = file_hasher.calculate_sha256(file)

			with file2.open("rb") as file:
				hash_two = file_hasher.calculate_sha256(file)

			self.assertNotEqual(hash_one, hash_two)

	def test_empty_file(self):
		with tempfile.TemporaryDirectory() as temp_dir:
			empty_file = Path(temp_dir) / "empty.txt"

			empty_file.write_bytes(b"")

			with empty_file.open("rb") as file:
				actual_hash = file_hasher.calculate_sha256(file)

			expected_hash = hashlib.sha256(b"").hexdigest()

			self.assertEqual(actual_hash, expected_hash)

class TestScanDirectory(unittest.TestCase):
	def test_scan_directory(self):
		with tempfile.TemporaryDirectory() as temp_dir:
			root = Path(temp_dir)

			file1 = root / "first.txt"
			file2 = root / "subfolder" / "second.txt"

			file2.parent.mkdir()

			file1.write_bytes(b"First file.")
			file2.write_bytes(b"Second file.")

			inventory, errors = file_hasher.scan_directory(root)

			self.assertEqual(len(inventory), 2)
			self.assertEqual(len(errors), 0)

			paths = [item["path"] for item in inventory]

			self.assertIn("first.txt", paths)
			self.assertIn("subfolder/second.txt", paths)

	def test_scan_records_correct_metadata(self):
		with tempfile.TemporaryDirectory() as temp_dir:
			root = Path(temp_dir)

			test_file = root / "evidence.txt"

			content = b"Forensic evidence test"
			test_file.write_bytes(content)

			inventory, errors = file_hasher.scan_directory(root)

			self.assertEqual(len(inventory), 1)
			self.assertEqual(len(errors), 0)

			record = inventory[0]

			self.assertEqual(record["path"], "evidence.txt")
			self.assertEqual(record["size"], len(content))
			self.assertEqual(record["sha256"], hashlib.sha256(content).hexdigest())

	def test_invalid_directory_raises_error(self):
		with tempfile.TemporaryDirectory() as temp_dir:
			missing_directory = Path(temp_dir) / "missing"

			with self.assertRaises(NotADirectoryError):
				file_hasher.scan_directory(missing_directory)

	def test_file_changed_during_hash_is_included(self):
		with tempfile.TemporaryDirectory() as temp_dir:
			root = Path(temp_dir)

			changing_file = root / "changing.txt"
			stable_file = root / "stable.txt"

			changing_file.write_bytes(b"Origianl content")
			stable_file.write_bytes(b"Stable content")

			original_hash = file_hasher.calculate_sha256

			def hash_and_modify(opened_file):
				digest = original_hash(opened_file)
				if Path(opened_file.name).name == "changing.txt":
					with open(opened_file.name, "ab") as modifier:
						modifier.write(b"Additional content")
				return digest

			with patch("file_hasher.calculate_sha256", side_effect=hash_and_modify):
				inventory, errors = file_hasher.scan_directory(root)

			paths = [item["path"] for item in inventory]

			self.assertNotIn("changing.txt", paths)
			self.assertIn("stable.txt", paths)

			self.assertEqual(len(errors), 1)
			self.assertEqual(errors[0]["path"], "changing.txt")
			self.assertIn("metadata changed during hashing", errors[0]["error"])

class TestCompareInventories(unittest.TestCase):
	def test_identifies_all_file_changes(self):
		baseline = [
			{"path": "unchanged.txt", "sha256": "aaa"},
			{"path": "modified.txt", "sha256": "bbb"},
			{"path": "deleted.txt", "sha256": "ccc"}
		]
		current = [
			{"path": "unchanged.txt", "sha256": "aaa"},
			{"path": "modified.txt", "sha256": "xyz"},
			{"path": "added.txt", "sha256": "ddd"}
		]

		results = file_hasher.compare_inventories(baseline, current)

		expected = {
			"unchanged.txt": "UNCHANGED",
			"modified.txt": "MODIFIED",
			"deleted.txt": "DELETED",
			"added.txt": "ADDED"
		}
		actual = {item["path"]: item["status"] for item in results}

		self.assertEqual(actual, expected)

	def test_empty_baseline(self):
		baseline = []
		current = [
			{"path":"first.txt", "sha256":"aaa"},
			{"path":"second.txt", "sha256":"bbb"}
		]

		results = file_hasher.compare_inventories(baseline, current)

		self.assertEqual(len(results), 2)
		for item in results:
			self.assertEqual(item["status"], "ADDED")

class TestBaselineLoading(unittest.TestCase):
	def test_missing_baseline_raises_error(self):
		with tempfile.TemporaryDirectory() as temp_dir:
			missing_file = Path(temp_dir) / "missing.json"

			with self.assertRaises(FileNotFoundError):
				file_hasher.load_baseline(missing_file)

	def test_corrupted_baseline_raises_error(self):
		with tempfile.TemporaryDirectory() as temp_dir:
			corrupted_file = Path(temp_dir) / "corrupted.json"

			corrupted_file.write_text(
				'{"algorithm":"SHA-256", "files":[INVALID]}',
				encoding="utf-8"
			)

			with self.assertRaises(json.JSONDecodeError):
				file_hasher.load_baseline(corrupted_file)

class TestValidateBaseline(unittest.TestCase):
	def setUp(self):
		self.valid_baseline = {
			"created_at": "2026-11-03T00:00:00+00:00",
			"algorithm": "SHA-256",
			"files": [
				{
					"path": "evidence.txt",
					"size": 12,
					"sha256": "a" * 64
				}
			]
		}

	def test_valid_baseline(self):
		self.assertTrue(file_hasher.validate_baseline(self.valid_baseline))

	def test_files_must_be_a_list(self):
		invalid = self.valid_baseline.copy()
		invalid["files"] = "not a list"

		with self.assertRaises(ValueError):
			file_hasher.validate_baseline(invalid)

	def test_unsupported_algorithm(self):
		invalid = self.valid_baseline.copy()
		invalid["algorithm"] = "MD5"

		with self.assertRaises(ValueError):
			file_hasher.validate_baseline(invalid)

	def test_invalid_hash_length(self):
		invalid = self.valid_baseline.copy()
		invalid["files"] = [dict(self.valid_baseline["files"][0], sha256="abc")]

		with self.assertRaises(ValueError):
			file_hasher.validate_baseline(invalid)

	def test_invalid_hash_characters(self):
		invalid = self.valid_baseline.copy()
		invalid["files"] = [dict(self.valid_baseline["files"][0], sha256="*" + "a" * 63)]

		with self.assertRaises(ValueError):
			file_hasher.validate_baseline(invalid)

	def test_duplicate_paths(self):
		invalid = self.valid_baseline.copy()
		invalid["files"] = [
			dict(self.valid_baseline["files"][0]),
			dict(self.valid_baseline["files"][0])
		]

		with self.assertRaises(ValueError):
			file_hasher.validate_baseline(invalid)

class TestApplicationErrorHandling(unittest.TestCase):
	def run_application(self, baseline_content=None):
		with tempfile.TemporaryDirectory() as temp_dir:
			root = Path(temp_dir)

			test_data = root / "test_data"
			test_data.mkdir()

			sample_file = test_data / "sample.txt"
			sample_file.write_text("Test evidence", encoding="utf-8")

			if baseline_content == "VALID":
				with sample_file.open("rb") as file:
					baseline = {
						"created_at": "2026-11-03T00:00:00+00:00",
						"algorithm":"SHA-256",
						"files": [
							{
								"path": "sample.txt",
								"size": sample_file.stat().st_size,
								"sha256": file_hasher.calculate_sha256(file)
							}
						]
					}
					baseline_content = json.dumps(baseline)
			if baseline_content is not None:
				(root / "baseline.json").write_text(baseline_content, encoding="utf-8")

			script_path = (Path(__file__).resolve().parent.parent / "file_hasher.py")

			result = subprocess.run(
				[
					sys.executable,
					str(script_path),
					"compare",
					"--directory",
					str(test_data),
					"--baseline",
					str(root / "baseline.json")
				],
				cwd = root,
				capture_output = True,
				text = True
			)
			return result


	def test_missing_baseline_message(self):
		result = self.run_application()

		self.assertIn("ERROR: Baseline does not exist: ", result.stdout)
		self.assertNotIn("File Integrity Report", result.stdout)
		self.assertEqual(result.returncode, 1)

	def test_corrupted_baseline_message(self):
		result = self.run_application("{invalid json")

		self.assertIn("ERROR: Baseline contains invalid JSON.", result.stdout)
		self.assertNotIn("File Integrity Report", result.stdout)
		self.assertEqual(result.returncode, 1)

	def test_invalid_baseline_message(self):
		invalid_baseline = json.dumps({
			"created_at": "2026-11-03T00:00:00+00:00",
			"algorithm":"MD5",
			"files": "[]"
		})

		result = self.run_application(invalid_baseline)

		self.assertIn("Unsupported hashing algorithm.", result.stdout)
		self.assertNotIn("File Integrity Report", result.stdout)
		self.assertEqual(result.returncode, 1)

	def test_successful_application(self):
		result = self.run_application("VALID")

		self.assertIn("File Integrity Report", result.stdout)
		self.assertIn("UNCHANGED: sample.txt", result.stdout)
		self.assertEqual(result.returncode, 0)
