# FileSentry

**A Python-based File Integrity Checker**

FileSentry is a command-line application that monitors file integrity using SHA-256 hashing.

It creates JSON-based file integrity baselines and compares subsequent directory scans against those baselines to identify unchanged, modified, added, and deleted files.

This project demonstrates practical Python programming, filesystem operations, cryptographic hashing, JSON data handling, command-line interface development, error handling, and automated testing.

## Features

- SHA-256 file hashing using chunked binary reads.
- Recursive directory scanning.
- Relative file-path recording.
- JSON baseline creation and loading.
- Detection of modified, added, deleted, and unchanged files.
- File metadata consistency checks during hashing.
- Error reporting and incomplete-scan protection.
- Baseline validation and overwrite protection.
- Command-line interface with separate create and comparison commands.
- Automated tests covering core functionality and application behaviour.

## Requirements

- Python 3.14.8 (version used during development and testing).
- No third-party Python packages are required.

FileSentry uses Python standard-library modules.

## Installation

Clone the repository:

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
```

Navigate into the project directory:

```bash
cd FileSentry
```

## Usage

FileSentry provides two commands.

### 1. Create a baseline

Create a baseline from a directory:

```bash
python3 file_hasher.py create-baseline --directory test_data --baseline baseline.json
```

This scans the target directory, calculates SHA-256 hashes, and creates a JSON baseline.

The baseline should be stored outside the directory being monitored.

FileSentry will not overwrite an existing baseline.

### 2. Compare against an existing baseline

Run:

```bash
python3 file_hasher.py compare --directory test_data --baseline baseline.json
```

This scans the target directory and compares its contents against the existing baseline.

Detected file states include:

| Status | Meaning |
|---|---|
| UNCHANGED | The file's hash matches the baseline. |
| MODIFIED | The file exists in both inventories, but its hash differs. |
| ADDED | The file exists in the current scan but not in the baseline. |
| DELETED | The file exists in the baseline but not in the current scan. |

FileSentry blocks comparison when the current scan contains errors, preventing an incomplete scan from incorrectly reporting files as deleted.

## Running the Tests

FileSentry includes an automated test suite using Python's built-in `unittest` framework.

Run the tests from the project root:

```bash
python3 -m unittest discover -s tests -v
```

The test suite covers hashing, directory scanning, baseline handling, comparison logic, validation, error handling, and command-line application behaviour.

## Security and Forensic Considerations

FileSentry is a learning-oriented file integrity monitoring tool. It is not a validated forensic acquisition or evidence preservation solution.

Important limitations:

- A matching SHA-256 hash indicates matching file contents at the time of comparison. It does not establish that a file is safe, authentic, or trustworthy.
- Baseline validation checks structure and content, but does not independently authenticate baseline provenance.
- An attacker who can modify both a monitored file and its baseline entry may conceal the modification.
- File metadata checks provide best-effort detection of changes during hashing, not a guarantee against every possible modification.
- A baseline should be protected and stored separately from the monitored directory.
- FileSentry does not independently establish chain of custody or prove the history of a file.

Use synthetic data when demonstrating or testing the application. Do not use this project as a substitute for validated forensic tools or procedures.

## Project Structure

```text
FileSentry/
├── file_hasher.py
├── README.md
├── .gitignore
├── test_data/
│   ├── evidence.txt
│   ├── first.txt
│   ├── hello.txt
│   ├── new_file.txt
│   └── subfolder/
│       └── second.txt
└── tests/
    └── test_file_hasher.py
```

## Future Improvements

Potential future enhancements include:

- Cryptographic signing or authentication of baseline files.
- Improved reporting and export options.
- Additional filesystem consistency checks.
- Expanded test coverage and compatibility testing across Python versions.

## Author

Developed as an independent Python cybersecurity portfolio project, focused on file integrity monitoring, secure programming practices, and foundational digital forensics concepts. 
