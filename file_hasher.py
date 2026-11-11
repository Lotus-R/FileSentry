import argparse
import hashlib
import json
import os
from pathlib import Path
from operator import itemgetter
from datetime import datetime, timezone

def calculate_sha256(opened_file):
    """Return the SHA-256 hash of a file."""

    sha256 = hashlib.sha256()

    for chunk in iter(lambda: opened_file.read(4096), b""):
        sha256.update(chunk)

    return sha256.hexdigest()

def scan_directory(root_directory):
    """Inventory regular files beneath a directory."""

    root = Path(root_directory).resolve()

    if not root.is_dir():
        raise NotADirectoryError(f"Not a valid directory: {root_directory}")

    inventory = []
    errors = []

    for path in root.rglob("*"):
        if path.is_symlink() or not path.is_file():
            continue

        try:
            with path.open("rb") as file:
                stats_before = os.fstat(file.fileno())
                meta_before = (stats_before.st_size, stats_before.st_mtime_ns, stats_before.st_ino)

                digest = calculate_sha256(file)

                stats_after = os.fstat(file.fileno())
                meta_after = (stats_after.st_size, stats_after.st_mtime_ns, stats_after.st_ino)

                if meta_before != meta_after:
                    raise OSError("File metadata changed during hashing; consistency cannot be verified.")

            inventory.append({
                "path": str(path.relative_to(root)),
                "size": stats_after.st_size,
                "sha256": digest
            })
        except OSError as error:
            errors.append({
                "path": str(path.relative_to(root)),
                "error": str(error)
            })

    inventory.sort(key=itemgetter("path"))

    return inventory, errors

def scan_display(records, errors):
    """Displays the scan output."""

    print("Current scan finished.")
    print(f"Files inventoried: {len(records)}")
    print(f"Errors: {len(errors)}")

    if errors:
        print("\nScan incomplete.")
        print("The current scan contains errors")

        for error in errors:
            print(f"Error:\n   Path -> {error['path']}\n   Msg -> {error['error']}\n")

        return False

    return True

def validate_baseline_location(scan_directory, baseline_file):
    """Ensure the baseline is outside the scan directory."""

    scan_root = Path(scan_directory).resolve()
    baseline_path = Path(baseline_file).resolve()

    if not scan_root.is_dir():
        raise NotADirectoryError(f"Error: Not a valid directory: {scan_root}")

    try:
        baseline_path.relative_to(scan_root)
    except ValueError:
        return

    raise ValueError("Baseline cannot be stored inside the scan directory.")

def create_baseline(inventory, output_file):
    """Save a file inventory as a JSON baseline."""

    baseline = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "algorithm": "SHA-256",
        "files": inventory
    }

    with open(output_file, "x", encoding="utf-8") as file:
        json.dump(baseline, file, indent=4)

    return baseline

def load_baseline(input_file):
    """Load a previously saved JSON baseline."""

    with open(input_file, "r", encoding="utf-8") as file:
        baseline = json.load(file)

    return baseline

def validate_baseline(baseline):
    """Validate the structure and basic contents of a baseline."""

    if not isinstance(baseline, dict):
        raise ValueError("baseline must be a dictionary.")

    if not isinstance(baseline.get("created_at"), str):
        raise ValueError("Invalid baseline timestamp.")

    if baseline.get("algorithm") != "SHA-256":
        raise ValueError("Unsupported hashing algorithm.")

    files = baseline.get("files")

    if not isinstance(files, list):
        raise ValueError("Baseline files must be a list.")

    seen_paths = set()

    for item in files:
        if not isinstance(item, dict):
            raise ValueError("File records must be dictionaries.")

        path = item.get("path")
        size = item.get("size")
        digest = item.get("sha256")

        if not isinstance(path, str) or not path:
            raise ValueError("Invalid file path.")

        if path in seen_paths:
            raise ValueError(f"Duplicate file path: {path}")

        seen_paths.add(path)

        if type(size) is not int or size < 0:
            raise ValueError(f"Invalid file size: {path}")

        if not isinstance(digest, str):
            raise ValueError(f"Invalid SHA-256 hash: {path}")

        if len(digest) != 64:
            raise ValueError(f"Invalid SHA-256 length: {path}")

        if any(char not in "0123456789abcdefABCDEF" for char in digest):
            raise ValueError(f"Invalid SHA-256 characters: {path}")

    return True

def compare_inventories(baseline_inventory, current_inventory):
    """Compare two file inventories and identify changes."""

    baseline_by_path = {
        item["path"]: item for item in baseline_inventory
    }

    current_by_path = {
        item["path"]: item for item in current_inventory
    }

    baseline_paths = set(baseline_by_path)
    current_paths = set(current_by_path)

    common_paths = baseline_paths & current_paths
    deleted_paths = baseline_paths - current_paths
    added_paths = current_paths - baseline_paths

    results = []

    for path in common_paths:
        baseline_hash = baseline_by_path[path]["sha256"]
        current_hash = current_by_path[path]["sha256"]

        if baseline_hash == current_hash:
            status = "UNCHANGED"
        else:
            status = "MODIFIED"

        results.append({
            "path" : path,
            "status" : status
        })

    for path in added_paths:
        results.append({
            "path": path,
            "status": "ADDED"
        })

    for path in deleted_paths:
        results.append({
            "path": path,
            "status": "DELETED"
        })

    results.sort(key=itemgetter("path"))

    return results

def create_argument_parser():
    """Create the FileSentry command-line argument parser."""

    parser = argparse.ArgumentParser(description="FileSentry - File Integrity Checker")

    subparsers = parser.add_subparsers(dest="command", required=True)

    create_parser = subparsers.add_parser("create-baseline", help="Create a new file integrity baseline")
    create_parser.add_argument("--directory", required=True, help="Directory to scan")
    create_parser.add_argument("--baseline", required=True, help="Output path for the new baseline")

    compare_parser = subparsers.add_parser("compare", help="Compare files against an existing baseline")
    compare_parser.add_argument("--directory", required=True, help="Directory to scan")
    compare_parser.add_argument("--baseline", required=True, help="Path of the existing baseline to load")

    return parser

def main():
    parser = create_argument_parser()
    args = parser.parse_args()

    scan_root = Path(args.directory).resolve()
    baseline_path = Path(args.baseline).resolve()

    if args.command == "create-baseline":
        validate_baseline_location(scan_root, baseline_path)

        if baseline_path.exists():
            print(f"Error: Baseline already exists: {baseline_path}")
            raise SystemExit(1)

        records, errors = scan_directory(scan_root)
        if not scan_display(records, errors):
            raise SystemExit(1)

        try:
            create_baseline(records, baseline_path)
        except FileExistsError:
            print(f"Error: Baseline already exists: {baseline_path}")
            raise SystemExit(1)
        except OSError as error:
            print(f"ERROR: Could not create baseline: {error}")
            raise SystemExit(1)
    elif args.command == "compare":
        validate_baseline_location(scan_root, baseline_path)

        if not baseline_path.exists():
            print(f"ERROR: Baseline does not exist: {baseline_path}")
            raise SystemExit(1)

        records, errors = scan_directory(scan_root)
        if not scan_display(records, errors):
            raise SystemExit(1)

        try:
            loaded_baseline = load_baseline(baseline_path)

            validate_baseline(loaded_baseline)

            results = compare_inventories(loaded_baseline["files"], records)
        except FileNotFoundError:
            print(f"ERROR: Baseline does not exist: {baseline_path}")
            raise SystemExit(1)
        except json.JSONDecodeError:
            print("ERROR: Baseline contains invalid JSON.")
            raise SystemExit(1)
        except ValueError as error:
            print(f"ERROR: Baseline validation failed: {error}")
            raise SystemExit(1)
        except OSError as error:
            print(f"ERROR: Could not read baseline: {error}")
            raise SystemExit(1)
        else:
            print("\nFile Integrity Report")
            for result in results:
                print(f"{result['status']}: {result['path']}")

if __name__ == "__main__":
	main()
