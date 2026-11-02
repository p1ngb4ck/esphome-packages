import argparse
import datetime
import gzip
import hashlib
import io
import json
import shutil
import sys
import tarfile
from pathlib import Path

FIELDS = (
    "Package",
    "Version",
    "Depends",
    "Architecture",
    "ESPHome-ABI",
    "ESPHome-Flash",
    "ESPHome-PSRAM",
    "ESPHome-IRAM",
    "Description",
)


def ar_members(data: bytes) -> dict[str, bytes]:
    if data[:8] != b"!<arch>\n":
        raise ValueError("not an ar archive")
    members = {}
    pos = 8
    while pos + 60 <= len(data):
        header = data[pos : pos + 60]
        name = header[:16].decode("ascii").strip().rstrip("/")
        size = int(header[48:58].decode("ascii").strip())
        pos += 60
        members[name] = data[pos : pos + size]
        pos += size + (size % 2)
    return members


def control_fields(ipk: bytes) -> dict[str, str]:
    members = ar_members(ipk)
    text = None
    with tarfile.open(fileobj=io.BytesIO(members["control.tar.gz"]), mode="r:gz") as tar:
        for member in tar.getmembers():
            if member.name.lstrip("./") == "control":
                text = tar.extractfile(member).read().decode("utf-8")
    if text is None:
        raise ValueError("no control file")
    fields: dict[str, str] = {}
    key = None
    for line in text.splitlines():
        if line[:1] in (" ", "\t") and key is not None:
            fields[key] += "\n" + line
        elif ":" in line:
            key, value = line.split(":", 1)
            key = key.strip()
            fields[key] = value.strip()
    return fields


def paragraph(fields: dict[str, str], filename: str, data: bytes) -> str:
    lines = [f"{name}: {fields[name]}" for name in FIELDS if name != "Description" and fields.get(name)]
    lines += [f"Filename: {filename}", f"Size: {len(data)}", f"SHA256sum: {hashlib.sha256(data).hexdigest()}"]
    if fields.get("Description"):
        lines.append(f"Description: {fields['Description']}")
    return "\n".join(lines) + "\n"


def publish(packages: Path, repo: Path, board: str, device: str, version: str) -> str:
    ipks = sorted(packages.glob("*.ipk"))
    if not ipks:
        raise SystemExit(f"no .ipk files in {packages}")
    found = []
    for ipk in ipks:
        data = ipk.read_bytes()
        found.append((ipk, data, control_fields(data)))
    abis = {fields.get("ESPHome-ABI", "") for _, _, fields in found}
    if len(abis) != 1 or not abis.pop().isdigit():
        raise SystemExit("the packages do not carry one firmware id (ESPHome-ABI)")
    firmware_id = f"{int(found[0][2]['ESPHome-ABI']):08x}"
    target = repo / firmware_id
    if target.exists():
        shutil.rmtree(target)
    target.mkdir(parents=True)
    paragraphs = []
    for ipk, data, fields in found:
        (target / ipk.name).write_bytes(data)
        paragraphs.append(paragraph(fields, ipk.name, data))
    index = "\n".join(paragraphs).encode("utf-8")
    (target / "Packages").write_bytes(index)
    with gzip.GzipFile(target / "Packages.gz", "wb", mtime=0) as out:
        out.write(index)
    catalog_path = repo / "index.json"
    catalog = json.loads(catalog_path.read_text(encoding="utf-8")) if catalog_path.is_file() else {"builds": []}
    builds = [build for build in catalog.get("builds", []) if build.get("id") != firmware_id]
    builds.append(
        {
            "id": firmware_id,
            "board": board,
            "device": device,
            "version": version,
            "date": datetime.date.today().isoformat(),
            "architecture": found[0][2].get("Architecture", ""),
            "packages": [fields["Package"] for _, _, fields in found],
        }
    )
    catalog["builds"] = builds
    catalog_path.write_text(json.dumps(catalog, indent=1) + "\n", encoding="utf-8", newline="\n")
    return firmware_id


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--packages", type=Path, required=True)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--board", required=True)
    parser.add_argument("--device", required=True)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    firmware_id = publish(args.packages, args.repo, args.board, args.device, args.version)
    print(firmware_id)
    return 0


if __name__ == "__main__":
    sys.exit(main())
