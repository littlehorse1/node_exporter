import argparse
import os
from typing import Optional

import requests

URL_FILE_UPLOAD = "http://hk4e-dfs.mihoyo.com:9999/main_fileserver/fileupload"


def upload_file(
    local_path: str,
    remote_filename: str,
    *,
    username: str = "MaQiMing",
    skip_date_folder: bool = True,
    timeout_s: int = 60,
) -> str:
    headers = {
        "Content-Type": "application/octet-stream",
        "userName": username,
        "fileName": remote_filename,
        "SkipDateFolder": "true" if skip_date_folder else "false",
    }

    with open(local_path, "rb") as f:
        res = requests.post(URL_FILE_UPLOAD, headers=headers, data=f, timeout=timeout_s)
    res.raise_for_status()
    return res.text


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Upload node_exporter outputs under ./out to hk4e-dfs."
    )
    parser.add_argument(
        "--out-dir",
        default="out",
        help="Local output directory (default: ./out)",
    )
    parser.add_argument(
        "--amd64",
        default="node_exporter_linux_amd64",
        help="amd64 output filename under out-dir",
    )
    parser.add_argument(
        "--arm64",
        default="node_exporter_linux_arm64",
        help="arm64 output filename under out-dir",
    )
    # Keep amd64 default name compatible with existing installers (overwrite old file).
    parser.add_argument("--remote-amd64", default="node_exporter.2", help="Remote filename for amd64")
    # Keep arm64 separate to avoid overwriting amd64 binary.
    parser.add_argument("--remote-arm64", default="node_exporter_arm64.2", help="Remote filename for arm64")
    parser.add_argument("--username", default="MaQiMing", help="userName header value")
    parser.add_argument(
        "--skip-date-folder",
        default=True,
        action=argparse.BooleanOptionalAction,
        help="Set SkipDateFolder header (default: true)",
    )
    parser.add_argument("--timeout", type=int, default=60, help="HTTP timeout seconds")

    args = parser.parse_args(argv)

    out_dir = os.path.abspath(args.out_dir)
    amd64_path = os.path.join(out_dir, args.amd64)
    arm64_path = os.path.join(out_dir, args.arm64)

    missing = [p for p in (amd64_path, arm64_path) if not os.path.isfile(p)]
    if missing:
        raise FileNotFoundError("Missing outputs: " + ", ".join(missing))

    print(f"[INFO] uploading amd64: {amd64_path} -> {args.remote_amd64}")
    print(upload_file(
        amd64_path,
        args.remote_amd64,
        username=args.username,
        skip_date_folder=args.skip_date_folder,
        timeout_s=args.timeout,
    ))
    print(f"[INFO] uploading arm64: {arm64_path} -> {args.remote_arm64}")
    print(upload_file(
        arm64_path,
        args.remote_arm64,
        username=args.username,
        skip_date_folder=args.skip_date_folder,
        timeout_s=args.timeout,
    ))

    print()
    print("[HINT] ARM64 安装时设置 URL，例如：")
    print("  NODE_EXPORTER_URL_ARM64='<arm64下载URL>' bash install_node_exporter.sh")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

