"""
  This file is just the entrypoint. All application code is in `addon.py`.

  I'm not proud of this layout, but I frankly do not care enough. It seems
  like mitmproxy creates a separate Python environment for the addons(?),
  and communicating between those seems like hell.
"""

import json
import os
from pathlib import Path

import mitmproxy_rs.wireguard
from mitmproxy.tools.main import mitmdump

WIREGUARD_KEYS_PATH = Path("wg-keys.json")

def ensure_wireguard_keys(keys_path: Path = WIREGUARD_KEYS_PATH) -> None:
  """Create a private, per-installation WireGuard keypair if none exists."""
  keys_path.parent.mkdir(parents=True, exist_ok=True)
  try:
    file_descriptor = os.open(
      keys_path,
      os.O_WRONLY | os.O_CREAT | os.O_EXCL,
      0o600,
    )
  except FileExistsError:
    keys_path.chmod(0o600)
    return

  try:
    with os.fdopen(file_descriptor, "w") as keys_file:
      json.dump({
        "server_key": mitmproxy_rs.wireguard.genkey(),
        "client_key": mitmproxy_rs.wireguard.genkey(),
      }, keys_file, indent=4)
  except BaseException:
    keys_path.unlink(missing_ok=True)
    raise

def main():
  ensure_wireguard_keys()
  mitmdump(args=[
    "-s", "addon.py",
    "--mode", "wireguard:wg-keys.json",
    "--set", "http3=false",
  ])

if __name__ == "__main__":
  main()
