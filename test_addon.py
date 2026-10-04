import json
import stat
import tempfile
import unittest
from pathlib import Path

import mitmproxy_rs.wireguard

import addon
import main


class WireGuardConfigTests(unittest.TestCase):
  def test_first_launch_generates_keys_and_later_launch_reuses_them(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      keys_path = Path(temp_dir) / "wg-keys.json"

      main.ensure_wireguard_keys(keys_path)
      first_keys = json.loads(keys_path.read_text())
      first_contents = keys_path.read_text()

      self.assertEqual(set(first_keys), {"server_key", "client_key"})
      self.assertNotEqual(first_keys["server_key"], first_keys["client_key"])
      mitmproxy_rs.wireguard.pubkey(first_keys["server_key"])
      mitmproxy_rs.wireguard.pubkey(first_keys["client_key"])
      self.assertEqual(stat.S_IMODE(keys_path.stat().st_mode), 0o600)

      keys_path.chmod(0o644)
      main.ensure_wireguard_keys(keys_path)
      self.assertEqual(keys_path.read_text(), first_contents)
      self.assertEqual(stat.S_IMODE(keys_path.stat().st_mode), 0o600)

  def test_generates_client_config_from_private_keys(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      temp_path = Path(temp_dir)
      keys_path = temp_path / "wg-keys.json"
      config_path = temp_path / "wireguard.cfg"
      server_key = mitmproxy_rs.wireguard.genkey()
      client_key = mitmproxy_rs.wireguard.genkey()
      keys_path.write_text(json.dumps({
        "server_key": server_key,
        "client_key": client_key,
      }))

      addon.generate_wireguard_client_config(
        "203.0.113.10",
        keys_path,
        config_path,
      )

      config = config_path.read_text()
      self.assertIn(f"PrivateKey = {client_key}", config)
      self.assertIn(
        f"PublicKey = {mitmproxy_rs.wireguard.pubkey(server_key)}",
        config,
      )
      self.assertNotIn(f"PublicKey = {server_key}", config)
      self.assertIn("Endpoint = 203.0.113.10:51820", config)
      self.assertEqual(stat.S_IMODE(keys_path.stat().st_mode), 0o600)
      self.assertEqual(stat.S_IMODE(config_path.stat().st_mode), 0o600)


if __name__ == "__main__":
  unittest.main()
