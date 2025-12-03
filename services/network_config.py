# services/network_config.py

import json
import ipaddress
from pathlib import Path

DEFAULT_HOSTNAME = "default_host"
DEFAULT_VLAN_ID = "0"
DEFAULT_VLAN_NAME = "default_vlan"
DEFAULT_LOCATION = "default_location"

class NetworkConfig:
    """
    Reads config/network_config.json and provides:
    - auto hostname
    - auto data VLAN
    - voice VLAN
    - profile VLANs (standard/av)
    - trunk list builder
    """

    def __init__(self, config_path: Path):
        self.config_path = config_path
        self.config = {}
        self._load_config()

    # -------- load config --------

    def _load_config(self):
        if not self.config_path.exists():
            raise FileNotFoundError(f"Missing network_config.json at {self.config_path}")

        self.config = json.loads(self.config_path.read_text(encoding="utf-8"))

    # -------- network matching --------

    def _match_network(self, ip: str):
        try:
            ip_obj = ipaddress.IPv4Address(ip)
        except Exception:
            return None

        for cfg in self.config.values():
            try:
                net = ipaddress.IPv4Network(
                    f"{cfg['network_address']}/{cfg['subnet_mask']}",
                    strict=False
                )
            except Exception:
                continue

            if ip_obj in net:
                return cfg

        return None

    # -------- VLAN helpers --------

    def get_gateway(self, ip: str):
        cfg = self._match_network(ip)
        if cfg:
            return cfg["gateway"]

        # fallback to /24
        try:
            net = ipaddress.IPv4Network(f"{ip}/24", strict=False)
            return str(net.network_address + 254)
        except Exception:
            return "0.0.0.0"

    def get_data_vlan(self, ip: str):
        cfg = self._match_network(ip)
        if cfg and "data_vlan" in cfg:
            return cfg["data_vlan"]["id"], cfg["data_vlan"]["name"]
        return DEFAULT_VLAN_ID, DEFAULT_VLAN_NAME

    def get_voice_vlan(self, ip: str):
        cfg = self._match_network(ip)
        if cfg and "voice_vlan" in cfg:
            return cfg["voice_vlan"]["id"], cfg["voice_vlan"]["name"]
        return "", ""

    def get_profile_vlans(self, ip: str, profile_type: str):
        cfg = self._match_network(ip)
        if not cfg:
            return {}
        return cfg.get("profiles", {}).get(profile_type, {})

    # -------- hostname --------

    def generate_hostname(self, ip: str, template_label: str):
        try:
            octs = ip.split(".")
        except Exception:
            return DEFAULT_HOSTNAME

        if "6300" in template_label.lower():
            prefix = "ae6000m"
        else:
            prefix = "ae4100i"

        return f"{prefix}-{octs[1]}-{octs[2]}-{octs[3]}"

    def detect_profile(self, template_label: str):
        t = template_label.lower()
        if "audio" in t or "av" in t or "visual" in t:
            return "av"
        return "standard"

    # -------- trunk VLAN builder --------

    def build_trunk_list(self, ip: str, data_vlan_id: str, profile_type: str):
        s = set()

        # data VLAN
        if data_vlan_id:
            s.add(str(data_vlan_id))

        # voice VLAN
        voice_id, _ = self.get_voice_vlan(ip)
        if voice_id:
            s.add(str(voice_id))

        # defaults
        s.update(["885", "1001"])

        # profile VLANs
        for vid in self.get_profile_vlans(ip, profile_type).keys():
            s.add(str(vid))

        # sort numerically
        try:
            return ",".join(sorted(s, key=lambda x: int(x)))
        except:
            return ",".join(sorted(s))
