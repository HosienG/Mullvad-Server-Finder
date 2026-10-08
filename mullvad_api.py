
import subprocess
import json
import os
import logging
from typing import Optional, Dict, Any

# Setup logger for this module
logger = logging.getLogger(__name__)

class MullvadCLIError(Exception):
    """Custom exception for errors originating from the Mullvad CLI."""
    pass

def normalize_relays(data: Dict[str, Any]) -> Dict[str, Any]:
    """Convert the flat relays.json format (locations + wireguard/openvpn relays)
    into the legacy nested countries -> cities -> relays structure."""
    if not isinstance(data, dict):
        return data
    if "countries" in data:
        return data
    locations = data.get("locations")
    if not isinstance(locations, dict):
        logger.warning(f"Neither 'countries' nor 'locations' found in server data. Top-level keys: {list(data.keys())}")
        return data

    relay_lists = []
    for proto in ("wireguard", "openvpn"):
        section = data.get(proto)
        if isinstance(section, dict):
            relay_lists.extend((relay, proto) for relay in section.get("relays", []))

    countries: Dict[str, Dict[str, Any]] = {}
    for loc_key, loc in locations.items():
        country_code, _, city_code = loc_key.partition("-")
        country = countries.setdefault(country_code, {
            "code": country_code, "name": loc.get("country", country_code), "cities": {}})
        country["cities"].setdefault(city_code, {
            "code": city_code, "name": loc.get("city", city_code), "relays": []})

    relay_count = 0
    for relay, proto in relay_lists:
        loc_key = relay.get("location")
        if loc_key not in locations:
            continue
        country_code, _, city_code = loc_key.partition("-")
        relay = dict(relay)
        if "endpoint_data" not in relay:
            relay["endpoint_data"] = {"wireguard": {}} if proto == "wireguard" else "openvpn"
        countries[country_code]["cities"][city_code]["relays"].append(relay)
        relay_count += 1

    data["countries"] = [
        {**c, "cities": [city for city in c["cities"].values() if city["relays"]]}
        for c in countries.values()
    ]
    data["countries"] = [c for c in data["countries"] if c["cities"]]
    logger.info(f"Converted flat relays format to nested structure: {len(data['countries'])} countries, {relay_count} relays.")
    return data

def load_cached_servers(cache_path: str) -> Optional[Dict[str, Any]]:
    """Load the cached Mullvad servers JSON from the specified path."""
    logger.info(f"Attempting to load cached servers from: {cache_path}")
    if not os.path.exists(cache_path):
        logger.error(f"Cache file not found at {cache_path}")
        return None
    try:
        with open(cache_path, "r", encoding='utf-8') as f:
            data = json.load(f)
        logger.info(f"Successfully loaded server data from {cache_path}")
        return normalize_relays(data)
    except json.JSONDecodeError as e:
        logger.exception(f"Error decoding JSON from {cache_path}: {e}")
        return None
    except Exception as e:
        logger.exception(f"Error loading cached servers from {cache_path}: {e}")
        return None

def _run_mullvad_command(cmd: list[str]) -> str:
    """Helper function to run Mullvad CLI commands and handle errors."""
    command_str = ' '.join(cmd)
    logger.info(f"Running Mullvad command: {command_str}")
    try:
        # Added timeout to prevent hanging indefinitely
        result = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=30)

        if result.returncode != 0:
            error_message = f"Mullvad command failed (code {result.returncode}): {command_str}\nStderr: {result.stderr.strip()}"
            logger.error(error_message)
            raise MullvadCLIError(error_message)

        logger.info(f"Mullvad command successful: {command_str}")
        return result.stdout.strip()
    except FileNotFoundError:
        logger.exception("Mullvad CLI command not found. Is Mullvad installed and in PATH?")
        raise MullvadCLIError("Mullvad CLI not found. Ensure Mullvad VPN is installed and CLI is accessible.")
    except subprocess.TimeoutExpired:
        logger.error(f"Mullvad command timed out: {command_str}")
        raise MullvadCLIError(f"Mullvad command timed out: {command_str}")
    except Exception as e:
        logger.exception(f"An unexpected error occurred while running Mullvad command: {command_str}")
        raise MullvadCLIError(f"An unexpected error occurred: {e}")


def set_mullvad_location(country_code: str, city_code: Optional[str] = None, hostname: Optional[str] = None) -> str:
    """Set Mullvad location to the given country, city, and server."""
    cmd = ['mullvad', 'relay', 'set', 'location']

    if not country_code:
         err = "Country code is required to set location."
         logger.error(err)
         raise ValueError(err)

    cmd.append(country_code)
    if city_code:
        cmd.append(city_code)
        if hostname:
            cmd.append(hostname)

    return _run_mullvad_command(cmd)

def set_mullvad_protocol(protocol: str) -> str:
    """Set Mullvad tunneling protocol (openvpn or wireguard)."""
    protocol = protocol.lower()
    if protocol not in ["openvpn", "wireguard"]:
        err = "Protocol must be either 'openvpn' or 'wireguard'"
        logger.error(err)
        raise ValueError(err)

    cmd = ['mullvad', 'relay', 'set', 'tunnel-protocol', protocol]
    return _run_mullvad_command(cmd)

def get_mullvad_status() -> str:
    """Get the current Mullvad connection status."""
    cmd = ['mullvad', 'status']
    # Don't raise MullvadCLIError here, as status checks might run when CLI isn't fully functional
    # Let the caller handle potential exceptions more gracefully.
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=10)
        if result.returncode != 0:
            logger.warning(f"Mullvad status command failed (code {result.returncode}): {result.stderr.strip()}")
            # Return a specific status indicating the issue
            if "Mullvad VPN daemon is not running" in result.stderr:
                return "Daemon not running"
            return "Status unavailable"
        return result.stdout.strip()
    except FileNotFoundError:
        logger.error("Mullvad CLI command not found during status check.")
        return "CLI not found"
    except subprocess.TimeoutExpired:
        logger.warning("Mullvad status command timed out.")
        return "Status timed out"
    except Exception as e:
        logger.exception(f"Unexpected error getting Mullvad status: {e}")
        return "Status error"


def connect_mullvad() -> str:
    """Connect to Mullvad VPN using the currently set location/protocol."""
    cmd = ['mullvad', 'connect']
    return _run_mullvad_command(cmd)

def disconnect_mullvad() -> str:
    """Disconnect from Mullvad VPN."""
    cmd = ['mullvad', 'disconnect']
    return _run_mullvad_command(cmd)
