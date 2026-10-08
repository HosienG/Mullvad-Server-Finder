import unittest

from mullvad_api import normalize_relays
from server_manager import filter_servers_by_protocol


class NormalizeRelaysTest(unittest.TestCase):
    def sample(self):
        return {
            "locations": {"se-got": {"country": "Sweden", "city": "Gothenburg", "latitude": 1, "longitude": 2}},
            "wireguard": {"relays": [{"hostname": "se-got-wg-001", "location": "se-got", "active": True,
                                      "ipv4_addr_in": "1.2.3.4", "provider": "x", "owned": True}]},
            "openvpn": {"relays": [{"hostname": "se-got-ovpn-001", "location": "se-got", "active": True}]},
        }

    def test_converts_flat_format(self):
        data = normalize_relays(self.sample())
        self.assertEqual(len(data["countries"]), 1)
        country = data["countries"][0]
        self.assertEqual((country["code"], country["name"]), ("se", "Sweden"))
        city = country["cities"][0]
        self.assertEqual((city["code"], city["name"]), ("got", "Gothenburg"))
        relays = city["relays"]
        self.assertEqual(len(relays), 2)
        self.assertEqual(relays[0]["ipv4_addr_in"], "1.2.3.4")
        self.assertEqual([r["hostname"] for r in filter_servers_by_protocol(relays, "wireguard")], ["se-got-wg-001"])
        self.assertEqual([r["hostname"] for r in filter_servers_by_protocol(relays, "openvpn")], ["se-got-ovpn-001"])

    def test_legacy_unchanged(self):
        legacy = {"countries": [{"code": "se"}]}
        self.assertIs(normalize_relays(legacy), legacy)
        self.assertEqual(legacy, {"countries": [{"code": "se"}]})

    def test_unknown_format(self):
        self.assertEqual(normalize_relays({"foo": 1}), {"foo": 1})


if __name__ == "__main__":
    unittest.main()
