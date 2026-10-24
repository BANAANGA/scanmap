import io
import unittest
from unittest.mock import patch

from app.jobs import _default_gateway, _resolve_zmap_gateway_mac


class ZmapGatewayTest(unittest.TestCase):
    def test_default_gateway_reads_proc_route(self):
        routes = (
            "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n"
            "eth0 00000000 010013AC 0003 0 0 0 00000000 0 0 0\n"
        )
        with patch("builtins.open", return_value=io.StringIO(routes)):
            self.assertEqual(_default_gateway(None), ("172.19.0.1", "eth0"))

    def test_default_gateway_respects_interface(self):
        routes = (
            "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n"
            "eth0 00000000 010013AC 0003 0 0 0 00000000 0 0 0\n"
        )
        with patch("builtins.open", return_value=io.StringIO(routes)):
            self.assertIsNone(_default_gateway("eth1"))

    def test_resolves_gateway_from_arp_table(self):
        arp = (
            "IP address HW type Flags HW address Mask Device\n"
            "172.19.0.1 0x1 0x2 36:fb:fb:49:ad:bd * eth0\n"
        )
        with (
            patch("app.jobs._default_gateway", return_value=("172.19.0.1", "eth0")),
            patch("app.jobs.socket.socket") as udp_socket,
            patch("builtins.open", return_value=io.StringIO(arp)),
        ):
            self.assertEqual(
                _resolve_zmap_gateway_mac(),
                ("172.19.0.1", "36:fb:fb:49:ad:bd"),
            )
            udp_socket.return_value.__enter__.return_value.sendto.assert_called_once_with(
                b"\0", ("172.19.0.1", 9)
            )


if __name__ == "__main__":
    unittest.main()
