"""Snort scanning test suite"""

import os

from azul_runner import FV, Event, JobResult, State, test_template

from azul_plugin_suricata.main import AzulPluginSuricata

config = {"security_override": "OFFICIAL", "rules_path": os.path.join(os.path.dirname(__file__), "data/rules")}


class TestExecute(test_template.TestPlugin):
    PLUGIN_TO_TEST = AzulPluginSuricata
    PLUGIN_TO_TEST_CONFIG = config

    def test_snort_alerts(self):
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "a9bf0b6c9125c181969c1e68718f1ad68bf7f091d5f115fb4089c983273e0e5d", "Benign PCAP."
                    ),
                )
            ],
            config=config,
        )
        # split out list access to show any empty list errors
        print(result)

        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        sha256="a9bf0b6c9125c181969c1e68718f1ad68bf7f091d5f115fb4089c983273e0e5d",
                        parent_sha256="a9bf0b6c9125c181969c1e68718f1ad68bf7f091d5f115fb4089c983273e0e5d",
                        features={
                            "network_signature_id": [FV("666")],
                            "network_signature_message": [FV("LOOPBACK - localhost connections", label="666")],
                        },
                        info={
                            "network_alerts": [
                                {
                                    "timestamp": "2015-01-30T14:49:01.890849+0000",
                                    "pcap_cnt": 1,
                                    "src_ip": "127.0.0.1",
                                    "src_port": 47261,
                                    "dest_ip": "127.0.0.1",
                                    "dest_port": 110,
                                    "proto": "TCP",
                                    "pkt_src": "wire/pcap",
                                    "alert": {
                                        "gid": 1,
                                        "signature_id": 666,
                                        "rev": 1,
                                        "signature": "LOOPBACK - localhost connections",
                                        "category": "",
                                        "severity": 3,
                                    },
                                    "direction": "to_server",
                                    "flow": {
                                        "pkts_toserver": 1,
                                        "pkts_toclient": 0,
                                        "bytes_toserver": 74,
                                        "bytes_toclient": 0,
                                        "start": "2015-01-30T14:49:01.890849+0000",
                                        "src_ip": "127.0.0.1",
                                        "dest_ip": "127.0.0.1",
                                        "src_port": 47261,
                                        "dest_port": 110,
                                    },
                                },
                                {
                                    "timestamp": "2015-01-30T14:49:01.890849+0000",
                                    "pcap_cnt": 1,
                                    "src_ip": "127.0.0.1",
                                    "src_port": 47261,
                                    "dest_ip": "127.0.0.1",
                                    "dest_port": 110,
                                    "proto": "TCP",
                                    "pkt_src": "wire/pcap",
                                    "alert": {
                                        "gid": 1,
                                        "signature_id": 666,
                                        "rev": 1,
                                        "signature": "LOOPBACK - localhost connections",
                                        "category": "",
                                        "severity": 3,
                                    },
                                    "direction": "to_server",
                                    "flow": {
                                        "pkts_toserver": 1,
                                        "pkts_toclient": 0,
                                        "bytes_toserver": 74,
                                        "bytes_toclient": 0,
                                        "start": "2015-01-30T14:49:01.890849+0000",
                                        "src_ip": "127.0.0.1",
                                        "dest_ip": "127.0.0.1",
                                        "src_port": 47261,
                                        "dest_port": 110,
                                    },
                                },
                                {
                                    "timestamp": "2063-10-25T12:49:34.640128+0000",
                                    "pcap_cnt": 2,
                                    "src_ip": "127.0.0.1",
                                    "src_port": 110,
                                    "dest_ip": "127.0.0.1",
                                    "dest_port": 47261,
                                    "proto": "TCP",
                                    "pkt_src": "wire/pcap",
                                    "alert": {
                                        "gid": 1,
                                        "signature_id": 666,
                                        "rev": 1,
                                        "signature": "LOOPBACK - localhost connections",
                                        "category": "",
                                        "severity": 3,
                                    },
                                    "direction": "to_server",
                                    "flow": {
                                        "pkts_toserver": 1,
                                        "pkts_toclient": 0,
                                        "bytes_toserver": 74,
                                        "bytes_toclient": 0,
                                        "start": "2063-10-25T12:49:34.640128+0000",
                                        "src_ip": "127.0.0.1",
                                        "dest_ip": "127.0.0.1",
                                        "src_port": 110,
                                        "dest_port": 47261,
                                    },
                                },
                                {
                                    "timestamp": "2063-10-25T12:49:34.640128+0000",
                                    "pcap_cnt": 2,
                                    "src_ip": "127.0.0.1",
                                    "src_port": 110,
                                    "dest_ip": "127.0.0.1",
                                    "dest_port": 47261,
                                    "proto": "TCP",
                                    "pkt_src": "wire/pcap",
                                    "alert": {
                                        "gid": 1,
                                        "signature_id": 666,
                                        "rev": 1,
                                        "signature": "LOOPBACK - localhost connections",
                                        "category": "",
                                        "severity": 3,
                                    },
                                    "direction": "to_server",
                                    "flow": {
                                        "pkts_toserver": 1,
                                        "pkts_toclient": 0,
                                        "bytes_toserver": 74,
                                        "bytes_toclient": 0,
                                        "start": "2063-10-25T12:49:34.640128+0000",
                                        "src_ip": "127.0.0.1",
                                        "dest_ip": "127.0.0.1",
                                        "src_port": 110,
                                        "dest_port": 47261,
                                    },
                                },
                                {
                                    "timestamp": "2015-01-30T14:49:01.890932+0000",
                                    "pcap_cnt": 3,
                                    "src_ip": "127.0.0.1",
                                    "src_port": 47261,
                                    "dest_ip": "127.0.0.1",
                                    "dest_port": 110,
                                    "proto": "TCP",
                                    "pkt_src": "wire/pcap",
                                    "alert": {
                                        "gid": 1,
                                        "signature_id": 666,
                                        "rev": 1,
                                        "signature": "LOOPBACK - localhost connections",
                                        "category": "",
                                        "severity": 3,
                                    },
                                    "direction": "to_client",
                                    "flow": {
                                        "pkts_toserver": 1,
                                        "pkts_toclient": 1,
                                        "bytes_toserver": 74,
                                        "bytes_toclient": 66,
                                        "start": "2063-10-25T12:49:34.640128+0000",
                                        "src_ip": "127.0.0.1",
                                        "dest_ip": "127.0.0.1",
                                        "src_port": 110,
                                        "dest_port": 47261,
                                    },
                                },
                                {
                                    "timestamp": "2015-01-30T14:49:01.890932+0000",
                                    "pcap_cnt": 3,
                                    "src_ip": "127.0.0.1",
                                    "src_port": 47261,
                                    "dest_ip": "127.0.0.1",
                                    "dest_port": 110,
                                    "proto": "TCP",
                                    "pkt_src": "wire/pcap",
                                    "alert": {
                                        "gid": 1,
                                        "signature_id": 666,
                                        "rev": 1,
                                        "signature": "LOOPBACK - localhost connections",
                                        "category": "",
                                        "severity": 3,
                                    },
                                    "direction": "to_client",
                                    "flow": {
                                        "pkts_toserver": 1,
                                        "pkts_toclient": 1,
                                        "bytes_toserver": 74,
                                        "bytes_toclient": 66,
                                        "start": "2063-10-25T12:49:34.640128+0000",
                                        "src_ip": "127.0.0.1",
                                        "dest_ip": "127.0.0.1",
                                        "src_port": 110,
                                        "dest_port": 47261,
                                    },
                                },
                            ]
                        },
                    )
                ],
            ),
        )
