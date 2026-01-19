"""Executes Suricata/Snort rules against packets in a Packet Capture file."""

import hashlib
import json
import os
import re
import shutil
import subprocess  # nosec: B404
import tempfile
from importlib import resources as impresources
from os.path import join

from azul_runner import (
    FV,
    BinaryPlugin,
    Feature,
    FeatureType,
    Job,
    State,
    add_settings,
    cmdline_run,
)

from . import config


class AzulPluginSuricata(BinaryPlugin):
    """Executes Suricata/Snort rules against packets in a Packet Capture file."""

    VERSION = "2025.03.19"
    SETTINGS = add_settings(
        filter_data_types={"*": ["network/tcpdump"]},
        subprocess_timeout=(int, 120),  # Seconds
        rules_path=(str, "rules"),
    )
    FEATURES = [
        Feature("network_signature_id", "Network IDS signature triggered by the sample", type=FeatureType.Integer),
        Feature(
            "network_signature_message", "Description or message for the triggered signature", type=FeatureType.String
        ),
    ]

    _COMMENT_LINES = re.compile("^[ \t]*#")

    def _prepare_rules(self) -> str:
        """Loads rules into memory for use by Suricata."""
        # We want to do this semi-frequently for gitsync - this is also fast enough that
        # we can do this each time
        output = ""

        rule_file_count = 0

        for root, _dirs, files in os.walk(self.cfg.rules_path):
            for file in files:
                if file.split(".")[-1].lower() in ["rules", "snort"]:
                    rule_file_count += 1
                    with open(join(root, file), "r") as rule_file:
                        for line in rule_file.readlines():
                            if self._COMMENT_LINES.match(line) is not None:
                                continue
                            output += line

                        output += "\n"

        self.logger.info("Loaded %d Snort/Suricata rule files", rule_file_count)

        return output

    def execute(self, job: Job):
        """Run the plugin."""
        pcap_data = job.get_all_data(file_format="network/tcpdump")

        if not pcap_data:
            # This is an error (in the dispatcher/cmdline_run),
            # since we asked for 'network/tcpdump' in our INPUT_CONTENT
            return State(label=State.Label.ERROR_EXCEPTION, message='job has no "network/tcpdump" streams')

        config_dir = impresources.files(config)

        rules = self._prepare_rules()

        with tempfile.NamedTemporaryFile("w+") as rule_file:
            rule_file.write(rules)
            rule_file.flush()

            for pcap in pcap_data:
                alerts = []

                with tempfile.TemporaryDirectory() as suricata_config_dir:
                    # Extract configuration files for use by Suricata - this is simpler to do
                    # on a per-PCAP basis due to needing to read/write to the current directory &
                    # wanting a clean state each time
                    for config_file in [
                        "suricata.yaml",
                        "classification.config",
                        "reference.config",
                        "threshold.config",
                    ]:
                        output_file = join(suricata_config_dir, config_file)

                        with (config_dir / config_file).open("r") as file_to_copy:
                            with open(output_file, "w") as file_to_save:
                                shutil.copyfileobj(file_to_copy, file_to_save)

                    # Run Suricata over the saved pcap
                    p = pcap.read()
                    pcap_hash = hashlib.sha256(p).hexdigest()
                    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=True) as tmp:
                        tmp.write(p)
                        tmp.flush()

                        command = ["suricata", "-c", "suricata.yaml", "-s", rule_file.name, "-r", tmp.name]

                        res: subprocess.CompletedProcess = subprocess.run(  # nosec: B603
                            args=command,
                            stdin=None,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            timeout=self.cfg.subprocess_timeout,
                            cwd=suricata_config_dir,
                            encoding="utf8",
                        )

                        print(res.stdout)

                        if res.returncode != 0:
                            return State(
                                State.Label.ERROR_EXCEPTION,
                                message=f"Unexpected error occurred when running rules: {res.stderr}",
                            )

                    # Parse the JSON output
                    with open(join(suricata_config_dir, "eve.json"), "r") as output_json:
                        for line in output_json.readlines():
                            event = json.loads(line)
                            if event["event_type"] == "alert":
                                del event["event_type"]
                                # We aren't an active network filter:
                                del event["alert"]["action"]
                                # Non-deterministic:
                                del event["flow_id"]
                                alerts.append(event)

                if len(alerts) == 0:
                    continue

                hits = []
                features = {}
                for x in alerts:
                    hits.append(x)

                    sig_id = x["alert"]["signature_id"]

                    features.setdefault("network_signature_id", set()).add(sig_id)
                    features.setdefault("network_signature_message", set()).add(
                        FV(x["alert"]["signature"], label=str(sig_id))
                    )

                e = self.get_data_event(pcap_hash)
                e.add_many_feature_values(features)
                e.add_info({"network_alerts": hits})


def main():
    """Plugin command-line entrypoint."""
    cmdline_run(plugin=AzulPluginSuricata)


if __name__ == "__main__":
    main()
