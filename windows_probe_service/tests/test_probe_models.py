"""Offline compatibility and hostile-input checks for the pure Python API models."""
from __future__ import annotations

from dataclasses import FrozenInstanceError
import json
from pathlib import Path
import sys
import unittest

SERVICE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SERVICE_DIR))
from probe_models import (DEFAULT_PING_COUNT, DEFAULT_PROBE_TIMEOUT_MS, DEFAULT_TCP_ATTEMPTS,
                          MAX_TARGETS, ProbeBatch, ProbeTarget, ValidationError, normalize_host)


PUBLIC = "93.184.216.34"


def batch(**changes):
    payload = {"queryId": "q1", "targets": [{"id": "t1", "host": PUBLIC}]}
    payload.update(changes)
    return ProbeBatch(**payload)


class TargetValidationTests(unittest.TestCase):
    def test_default_port_and_json_contract(self):
        self.assertEqual(ProbeTarget(id="t1", host=PUBLIC).model_dump(), {"id": "t1", "host": PUBLIC, "port": None})
        self.assertEqual(ProbeTarget(id="t1", host=PUBLIC, port=65535).port, 65535)
        self.assertEqual(ProbeTarget(id="t1", host=PUBLIC, port=1).port, 1)

    def test_required_and_unknown_fields(self):
        for payload in [{}, {"id": "t1"}, {"host": PUBLIC}, {"id": "t1", "host": PUBLIC, "command": "ping"}]:
            with self.subTest(payload=payload), self.assertRaises(ValidationError):
                ProbeTarget(**payload)

    def test_id_is_a_strict_bounded_string_without_added_trimming(self):
        self.assertEqual(ProbeTarget(id=" " * 160, host=PUBLIC).id, " " * 160)
        for value in [None, True, 1, 1.0, b"t1", [], {}, "", "x" * 161]:
            with self.subTest(value=value), self.assertRaises(ValidationError):
                ProbeTarget(id=value, host=PUBLIC)

    def test_host_is_a_strict_bounded_string(self):
        for value in [None, True, 1, 1.0, b"example.com", [], {}, "", "a" * 254, " " * 254 + PUBLIC]:
            with self.subTest(value=value), self.assertRaises(ValidationError):
                ProbeTarget(id="t1", host=value)

    def test_port_never_coerces_non_integer_values(self):
        for value in [False, True, "443", 443.0, float("nan"), float("inf"), -float("inf"), 0, -1, 65536, [], {}]:
            with self.subTest(value=value), self.assertRaises(ValidationError):
                ProbeTarget(id="t1", host=PUBLIC, port=value)

    def test_hostname_normalization_preserves_idna_and_ip_behavior(self):
        cases = {" EXAMPLE.COM. ": "example.com", "例子.测试": "xn--fsqu00a.xn--0zwm56d",
                 "[93.184.216.34]": PUBLIC, "[2001:DB8::1]": "2001:db8::1"}
        for host, expected in cases.items():
            with self.subTest(host=host):
                self.assertEqual(normalize_host(host), expected)
                self.assertEqual(ProbeTarget(id="t1", host=host).host, expected)

    def test_full_length_dns_name_and_label_boundaries(self):
        host = ".".join(["a" * 63, "b" * 63, "c" * 63, "d" * 61])
        self.assertEqual(len(host), 253)
        self.assertEqual(ProbeTarget(id="t1", host=host).host, host)
        for value in ["a" * 64 + ".com", "-bad.example", "bad-.example", "bad..example", "example_com.test"]:
            with self.subTest(value=value), self.assertRaises(ValidationError):
                ProbeTarget(id="t1", host=value)

    def test_command_url_and_numeric_pseudo_ip_input_rejected(self):
        for value in ["1.2.3.4;whoami", "https://example.com", "example.com/path", "user@example.com", "example.com:443",
                      "example.com\nwhoami", "example.com\twhoami", "a b.example", "$(whoami).example", "foo|bar.example",
                      "example.com?x=y", "example.com#hash", "example.com%20", "1234", "0177.0.0.1", "127.1", "0x7f000001",
                      "0xabc.example", "localhost", "..."]:
            with self.subTest(value=value), self.assertRaises(ValidationError):
                ProbeTarget(id="t1", host=value)

    def test_model_validate_requires_an_object_and_revalidates_instances(self):
        target = ProbeTarget(id="t1", host="EXAMPLE.COM", port=443)
        self.assertEqual(ProbeTarget.model_validate(target), target)
        self.assertIsNot(ProbeTarget.model_validate(target), target)
        for value in [None, True, [], [("id", "t1"), ("host", PUBLIC)], "{}"]:
            with self.subTest(value=value), self.assertRaises(ValidationError):
                ProbeTarget.model_validate(value)

    def test_validated_target_attributes_cannot_be_reassigned(self):
        target = ProbeTarget(id="t1", host=PUBLIC)
        with self.assertRaises(FrozenInstanceError):
            target.port = "443"


class BatchValidationTests(unittest.TestCase):
    def test_json_round_trip_includes_original_api_defaults(self):
        payload = {"queryId": "q1", "targets": [{"id": "t1", "host": PUBLIC, "port": None}],
                   "excludedHosts": [], "excludedCidrs": [], "dnsServers": ["8.8.8.8", "223.5.5.5", "223.6.6.6", "180.76.76.76"],
                   "pingCount": 5, "tcpAttempts": 3, "timeoutMs": 3000}
        self.assertEqual(batch().model_dump(), payload)
        self.assertEqual(ProbeBatch.model_validate(json.loads(json.dumps(payload))).model_dump(), payload)

    def test_probe_attempt_defaults_and_strict_bounds(self):
        parsed = batch()
        self.assertEqual(parsed.pingCount, DEFAULT_PING_COUNT)
        self.assertEqual(parsed.tcpAttempts, DEFAULT_TCP_ATTEMPTS)
        self.assertEqual(parsed.timeoutMs, DEFAULT_PROBE_TIMEOUT_MS)
        custom = batch(pingCount=1, tcpAttempts=10, timeoutMs=200)
        self.assertEqual((custom.pingCount, custom.tcpAttempts, custom.timeoutMs), (1, 10, 200))
        for changes in ({"pingCount": 0}, {"pingCount": 11}, {"pingCount": True},
                        {"tcpAttempts": 0}, {"tcpAttempts": 11}, {"tcpAttempts": "3"},
                        {"timeoutMs": 199}, {"timeoutMs": 10001}, {"timeoutMs": 30.0},
                        {"timeoutMs": False}):
            with self.subTest(changes=changes), self.assertRaises(ValidationError):
                batch(**changes)

    def test_query_id_is_required_strict_and_bounded(self):
        self.assertEqual(batch(queryId="q" * 160).queryId, "q" * 160)
        for value in [None, True, 1, 1.0, b"q1", [], {}, "", "q" * 161]:
            with self.subTest(value=value), self.assertRaises(ValidationError):
                batch(queryId=value)
        with self.assertRaises(ValidationError):
            ProbeBatch(targets=[{"id": "t1", "host": PUBLIC}])

    def test_required_targets_unknown_fields_and_nested_unknown_fields(self):
        for payload in [{"queryId": "q1"}, {"queryId": "q1", "targets": [], "unknown": True}]:
            with self.subTest(payload=payload), self.assertRaises(ValidationError):
                ProbeBatch(**payload)
        with self.assertRaises(ValidationError) as caught:
            batch(targets=[{"id": "t1", "host": PUBLIC, "options": {"port": 443}}])
        self.assertEqual(caught.exception.errors()[0]["loc"], ("targets", 0, "options"))

    def test_target_list_is_strict_and_bounded_before_deduplication(self):
        for value in [None, True, {}, (), iter([]), "targets", []]:
            with self.subTest(value=repr(value)), self.assertRaises(ValidationError):
                batch(targets=value)
        targets = [{"id": str(index), "host": PUBLIC} for index in range(MAX_TARGETS)]
        self.assertEqual(len(batch(targets=targets).targets), MAX_TARGETS)
        with self.assertRaises(ValidationError):
            batch(targets=targets + [{"id": "overflow", "host": PUBLIC}])

    def test_target_items_must_be_objects_or_validated_targets(self):
        for value in [None, True, 1, [], "93.184.216.34"]:
            with self.subTest(value=value), self.assertRaises(ValidationError):
                batch(targets=[value])
        target = ProbeTarget(id="t1", host=PUBLIC, port=443)
        self.assertEqual(batch(targets=[target]).targets, [target])

    def test_duplicate_ids_rejected_for_dicts_instances_and_repeated_objects(self):
        target = ProbeTarget(id="same", host=PUBLIC)
        for targets in [[target, target], [target, {"id": "same", "host": "example.com"}],
                        [{"id": "same", "host": PUBLIC}, {"id": "same", "host": "example.com"}]]:
            with self.subTest(targets=targets), self.assertRaises(ValidationError):
                batch(targets=targets)

    def test_excluded_hosts_only_accept_canonical_ipv4_strings(self):
        self.assertEqual(batch(excludedHosts=[" 93.184.216.34 ", PUBLIC, "45.33.32.156"]).excludedHosts, [PUBLIC, "45.33.32.156"])
        for value in [None, True, {}, (), "93.184.216.34", [None], [True], [1234], ["::1"], ["example.com"], ["10.0.0.0/8"], ["0177.0.0.1"], [""]]:
            with self.subTest(value=value), self.assertRaises(ValidationError):
                batch(excludedHosts=value)

    def test_excluded_host_count_limit_applies_before_deduplication(self):
        self.assertEqual(batch(excludedHosts=[PUBLIC] * 200).excludedHosts, [PUBLIC])
        with self.assertRaises(ValidationError):
            batch(excludedHosts=[PUBLIC] * 201)

    def test_excluded_cidrs_only_accept_strict_ipv4_networks(self):
        self.assertEqual(batch(excludedCidrs=[" 93.184.216.34 ", PUBLIC + "/32", "93.184.216.0/24"]).excludedCidrs,
                         [PUBLIC + "/32", "93.184.216.0/24"])
        for value in [None, True, {}, (), "93.184.216.0/24", [None], [True], [1234], ["::1"], ["2001:db8::/32"],
                      ["93.184.216.1/24"], ["example.com"], ["invalid"], [""]]:
            with self.subTest(value=value), self.assertRaises(ValidationError):
                batch(excludedCidrs=value)

    def test_excluded_cidr_count_limit_applies_before_deduplication(self):
        self.assertEqual(batch(excludedCidrs=[PUBLIC] * 2048).excludedCidrs, [PUBLIC + "/32"])
        with self.assertRaises(ValidationError):
            batch(excludedCidrs=[PUBLIC] * 2049)

    def test_input_lists_dumped_lists_and_model_defaults_are_independent(self):
        targets, hosts, cidrs = [{"id": "t1", "host": PUBLIC}], [PUBLIC], [PUBLIC]
        value = batch(targets=targets, excludedHosts=hosts, excludedCidrs=cidrs)
        targets[0]["host"] = "changed.example"
        targets.clear()
        hosts.clear()
        cidrs.clear()
        dumped = value.model_dump()
        dumped["targets"][0]["host"] = "changed.example"
        dumped["excludedHosts"].clear()
        dumped["excludedCidrs"].clear()
        self.assertEqual(value.targets[0].host, PUBLIC)
        self.assertEqual(value.excludedHosts, [PUBLIC])
        self.assertEqual(value.excludedCidrs, [PUBLIC + "/32"])
        first, second = batch(), batch()
        first.excludedHosts.append(PUBLIC)
        first.excludedCidrs.append(PUBLIC + "/32")
        self.assertEqual(second.excludedHosts, [])
        self.assertEqual(second.excludedCidrs, [])

    def test_batch_factory_requires_object_and_revalidates_existing_instance(self):
        original = batch()
        self.assertEqual(ProbeBatch.model_validate(original).model_dump(), original.model_dump())
        for value in [None, True, [], "{}", 1234]:
            with self.subTest(value=value), self.assertRaises(ValidationError):
                ProbeBatch.model_validate(value)
        original.targets.append(original.targets[0])
        with self.assertRaises(ValidationError):
            ProbeBatch.model_validate(original)

    def test_validation_errors_are_safe_to_encode_and_preserve_nested_location(self):
        with self.assertRaises(ValidationError) as caught:
            batch(targets=[{"id": "t1", "host": PUBLIC, "port": "secret-value"}])
        details = caught.exception.errors()
        self.assertEqual(details[0]["loc"], ("targets", 0, "port"))
        self.assertNotIn("secret-value", json.dumps(details))
        details[0]["msg"] = "changed"
        self.assertNotEqual(caught.exception.errors()[0]["msg"], "changed")
        self.assertIsInstance(caught.exception, ValueError)


if __name__ == "__main__":
    unittest.main()
