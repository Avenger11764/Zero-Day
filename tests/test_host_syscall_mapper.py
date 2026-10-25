import unittest

from detection.host_syscall_mapper import (
    classify_host_syscalls,
    enrich_scored_alert,
)


class HostSyscallMapperTests(unittest.TestCase):
    def classify(self, records, score=0.8, threshold=0.5, features=None):
        return classify_host_syscalls(
            records,
            host_anomaly_score=score,
            threshold=threshold,
            host_features=features,
        )

    def test_below_threshold_does_not_emit_candidates(self):
        result = self.classify([{"syscall": "ptrace"}], score=0.5)
        self.assertEqual(result["host_mapping_status"], "below_threshold")
        self.assertEqual(result["host_attack_mappings"], [])

    def test_ptrace_without_memory_read_is_incomplete_candidate(self):
        result = self.classify([{"syscall": "ptrace", "pid": 100, "args": {"pid": 200}}])
        mapping = result["host_attack_mappings"][0]
        self.assertEqual(mapping["technique_id"], "T1055.008")
        self.assertFalse(mapping["evidence_complete"])

    def test_ptrace_and_memory_read_for_same_target_are_candidate(self):
        records = [
            {"syscall": "ptrace", "pid": 100, "args": {"pid": 200}},
            {"syscall": "process_vm_readv", "pid": 100, "args": {"pid": 200}},
        ]
        result = self.classify(records, features={"sec_ptrace_flag": 1.0})
        mapping = result["host_attack_mappings"][0]
        self.assertEqual(mapping["technique_id"], "T1055.008")
        self.assertTrue(mapping["evidence_complete"])
        self.assertEqual(mapping["matched_features"]["sec_ptrace_flag"], 1.0)

    def test_different_ptrace_targets_do_not_complete_signature(self):
        records = [
            {"syscall": "ptrace", "pid": 100, "args": {"pid": 200}},
            {"syscall": "process_vm_readv", "pid": 100, "args": {"pid": 201}},
        ]
        mapping = self.classify(records)["host_attack_mappings"][0]
        self.assertFalse(mapping["evidence_complete"])

    def test_lsass_dump_requires_process_target_and_dump_event(self):
        records = [
            {
                "event_name": "OpenProcess",
                "pid": 5,
                "args": {"target_process": "C:\\Windows\\System32\\lsass.exe"},
            },
            {"event_name": "MiniDumpWriteDump", "pid": 5},
        ]
        result = self.classify(records)
        self.assertEqual(result["host_attack_mappings"][0]["technique_id"], "T1003.001")

    def test_registry_run_key_requires_value_data(self):
        record = {
            "event_name": "RegSetValue",
            "args": {
                "registry_path": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                "value_data": "updater.exe",
            },
        }
        result = self.classify([record])
        self.assertEqual(result["host_attack_mappings"][0]["technique_id"], "T1547.001")

    def test_setuid_to_root_from_non_root_is_candidate(self):
        record = {"syscall": "setuid", "uid": 1000, "args": {"uid": 0}}
        mapping = self.classify([record])["host_attack_mappings"][0]
        self.assertEqual(mapping["technique_id"], "T1548.001")
        self.assertTrue(mapping["evidence_complete"])

    def test_openat_alone_never_maps_to_ransomware(self):
        result = self.classify([{"syscall": "openat"}])
        ids = [mapping["technique_id"] for mapping in result["host_attack_mappings"]]
        self.assertNotIn("T1486", ids)
        self.assertIn("T1486", result["host_explanation"][-1])

    def test_enrichment_preserves_existing_network_alert_fields(self):
        alert = {"alert_id": "alert-1", "mitre_technique": "T1046"}
        enriched = enrich_scored_alert(
            alert,
            [{"syscall": "init_module", "args": {"umod": "module"}}],
            host_anomaly_score=0.8,
            threshold=0.5,
        )
        self.assertEqual(enriched["alert_id"], "alert-1")
        self.assertEqual(enriched["mitre_technique"], "T1046")
        self.assertEqual(enriched["host_attack_mappings"][0]["technique_id"], "T1547.006")
        self.assertFalse(enriched["host_attack_mappings"][0]["evidence_complete"])

    def test_mapping_evidence_does_not_echo_host_identifiers_or_paths(self):
        records = [
            {
                "event_name": "RegSetValue",
                "args": {
                    "registry_path": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                    "value_data": r"C:\Users\private\updater.exe",
                },
            },
            {"syscall": "init_module", "args": {"module_name": "private-module.ko"}},
        ]

        result = self.classify(records)
        serialized = str(result)

        self.assertNotIn("HKCU", serialized)
        self.assertNotIn("private", serialized)
        self.assertNotIn("updater.exe", serialized)


if __name__ == "__main__":
    unittest.main()
