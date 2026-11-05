"""Contract and regression tests for the multi-target-only review service."""

import base64
import tempfile
import unittest
import uuid
from pathlib import Path
from xml.etree import ElementTree as ET

import controller

TARGET_A = "11111111-1111-4111-8111-111111111111"
TARGET_B = "11111111-1111-4111-8111-111111111112"
PORTS = "22222222-2222-4222-8222-222222222222"
CREDENTIAL = "33333333-3333-4333-8333-333333333333"
CONFIG = "55555555-5555-4555-8555-555555555555"
SCANNER = "66666666-6666-4666-8666-666666666666"
TASK_A = "88888888-8888-4888-8888-888888888888"
TASK_B = "99999999-9999-4999-8999-999999999999"
REPORT_A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
REPORT_B = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"


class FakeGmp:
    def get_targets(self, **_):
        return '<get_targets_response status="200"/>'

    def get_credentials(self, **_):
        return '<get_credentials_response status="200"/>'

    def get_scan_configs(self, **_):
        return f'<get_configs_response status="200"><config id="{CONFIG}"/></get_configs_response>'

    def get_scanners(self, **_):
        return f'<get_scanners_response status="200"><scanner id="{SCANNER}"/></get_scanners_response>'

    def get_target(self, target_id):
        hosts = "192.0.2.1,192.0.2.2,192.0.2.3" if target_id == TARGET_A else "192.0.2.4,192.0.2.5,192.0.2.6"
        return (f'<get_targets_response status="200"><target id="{target_id}">'
                f'<name>{"A" if target_id == TARGET_A else "B"}</name>'
                f'<hosts>{hosts}</hosts><port_list id="{PORTS}"/>'
                f'<ssh_credential id="{CREDENTIAL}"><port>22</port></ssh_credential>'
                '</target></get_targets_response>')


class CompletedGmp:
    def get_task(self, task_id):
        report_id = REPORT_A if task_id == TASK_A else REPORT_B
        return (f'<get_tasks_response status="200"><task id="{task_id}">'
                f'<status>Done</status><last_report><report id="{report_id}"/>'
                '</last_report></task></get_tasks_response>')

    def get_results(self, **_):
        return ('<get_results_response status="200">'
                '<result_count><filtered>0</filtered></result_count>'
                '</get_results_response>')


class Tests(unittest.TestCase):
    def request(self):
        return {"name": "Six hosts", "target_ids": [TARGET_A, TARGET_B],
                "config_id": CONFIG, "scanner_id": SCANNER}

    def test_six_hosts_are_two_scan_units(self):
        plan = controller.build_plan(FakeGmp(), self.request())
        self.assertEqual(len(plan["units"]), 6)
        self.assertEqual([unit["hosts"] for unit in plan["scan_units"]],
                         [["192.0.2.1", "192.0.2.2", "192.0.2.3"], ["192.0.2.4", "192.0.2.5", "192.0.2.6"]])
        targets = [ET.fromstring(controller.target_xml("group", unit))
                   for unit in plan["scan_units"]]
        self.assertEqual([target.findtext("hosts") for target in targets],
                         ["192.0.2.1,192.0.2.2,192.0.2.3", "192.0.2.4,192.0.2.5,192.0.2.6"])
        self.assertTrue(all(target.find("ssh_credential").get("id") == CREDENTIAL
                            for target in targets))

    def test_override_request_is_rejected_in_this_tier(self):
        request = self.request()
        request["overrides"] = [{"host": "192.0.2.3", "service": "ssh", "credential_id": CREDENTIAL}]
        with self.assertRaisesRegex(controller.ReviewError, "combined feature tier"):
            controller.build_plan(FakeGmp(), request)

    def test_create_group_creates_two_children(self):
        class CreatingGmp:
            targets = []
            tasks = []

            def send_command(self, command):
                self.targets.append(ET.fromstring(command).findtext("hosts"))
                return (f'<create_target_response status="201" '
                        f'id="{uuid.UUID(int=len(self.targets))}"/>')

            def create_task(self, **kwargs):
                self.tasks.append(kwargs)
                return (f'<create_task_response status="201" '
                        f'id="{uuid.UUID(int=100 + len(self.tasks))}"/>')

        plan = controller.build_plan(FakeGmp(), self.request())
        gmp = CreatingGmp()
        original_db = controller.DB
        original_create_native_task = controller.create_native_task
        with tempfile.TemporaryDirectory() as directory:
            controller.DB = Path(directory) / "groups.sqlite"
            controller.create_native_task = lambda *_: SCANNER
            try:
                controller.init_db()
                group = controller.create_group(gmp, plan)
                self.assertEqual(len(group["children"]), 2)
                self.assertEqual(gmp.targets, ["192.0.2.1,192.0.2.2,192.0.2.3", "192.0.2.4,192.0.2.5,192.0.2.6"])
                self.assertEqual(len(gmp.tasks), 2)
            finally:
                controller.DB = original_db
                controller.create_native_task = original_create_native_task

    def test_dns_source_is_rejected_before_scheduling(self):
        class DnsGmp(FakeGmp):
            def get_target(self, target_id):
                return super().get_target(target_id).replace(
                    "192.0.2.1,192.0.2.2,192.0.2.3",
                    "scan.example.test,192.0.2.2,192.0.2.3")

        with self.assertRaisesRegex(controller.ReviewError, "DNS source host"):
            controller.build_plan(DnsGmp(), self.request())

    def test_proxy_requires_operator_credentials_and_gsad_session(self):
        class Request:
            def __init__(self, headers):
                self.headers = headers
                self.status = None

            def send_response(self, status):
                self.status = status

            def send_header(self, *_):
                pass

            def end_headers(self):
                pass

        original = (controller.USERNAME, controller.PASSWORD,
                    controller.TRUST_GSA_PROXY)
        try:
            controller.TRUST_GSA_PROXY = True
            controller.USERNAME = "operator"
            controller.PASSWORD = "review-secret"
            valid = "Basic " + base64.b64encode(b"operator:review-secret").decode()
            for headers in ({"X-Review-Authenticated": "1"},
                            {"X-Review-Operator-Authorization": valid}):
                request = Request(headers)
                self.assertFalse(controller.Handler._authorized(request))
                self.assertEqual(request.status, 401)
            self.assertTrue(controller.Handler._authorized(Request({
                "X-Review-Authenticated": "1",
                "X-Review-Operator-Authorization": valid})))
            controller.PASSWORD = ""
            request = Request({"X-Review-Authenticated": "1",
                               "X-Review-Operator-Authorization": valid})
            self.assertFalse(controller.Handler._authorized(request))
            self.assertEqual(request.status, 503)
        finally:
            controller.USERNAME, controller.PASSWORD, controller.TRUST_GSA_PROXY = original

    def test_failed_restart_cannot_mix_reports_or_export(self):
        class PartialGmp(CompletedGmp):
            def start_task(self, task_id):
                if task_id == TASK_B:
                    raise controller.ReviewError("Second child failed")
                return (f'<start_task_response status="202"><report_id>'
                        f'{REPORT_A}</report_id></start_task_response>')

        children = [
            {"host": "192.0.2.1", "task_id": TASK_A, "target_id": TARGET_A},
            {"host": "192.0.2.4", "task_id": TASK_B, "target_id": TARGET_B},
        ]
        original_db = controller.DB
        with tempfile.TemporaryDirectory() as directory:
            controller.DB = Path(directory) / "groups.sqlite"
            try:
                controller.init_db()
                controller.save_group(TARGET_A, {"name": "Review"}, children,
                                      SCANNER)
                gmp = PartialGmp()
                result = controller.start_group(
                    gmp, controller.group_by_id(TARGET_A))
                self.assertEqual(len(result["failed"]), 1)
                group = controller.group_by_id(TARGET_A)
                self.assertEqual(group["run_state"]["state"], "failed")
                self.assertIsNone(controller.publish_native_report(gmp, group))
                self.assertFalse(controller.group_report(gmp, group)["complete"])
                with self.assertRaisesRegex(controller.ReviewError, "incomplete"):
                    controller.group_report_csv(gmp, group)
            finally:
                controller.DB = original_db

    def test_empty_source_report_is_valid_but_missing_child_is_not(self):
        class EmptyGmp(CompletedGmp):
            imported = ""

            def get_report(self, report_id, **_):
                host = "192.0.2.4" if report_id == REPORT_B else None
                host_xml = f'<host><ip>{host}</ip></host>' if host else ''
                results_xml = (f'<result id="{TASK_B}"><host>{host}</host></result>'
                               if host else '')
                return (f'<get_reports_response status="200"><report><report>'
                        f'<scan_start>2026-10-16T01:00:00Z</scan_start>{host_xml}'
                        f'<results>{results_xml}</results>'
                        f'<scan_end>2026-10-16T01:01:00Z</scan_end>'
                        '</report></report></get_reports_response>')

            def send_command(self, command):
                self.imported = command
                return f'<create_report_response status="201" id="{REPORT_A}"/>'

        children = [
            {"host": "192.0.2.1", "task_id": TASK_A, "target_id": TARGET_A},
            {"host": "192.0.2.4", "task_id": TASK_B, "target_id": TARGET_B},
        ]
        original_db = controller.DB
        with tempfile.TemporaryDirectory() as directory:
            controller.DB = Path(directory) / "groups.sqlite"
            try:
                controller.init_db()
                controller.save_group(TARGET_A, {"name": "Review"}, children,
                                      SCANNER)
                gmp = EmptyGmp()
                self.assertIsNotNone(controller.publish_native_report(
                    gmp, controller.group_by_id(TARGET_A)))
                self.assertEqual(len(ET.fromstring(gmp.imported).findall(
                    "./report/results/result")), 1)

                class MissingGmp(CompletedGmp):
                    def get_task(self, task_id):
                        if task_id == TASK_B:
                            return (f'<get_tasks_response status="200"><task id="{task_id}">'
                                    '<status>Done</status></task></get_tasks_response>')
                        return super().get_task(task_id)

                missing = controller.group_report(
                    MissingGmp(), controller.group_by_id(TARGET_A))
                self.assertFalse(missing["complete"])
                with self.assertRaisesRegex(controller.ReviewError, "incomplete"):
                    controller.group_report_csv(
                        MissingGmp(), controller.group_by_id(TARGET_A))
            finally:
                controller.DB = original_db


    def test_current_run_rejects_previous_report_ids(self):
        original_db = controller.DB
        with tempfile.TemporaryDirectory() as directory:
            controller.DB = Path(directory) / "groups.sqlite"
            try:
                controller.init_db()
                children = [{"host": "192.0.2.1", "task_id": TASK_A,
                             "target_id": TARGET_A}]
                controller.save_group(TARGET_A,
                                      {"name": "Review"}, children, SCANNER)
                controller.save_run_state(TARGET_A, {
                    "id": str(uuid.uuid4()), "state": "active",
                    "reports": {TASK_A: "00000000-0000-4000-8000-000000000001"},
                    "failed": []})
                group = controller.group_by_id(TARGET_A)
                summary = controller.group_summary(CompletedGmp(), group)
                self.assertNotEqual(summary["status"], "Done")
                self.assertEqual(summary["report_count"], 0)
                self.assertEqual(summary["done_count"], 0)
                self.assertIsNone(controller.publish_native_report(
                    CompletedGmp(), group))
            finally:
                controller.DB = original_db


if __name__ == "__main__":
    unittest.main()
