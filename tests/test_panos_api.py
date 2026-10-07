#!/usr/bin/env python3
"""tests/test_panos_api.py -- unit tests for the pure functions in
panos_api.py (no network needed).

Run:  python3 -m unittest -v tests.test_panos_api
"""

import os
import sys
import unittest
import xml.dom.minidom

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from panos_api import (check_read_only, cli_to_xml,  # noqa: E402
                       normalize_empty_elements)


class TestCliToXml(unittest.TestCase):

    def test_three_tokens(self):
        self.assertEqual(cli_to_xml("show system info"),
                         "<show><system><info/></system></show>")

    def test_four_tokens(self):
        self.assertEqual(cli_to_xml("show config running"),
                         "<show><config><running/></config></show>")

    def test_two_tokens(self):
        self.assertEqual(cli_to_xml("show version"), "<show><version/></show>")

    def test_one_token(self):
        self.assertEqual(cli_to_xml("commit"), "<commit/>")

    def test_bad_token(self):
        with self.assertRaises(ValueError):
            cli_to_xml("show system info=1")

    def test_empty(self):
        with self.assertRaises(ValueError):
            cli_to_xml("")

    def test_always_well_formed(self):
        # regression guard: a missing closing tag is exactly the bug that
        # 400s on the device ("Request is not a valid XML")
        for cmd in ("show", "show version", "show system info",
                    "show config running", "show system resources",
                    "commit"):
            with self.subTest(cmd=cmd):
                xml.dom.minidom.parseString(cli_to_xml(cmd))


class TestNormalizeEmptyElements(unittest.TestCase):

    def test_paired_empty(self):
        self.assertEqual(
            normalize_empty_elements(
                "<show><system><status></status></system></show>"),
            "<show><system><status/></system></show>")

    def test_already_self_closing_untouched(self):
        s = "<show><system><info/></system></show>"
        self.assertEqual(normalize_empty_elements(s), s)

    def test_nested_paired(self):
        self.assertEqual(normalize_empty_elements("<a><b></b><c></c></a>"),
                         "<a><b/><c/></a>")

    def test_with_attributes(self):
        self.assertEqual(normalize_empty_elements('<entry name="x"></entry>'),
                         '<entry name="x"/>')

    def test_content_not_touched(self):
        s = "<a><b>text</b></a>"
        self.assertEqual(normalize_empty_elements(s), s)

    def test_nested_same_name(self):
        self.assertEqual(normalize_empty_elements("<a><a></a></a>"),
                         "<a><a/></a>")


class TestReadOnlyGuard(unittest.TestCase):

    def test_read_ok(self):
        check_read_only("<show><system><info/></system></show>", False)

    def test_config_read_ok(self):
        check_read_only("<show><config><running/></config></show>", False)

    def test_commit_refused(self):
        with self.assertRaises(SystemExit):
            check_read_only("<commit/>", False)

    def test_set_refused(self):
        with self.assertRaises(SystemExit):
            check_read_only("<set><address>x</address></set>", False)

    def test_settings_not_matched_by_set(self):
        # '<settings>' must not trigger the 'set' verb check
        check_read_only("<show><settings/></show>", False)

    def test_allow_write_overrides(self):
        check_read_only("<commit/>", True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
