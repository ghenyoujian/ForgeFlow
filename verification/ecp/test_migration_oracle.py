"""Offline research cases; supplied bytes/rows are never authority or a Gate."""
import importlib.util
from pathlib import Path
import unittest

_spec = importlib.util.spec_from_file_location('p002_migration_oracle', Path(__file__).with_name('migration_oracle.py'))
o = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(o)

ABC = 'cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7'
CRLF = '8ee557dcc9f3af58365d6983e53a2eac981ef550d2ccc186a32cbf2d2ae0e7ddbfd3febce387e2f5c21c44f0546ae0b9'


def entry(name, raw=b'abc'):
    return {'name': name, 'sql': raw}


def row(version, description, checksum=ABC, success=True):
    return {'version': version, 'description': description, 'success': success, 'checksum_sha384': checksum}


class MigrationExpectationTests(unittest.TestCase):
    def test_simple_description_and_known_checksum(self):
        report = o.inventory([entry('0002_authority_hardening.sql')])
        item = report['forward'][0]
        self.assertEqual((item['version'], item['description'], item['direction'], item['sqlx_sha384']),
                         (2, 'authority hardening', 'simple', ABC))
        self.assertEqual((report['qualification'], report['product_gate_effect'], report['source_authentication']),
                         ('NOT_RUN', 'NONE', 'UNVERIFIED'))

    def test_raw_crlf_checksum_is_not_newline_normalized(self):
        item = o.inventory([entry('1_crlf.sql', b'A\r\nB')])['forward'][0]
        self.assertEqual(item['sqlx_sha384'], CRLF)
        self.assertEqual(item['bytes'], 4)

    def test_numeric_order_and_gapped_timestamp_do_not_allocate_version_range(self):
        v = 20260101000000
        result = o.inventory([entry(str(v)+'_new.sql'), entry('10_second.sql'), entry('2_first.sql')])
        self.assertEqual([x['version'] for x in result['forward']], [2, 10, v])

    def test_signed_i64_edge_versions_are_not_silently_changed(self):
        result = o.inventory([entry('-9223372036854775808_min.sql'), entry('+9223372036854775807_max.sql')])
        self.assertEqual([x['version'] for x in result['forward']], [-(2**63), 2**63-1])

    def test_zero_and_signed_zero_versions_are_duplicate_forward(self):
        with self.assertRaisesRegex(o.OracleInputError, 'AMBIGUOUS_FORWARD_VERSION'):
            o.inventory([entry('0_first.sql'), entry('-0_second.sql')])

    def test_version_out_of_i64_range_is_rejected(self):
        for name in ('9223372036854775808_x.sql', '-9223372036854775809_x.sql'):
            with self.subTest(name=name), self.assertRaisesRegex(o.OracleInputError, 'SQLX_VERSION_OUT_OF_RANGE'):
                o.inventory([entry(name)])

    def test_invalid_prefix_matching_sqlx_shape_is_not_silently_ignored(self):
        for name in ('x_description.sql', '١_description.sql', '_empty.sql'):
            with self.subTest(name=name), self.assertRaisesRegex(o.OracleInputError, 'INVALID_SQLX_VERSION_PREFIX'):
                o.inventory([entry(name)])

    def test_non_migration_files_are_accounted_for_and_ignored(self):
        report = o.inventory([entry('README', b'\xff'), entry('3_good.sql')])
        self.assertEqual([x['filename'] for x in report['ignored']], ['README'])
        self.assertEqual((report['inputs']['entries'], report['inputs']['bytes']), (2, 4))

    def test_invalid_utf8_sql_is_rejected(self):
        with self.assertRaisesRegex(o.OracleInputError, 'INVALID_SQL_UTF8'):
            o.inventory([entry('1_bad.sql', b'\xff')])

    def test_empty_or_only_down_denominator_rejected(self):
        for entries in ([], [entry('1_only.down.sql')]):
            with self.subTest(entries=entries), self.assertRaisesRegex(o.OracleInputError, 'NO_FORWARD_MIGRATIONS'):
                o.inventory(entries)

    def test_same_version_up_down_is_not_duplicate_forward(self):
        report = o.inventory([entry('0020_new_feature.up.sql'), entry('0020_new_feature.down.sql', b'other')])
        self.assertEqual((len(report['forward']), len(report['down']), report['policy_concerns']), (1, 1, []))
        self.assertEqual((report['forward'][0]['version'], report['forward'][0]['description']), (20, 'new feature'))
        self.assertEqual((report['forward'][0]['direction'], report['down'][0]['direction']), ('up', 'down'))

    def test_pair_description_difference_is_explicit_not_silently_accepted(self):
        report = o.inventory([entry('1_up_name.up.sql'), entry('1_down_name.down.sql')])
        self.assertEqual(report['policy_concerns'], [{'version': 1, 'reason': 'PAIR_DESCRIPTION_DIFFERENCE'}])

    def test_lone_up_warns_but_no_down_source_is_not_invented(self):
        report = o.inventory([entry('1_alone.up.sql')])
        self.assertEqual(report['down'], [])
        self.assertEqual(report['policy_concerns'], [{'version': 1, 'reason': 'UP_WITHOUT_DOWN'}])

    def test_orphan_down_is_conservative_policy_error(self):
        with self.assertRaisesRegex(o.OracleInputError, 'ORPHAN_DOWN_POLICY'):
            o.inventory([entry('1_forward.sql'), entry('2_orphan.down.sql')])

    def test_simple_plus_down_is_annotated(self):
        report = o.inventory([entry('1_same.sql'), entry('1_same.down.sql')])
        self.assertEqual(report['policy_concerns'], [{'version': 1, 'reason': 'SIMPLE_WITH_DOWN'}])

    def test_multiple_forward_or_down_versions_are_ambiguous(self):
        for values, code in [([entry('1_a.sql'), entry('1_b.up.sql')], 'AMBIGUOUS_FORWARD_VERSION'),
                             ([entry('1_a.up.sql'), entry('1_a.down.sql'), entry('01_b.down.sql')], 'AMBIGUOUS_DOWN_VERSION')]:
            with self.subTest(code=code), self.assertRaisesRegex(o.OracleInputError, code):
                o.inventory(values)

    def test_duplicate_filename_is_never_deduplicated(self):
        with self.assertRaisesRegex(o.OracleInputError, 'DUPLICATE_FILENAME'):
            o.inventory([entry('1_a.sql'), entry('1_a.sql')])

    def test_repeated_suffix_uses_sqlx_trim_end_matches(self):
        result = o.inventory([entry('3_feature.sql.sql')])
        self.assertEqual(result['forward'][0]['description'], 'feature')

    def test_no_transaction_is_exact_prefix(self):
        result = o.inventory([entry('1_yes.sql', b'-- no-transaction\nSELECT 1;'),
                              entry('2_no.sql', b' \n-- no-transaction\nSELECT 2;')])
        self.assertEqual([x['no_transaction'] for x in result['forward']], [True, False])

    def test_declared_match_is_never_product_qualification(self):
        result = o.compare([entry('1_test.sql')], [row(1, 'test')], source_complete_claim=True, row_complete_claim=True)
        self.assertEqual((result['state'], result['qualification'], result['product_gate_effect']), ('MATCH_DECLARED', 'NOT_RUN', 'NONE'))
        self.assertEqual((result['source_authentication'], result['database_authentication'], result['claim_authority']),
                         ('UNVERIFIED', 'UNVERIFIED', 'UNVERIFIED'))
        self.assertEqual((result['expected_forward_count'], result['observed_row_count']), (1, 1))

    def test_equal_counts_with_changed_inputs_have_distinct_content_labels(self):
        old = o.compare([entry('1_x.sql', b'abc')], [row(1, 'x', ABC)], source_complete_claim=True, row_complete_claim=True)
        new_checksum = '180c325cccb299e76ec6c03a5b5a7755af8ef499906dbf531f18d0ca509e4871b0805cac0f122b962d54badc6119f3cf'
        new = o.compare([entry('1_x.sql', b'def')], [row(1, 'x', new_checksum)], source_complete_claim=True, row_complete_claim=True)
        self.assertEqual((old['state'], new['state']), ('MATCH_DECLARED', 'MATCH_DECLARED'))
        self.assertNotEqual(old['expected_inventory_sha256'], new['expected_inventory_sha256'])
        self.assertNotEqual(old['observed_rows_sha256'], new['observed_rows_sha256'])

    def test_incomplete_match_is_inconclusive(self):
        for source, rows in ((False, True), (True, False), (False, False)):
            with self.subTest(source=source, rows=rows):
                result = o.compare([entry('1_test.sql')], [row(1, 'test')], source_complete_claim=source, row_complete_claim=rows)
                self.assertEqual(result['state'], 'INCONCLUSIVE')

    def test_incomplete_rows_do_not_confirm_missing_versions(self):
        result = o.compare([entry('1_test.sql')], [], source_complete_claim=False, row_complete_claim=False)
        self.assertEqual((result['state'], result['discrepancies']['missing_versions']), ('INCONCLUSIVE', []))
        self.assertEqual(result['unconfirmed']['possible_missing_versions'], [1])

    def test_incomplete_source_does_not_confirm_extra_versions(self):
        result = o.compare([entry('1_one.sql')], [row(1, 'one'), row(2, 'two')],
                           source_complete_claim=False, row_complete_claim=True)
        self.assertEqual(result['state'], 'INCONCLUSIVE')
        self.assertEqual(result['discrepancies']['extra_versions'], [])
        self.assertEqual(result['unconfirmed']['possible_extra_versions'], [2])

    def test_declared_complete_rows_confirm_missing_even_if_source_incomplete(self):
        result = o.compare([entry('1_one.sql')], [], source_complete_claim=False, row_complete_claim=True)
        self.assertEqual((result['state'], result['discrepancies']['missing_versions']), ('MISMATCH', [1]))
        self.assertEqual(result['unconfirmed']['possible_missing_versions'], [])

    def test_declared_complete_source_confirms_extra_even_if_rows_incomplete(self):
        result = o.compare([entry('1_one.sql')], [row(1, 'one'), row(2, 'two')],
                           source_complete_claim=True, row_complete_claim=False)
        self.assertEqual((result['state'], result['discrepancies']['extra_versions']), ('MISMATCH', [2]))
        self.assertEqual(result['unconfirmed']['possible_extra_versions'], [])

    def test_common_conflict_survives_both_incomplete_claims(self):
        result = o.compare([entry('1_one.sql')], [row(1, 'wrong', '0'*96, False)],
                           source_complete_claim=False, row_complete_claim=False)
        self.assertEqual(result['state'], 'MISMATCH')
        for field in ('unsuccessful_versions', 'checksum_mismatch_versions', 'description_mismatch_versions'):
            self.assertEqual(result['discrepancies'][field], [1])

    def test_unconfirmed_missing_and_extra_are_preserved(self):
        result = o.compare([entry('1_one.sql')], [row(2, 'two')],
                           source_complete_claim=False, row_complete_claim=False)
        self.assertEqual(result['state'], 'INCONCLUSIVE')
        self.assertEqual(result['unconfirmed']['possible_missing_versions'], [1])
        self.assertEqual(result['unconfirmed']['possible_extra_versions'], [2])

    def test_extra_dirty_row_is_mismatch_even_with_incomplete_source(self):
        result = o.compare([entry('1_one.sql')], [row(1, 'one'), row(2, 'two', success=False)],
                           source_complete_claim=False, row_complete_claim=True)
        self.assertEqual(result['state'], 'MISMATCH')
        self.assertEqual(result['discrepancies']['unsuccessful_versions'], [2])
        self.assertEqual(result['discrepancies']['extra_versions'], [])
        self.assertEqual(result['unconfirmed']['possible_extra_versions'], [2])

    def test_missing_and_extra_versions_are_distinct(self):
        result = o.compare([entry('1_first.sql'), entry('2_second.sql')], [row(1, 'first'), row(3, 'third')],
                           source_complete_claim=True, row_complete_claim=True)
        self.assertEqual(result['discrepancies']['missing_versions'], [2])
        self.assertEqual(result['discrepancies']['extra_versions'], [3])

    def test_checksum_success_and_description_mismatches_are_separate(self):
        result = o.compare([entry('1_expected_name.sql')], [row(1, 'wrong', '0'*96, False)],
                           source_complete_claim=True, row_complete_claim=True)
        self.assertEqual(result['state'], 'MISMATCH')
        for field in ('checksum_mismatch_versions', 'unsuccessful_versions', 'description_mismatch_versions'):
            self.assertEqual(result['discrepancies'][field], [1])

    def test_duplicate_row_version_is_invalid(self):
        with self.assertRaisesRegex(o.OracleInputError, 'DUPLICATE_ROW_VERSION'):
            o.compare([entry('1_x.sql')], [row(1, 'x'), row(1, 'x')], source_complete_claim=True, row_complete_claim=True)

    def test_boolean_version_and_non_boolean_success_are_invalid(self):
        for bad in (row(True, 'x'), row(1, 'x', success=1)):
            with self.subTest(bad=bad), self.assertRaises(o.OracleInputError):
                o.compare([entry('1_x.sql')], [bad], source_complete_claim=True, row_complete_claim=True)

    def test_completeness_booleans_are_strict(self):
        with self.assertRaisesRegex(o.OracleInputError, 'COMPLETENESS_CLAIM_INVALID'):
            o.compare([entry('1_x.sql')], [row(1, 'x')], source_complete_claim=1, row_complete_claim=True)

    def test_checksum_encoding_is_strict_lowercase_full_sha384(self):
        for checksum in ('f'*95, 'G'*96, 'A'*96, ''):
            with self.subTest(checksum=checksum), self.assertRaisesRegex(o.OracleInputError, 'ROW_VALUE_INVALID'):
                o.compare([entry('1_x.sql')], [row(1, 'x', checksum)], source_complete_claim=True, row_complete_claim=True)

    def test_malformed_row_shape_is_invalid(self):
        with self.assertRaisesRegex(o.OracleInputError, 'ROW_SHAPE_INVALID'):
            o.compare([entry('1_x.sql')], [{'version': 1}], source_complete_claim=True, row_complete_claim=True)

    def test_non_regular_unknown_and_symlink_cannot_be_established_from_bytes(self):
        report = o.inventory([entry('1_x.sql')])
        self.assertEqual(report['source_file_set_completeness'], 'CALLER_UNVERIFIED')
        self.assertEqual(report['source_authentication'], 'UNVERIFIED')

    def test_name_and_count_limits_reject_ambiguous_inputs(self):
        for bad in ('../1_x.sql', '', 'a\0b'):
            with self.subTest(name=bad), self.assertRaisesRegex(o.OracleInputError, 'INVALID_FILENAME'):
                o.inventory([entry(bad)])
        with self.assertRaisesRegex(o.OracleInputError, 'ENTRY_COUNT_INVALID'):
            o.inventory([entry('1_x.sql')] * (o.MAX_ENTRIES + 1))
        with self.assertRaisesRegex(o.OracleInputError, 'ROW_COUNT_INVALID'):
            o.compare([entry('1_x.sql')], [row(1, 'x')] * (o.MAX_DB_ROWS + 1), source_complete_claim=True, row_complete_claim=True)


    def test_rejection_exposes_stable_error_code(self):
        with self.assertRaises(o.OracleInputError) as caught:
            o.inventory([entry('1_bad.sql', b'\xff')])
        self.assertEqual(caught.exception.code, 'INVALID_SQL_UTF8')

    def test_name_character_limit_is_checked_before_utf8_encoding(self):
        from unittest.mock import patch
        with patch.object(o, 'MAX_NAME_BYTES', 3):
            with self.assertRaisesRegex(o.OracleInputError, 'FILENAME_LIMIT'):
                o.inventory([entry('\ud800abc')])
            with self.assertRaisesRegex(o.OracleInputError, 'INVALID_FILENAME_UTF8'):
                o.inventory([entry('\ud800')])

    def test_row_description_utf8_byte_limit_is_enforced(self):
        from unittest.mock import patch
        with patch.object(o, 'MAX_ROW_DESCRIPTION_BYTES', 4):
            valid = o.compare([entry('1_x.sql')], [row(1, 'éé')], source_complete_claim=True, row_complete_claim=True)
            self.assertEqual(valid['state'], 'MISMATCH')
            with self.assertRaisesRegex(o.OracleInputError, 'ROW_DESCRIPTION_LIMIT'):
                o.compare([entry('1_x.sql')], [row(1, 'ééé')], source_complete_claim=True, row_complete_claim=True)
            with self.assertRaisesRegex(o.OracleInputError, 'ROW_DESCRIPTION_LIMIT'):
                o.compare([entry('1_x.sql')], [row(1, '\ud800aaaa')], source_complete_claim=True, row_complete_claim=True)

    def test_row_description_nul_and_lone_surrogate_are_rejected(self):
        for desc, code in [('a\0b', 'ROW_DESCRIPTION_NUL'), ('\ud800', 'ROW_DESCRIPTION_UTF8_INVALID')]:
            with self.subTest(code=code), self.assertRaisesRegex(o.OracleInputError, code):
                o.compare([entry('1_x.sql')], [row(1, desc)], source_complete_claim=True, row_complete_claim=True)

    def test_total_row_description_utf8_byte_budget_is_enforced(self):
        from unittest.mock import patch
        entries = [entry('1_a.sql'), entry('2_b.sql')]
        rows = [row(1, 'abcd'), row(2, 'efgh')]
        with patch.object(o, 'MAX_ROW_DESCRIPTION_BYTES', 4), patch.object(o, 'MAX_TOTAL_ROW_DESCRIPTION_BYTES', 7):
            with self.assertRaisesRegex(o.OracleInputError, 'TOTAL_DESCRIPTION_BYTES_LIMIT'):
                o.compare(entries, rows, source_complete_claim=True, row_complete_claim=True)
        with patch.object(o, 'MAX_ROW_DESCRIPTION_BYTES', 4), patch.object(o, 'MAX_TOTAL_ROW_DESCRIPTION_BYTES', 8):
            result = o.compare(entries, rows, source_complete_claim=True, row_complete_claim=True)
            self.assertEqual(result['state'], 'MISMATCH')

    def test_file_and_aggregate_byte_budgets_are_checked(self):
        from unittest.mock import patch
        with patch.object(o, 'MAX_FILE_BYTES', 2):
            with self.assertRaisesRegex(o.OracleInputError, 'FILE_BYTES_INVALID'):
                o.inventory([entry('1_x.sql', b'abc')])
        with patch.object(o, 'MAX_TOTAL_BYTES', 5):
            with self.assertRaisesRegex(o.OracleInputError, 'TOTAL_BYTES_LIMIT'):
                o.inventory([entry('1_x.sql', b'abc'), entry('2_y.sql', b'def')])


if __name__ == '__main__':
    unittest.main()
