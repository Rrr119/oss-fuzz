#!/usr/bin/env python3
# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################
"""Acceptance tests for project validation and repro script generation."""

# pylint: disable=missing-function-docstring,wrong-import-position

import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import project_onboarding


class ProjectOnboardingTest(unittest.TestCase):
  """Tests the three required bad configurations and good-config generation."""

  def setUp(self):
    self.temp_dir = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
    self.addCleanup(self.temp_dir.cleanup)

  def _write_project(self, name, contents):
    project_dir = os.path.join(self.temp_dir.name, name)
    os.makedirs(project_dir)
    yaml_path = os.path.join(project_dir, 'project.yaml')
    with open(yaml_path, 'w', encoding='utf-8') as file_handle:
      file_handle.write(contents)
    return project_dir

  def _assert_single_config_error_has_fix(self, project_dir, expected_fix):
    result = project_onboarding.validate_target(project_dir)
    config_errors = [
        issue for issue in result.errors
        if issue.fix and expected_fix in (issue.message + ' ' + issue.fix)
    ]
    self.assertFalse(result.ok, result.format())
    self.assertTrue(config_errors, result.format())
    self.assertIn('Fix', config_errors[0].format(project_dir))

  def test_three_invalid_configurations_are_rejected_with_fixes(self):
    bad_language = self._write_project(
        'bad-language', '''\
language: java
main_repo: https://example.com/bad-language.git
fuzzing_engines: [libfuzzer]
sanitizers: [address]
''')
    self._assert_single_config_error_has_fix(bad_language, 'jvm')

    bad_engine = self._write_project(
        'bad-engine', '''\
language: jvm
main_repo: https://example.com/bad-engine.git
fuzzing_engines: [libFuzzer]
sanitizers: [address]
''')
    self._assert_single_config_error_has_fix(bad_engine, 'libfuzzer')

    bad_sanitizer = self._write_project(
        'bad-sanitizer', '''\
language: c++
main_repo: https://example.com/bad-sanitizer.git
fuzzing_engines: [libfuzzer]
sanitizers:
  - addres
''')
    self._assert_single_config_error_has_fix(bad_sanitizer, 'address')

  def test_scalar_list_fields_are_rejected_with_copyable_fix(self):
    project_dir = self._write_project(
        'scalar-list', '''\
language: c++
main_repo: https://example.com/scalar-list.git
sanitizers: address
''')
    result = project_onboarding.validate_target(project_dir)
    self.assertFalse(result.ok)
    self.assertIn('sanitizers', result.errors[0].message)
    self.assertIn('[address]', result.errors[0].fix)

  def test_invalid_yaml_reports_syntax_fix(self):
    project_dir = self._write_project('bad-yaml',
                                      'language: c++\nsanitizers: [address\n')
    result = project_onboarding.validate_target(project_dir)
    self.assertFalse(result.ok)
    self.assertIn('Invalid YAML', result.errors[0].message)
    self.assertTrue(result.errors[0].fix)

  def test_json_output_contains_structured_fixes(self):
    project_dir = self._write_project(
        'json-bad', 'language: not-real\nmain_repo: https://example.com/x\n')
    result = project_onboarding.validate_target(project_dir)
    payload = json.loads(result.format(json_output=True))
    self.assertFalse(payload['ok'])
    self.assertTrue(payload['issues'][0]['fix'])

  def test_valid_config_generates_executable_dry_run_script(self):
    project_dir = self._write_project(
        'good', '''\
language: c++
main_repo: https://example.com/good.git
fuzzing_engines: [libfuzzer]
sanitizers: [address]
architectures: [x86_64]
''')
    result = project_onboarding.validate_target(project_dir)
    self.assertTrue(result.ok, result.format())

    script_path = os.path.join(self.temp_dir.name, 'reproduce_good.sh')
    generated_path = project_onboarding.build_reproduction_script(
        result,
        output_path=script_path,
        fuzzer_name='demo_fuzzer',
        testcase_path=os.path.join(self.temp_dir.name, 'crash.bin'))
    self.assertEqual(script_path, generated_path)

    mode = os.stat(script_path).st_mode
    self.assertTrue(mode & stat.S_IXUSR)
    self.assertTrue(mode & stat.S_IXGRP)
    self.assertTrue(mode & stat.S_IXOTH)

    with open(script_path, encoding='utf-8') as file_handle:
      script_contents = file_handle.read()
    self.assertIn('infra/helper.py', script_contents)
    self.assertIn('build_fuzzers', script_contents)
    self.assertIn('reproduce', script_contents)

    subprocess.run(['bash', '-n', script_path], check=True)
    help_result = subprocess.run([script_path, '--help'], check=False)
    self.assertEqual(0, help_result.returncode)
    no_args_result = subprocess.run([script_path], check=False)
    self.assertEqual(0, no_args_result.returncode)

    testcase = os.path.join(self.temp_dir.name, 'crash.bin')
    with open(testcase, 'wb') as file_handle:
      file_handle.write(b'crash')
    dry_run = subprocess.run([script_path, '--dry-run'],
                             check=False,
                             capture_output=True,
                             text=True)
    self.assertEqual(0, dry_run.returncode, dry_run.stdout + dry_run.stderr)
    self.assertIn('validate-config', dry_run.stdout)
    self.assertIn('build_fuzzers', dry_run.stdout)
    self.assertIn('reproduce', dry_run.stdout)

  def test_cli_rejects_bad_config_before_generation(self):
    project_dir = self._write_project(
        'cli-bad', 'language: java\nmain_repo: https://example.com/x\n')
    parser = project_onboarding.get_parser()
    args = parser.parse_args(['generate-repro', project_dir])
    self.assertEqual(1, project_onboarding.main(['validate', project_dir]))
    self.assertFalse(project_onboarding.generate_repro_cli(args))


if __name__ == '__main__':
  unittest.main()
