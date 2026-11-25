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
"""Static validation and local reproduction script generation for projects."""

# The validator intentionally collects many independent checks in one pass.
# pylint: disable=too-many-arguments,too-many-branches,too-many-lines
# pylint: disable=too-many-locals,too-many-positional-arguments
# pylint: disable=too-many-return-statements,too-many-statements

import argparse
import difflib
import json
import os
import re
import shlex
import stat
import sys

import yaml

_INFRA_DIR = os.path.dirname(os.path.abspath(__file__))
if _INFRA_DIR not in sys.path:
  sys.path.insert(0, _INFRA_DIR)

import constants  # pylint: disable=wrong-import-position

OSS_FUZZ_ROOT = os.path.dirname(_INFRA_DIR)
PROJECTS_DIR = os.path.join(OSS_FUZZ_ROOT, 'projects')
PROJECT_NAME_REGEX = re.compile(r'^[a-z0-9_-]+$')

try:
  from presubmit import ProjectYamlChecker
  KNOWN_KEYS = list(ProjectYamlChecker.VALID_SECTION_NAMES)
except Exception:  # pragma: no cover - presubmit is always available in repo.
  KNOWN_KEYS = [
      'architectures', 'auto_ccs', 'blackbox', 'builds_per_day',
      'coverage_extra_args', 'disabled', 'disable_remediation',
      'disable_remediation_pre_review', 'fuzzing_engines', 'help_url',
      'homepage', 'language', 'labels', 'main_repo', 'primary_contact',
      'run_tests', 'sanitizers', 'selective_unpack', 'vendor_ccs',
      'view_restrictions', 'file_github_issue', 'indexer', 'base_os_version'
  ]

BOOLEAN_KEYS = {
    'blackbox', 'disabled', 'disable_remediation',
    'disable_remediation_pre_review', 'file_github_issue', 'run_tests',
    'selective_unpack'
}
INTEGER_KEYS = {'builds_per_day'}
DICT_KEYS = {'indexer', 'labels'}
STRING_KEYS = {
    'base_os_version', 'coverage_extra_args', 'help_url', 'homepage',
    'language', 'main_repo', 'primary_contact', 'view_restrictions'
}
STRING_LIST_KEYS = {'architectures', 'auto_ccs', 'vendor_ccs'}

VALUE_ALIASES = {
    'language': {
        'c++': 'c++',
        'cpp': 'c++',
        'cxx': 'c++',
        'cplusplus': 'c++',
        'java': 'jvm',
        'kotlin': 'jvm',
        'scala': 'jvm',
        'py': 'python',
        'python3': 'python',
        'golang': 'go',
        'js': 'javascript',
        'node': 'javascript',
        'nodejs': 'javascript',
    },
    'sanitizer': {
        'asan': 'address',
        'addresssanitizer': 'address',
        'addres': 'address',
        'addrress': 'address',
        'ubsan': 'undefined',
        'undefinedbehavior': 'undefined',
        'memsan': 'memory',
        'msan': 'memory',
        'tsan': 'thread',
        'hwasan': 'hwaddress',
    },
    'engine': {
        'libfuzzer': 'libfuzzer',
        'lib-fuzzer': 'libfuzzer',
        'lib_fuzzer': 'libfuzzer',
        'fuzzer': 'libfuzzer',
        'afl++': 'afl',
        'hongfuzz': 'honggfuzz',
        'wycheproofengine': 'wycheproof',
    },
    'architecture': {
        'x64': 'x86_64',
        'amd64': 'x86_64',
        'x86-64': 'x86_64',
        'arm64': 'aarch64',
        'x86': 'i386',
        'i686': 'i386',
    }
}

KEY_ALIASES = {
    'arch': 'architectures',
    'architecture': 'architectures',
    'engine': 'fuzzing_engines',
    'engines': 'fuzzing_engines',
    'lang': 'language',
    'mainrepo': 'main_repo',
    'repo': 'main_repo',
    'sanitizer': 'sanitizers',
}


class ValidationIssue:
  """A static validation error or warning and its actionable fix."""

  def __init__(self, severity, message, fix=None, line=None):
    self.severity = severity
    self.message = message
    self.fix = fix
    self.line = line

  def to_dict(self):
    """Returns a JSON-serializable representation."""
    result = {'severity': self.severity, 'message': self.message}
    if self.fix:
      result['fix'] = self.fix
    if self.line is not None:
      result['line'] = self.line
    return result

  def format(self, location):
    """Formats the issue for terminal output."""
    line_suffix = f':{self.line}' if self.line is not None else ''
    lines = [
        f'[{self.severity.upper()}] {location}{line_suffix}: {self.message}'
    ]
    if self.fix:
      lines.append(f'  Fix (修法): {self.fix}')
    return '\n'.join(lines)


class ValidationResult:
  """Validation data and issues for one project."""

  def __init__(self,
               target,
               project_dir=None,
               yaml_path=None,
               data=None,
               external=False):
    self.target = target
    self.project_dir = project_dir
    self.yaml_path = yaml_path
    self.data = data if isinstance(data, dict) else {}
    self.external = external
    self.issues = []

  @property
  def errors(self):
    """Returns error-severity issues."""
    return [issue for issue in self.issues if issue.severity == 'error']

  @property
  def warnings(self):
    """Returns warning-severity issues."""
    return [issue for issue in self.issues if issue.severity == 'warning']

  @property
  def ok(self):
    """Returns True when no error was found."""
    return not self.errors

  def add_error(self, message, fix=None, line=None):
    """Adds an error and marks the result unsuccessful."""
    self.issues.append(ValidationIssue('error', message, fix, line))

  def add_warning(self, message, fix=None, line=None):
    """Adds a non-fatal warning."""
    self.issues.append(ValidationIssue('warning', message, fix, line))

  def to_dict(self):
    """Returns a JSON-serializable result."""
    return {
        'target': self.target,
        'project_dir': self.project_dir,
        'yaml_path': self.yaml_path,
        'external': self.external,
        'ok': self.ok,
        'data': self.data,
        'issues': [issue.to_dict() for issue in self.issues],
    }

  def format(self, json_output=False):
    """Formats this result as text or JSON."""
    if json_output:
      return json.dumps(self.to_dict(), indent=2, sort_keys=True)

    location = self.yaml_path or self.target
    try:
      location = os.path.relpath(location)
    except ValueError:
      pass

    lines = [issue.format(location) for issue in self.issues]
    if self.ok:
      lines.append(f'Configuration is valid: {location}')
      if self.warnings:
        lines.append(
            f'{len(self.warnings)} warning(s); generation can continue.')
    else:
      lines.append(
          f'Configuration validation failed with {len(self.errors)} error(s) '
          f'and {len(self.warnings)} warning(s).')
    return '\n'.join(lines)


def _suggest_value(value, allowed, aliases=None):
  """Returns the best known replacement for |value|, if one exists."""
  if value is None:
    return None

  raw = str(value)
  lowered = raw.lower()
  aliases = aliases or {}
  if lowered in aliases:
    return aliases[lowered]

  for allowed_value in allowed:
    if lowered == str(allowed_value).lower():
      return allowed_value

  matches = difflib.get_close_matches(lowered, list(allowed), n=1, cutoff=0.45)
  if matches:
    return matches[0]
  return None


def _suggest_key(key):
  """Returns a likely valid project.yaml key."""
  matches = difflib.get_close_matches(str(key), KNOWN_KEYS, n=1, cutoff=0.55)
  return matches[0] if matches else None


def _resolve_target(target):
  """Resolves a project name, directory, Project object, or YAML file."""
  if target is not None and not isinstance(target, str):
    build_path = getattr(target, 'build_integration_path', None)
    if build_path:
      return build_path, os.path.join(build_path, 'project.yaml')
    target = getattr(target, 'target', None) or getattr(target, 'path', None)

  target = os.path.abspath(os.path.expanduser(str(target)))
  if os.path.isfile(target):
    return os.path.dirname(target), target

  if os.path.isdir(target):
    yaml_path = os.path.join(target, 'project.yaml')
    return target, yaml_path

  named_project_dir = os.path.join(PROJECTS_DIR, target)
  if os.path.isdir(named_project_dir):
    return named_project_dir, os.path.join(named_project_dir, 'project.yaml')

  return None, None


def _is_external_layout(yaml_path):
  """Returns True for ClusterFuzzLite/.clusterfuzzlite integrations."""
  normalized = os.path.normpath(yaml_path or '')
  return ('.clusterfuzzlite' in normalized.split(os.sep) or
          os.path.basename(os.path.dirname(normalized)) == '.clusterfuzzlite')


def _canonical_project_name(project_dir):
  """Returns the project name for projects/<name>, otherwise None."""
  if not project_dir:
    return None
  parent = os.path.dirname(os.path.abspath(project_dir))
  if os.path.abspath(parent) == os.path.abspath(PROJECTS_DIR):
    return os.path.basename(os.path.abspath(project_dir))
  return None


def _find_value_line(yaml_text, key, value):
  """Best-effort line lookup for a scalar/list item."""
  key_pattern = re.compile(rf'^{re.escape(str(key))}\s*:')
  lines = yaml_text.splitlines()
  in_section = False
  for index, line in enumerate(lines, start=1):
    if key_pattern.match(line):
      in_section = True
      if str(value) in line:
        return index
      continue
    if in_section:
      if line and not line.startswith((' ', '\t')):
        return None
      if str(value) in line:
        return index
  return None


def _validate_choice_list(result, yaml_text, key, allowed, alias_kind):
  """Validates a project.yaml list whose items must be known constants."""
  data = result.data
  if key not in data or data[key] is None:
    return

  values = data[key]
  if not isinstance(values, list):
    suggested = None
    if isinstance(values, str):
      suggested = _suggest_value(values, allowed,
                                 VALUE_ALIASES.get(alias_kind, {}))
    fix_example = suggested or (values if isinstance(values, str) else 'value')
    result.add_error(
        f'"{key}" must be a list, got {type(values).__name__}: {values!r}.',
        f'Use `{key}: [{fix_example}]` instead of a scalar value.',
        _find_value_line(yaml_text, key, values))
    return

  for value in values:
    if key == 'sanitizers' and isinstance(value, dict):
      if len(value) != 1:
        result.add_error(
            f'Invalid {key} entry {value!r}.',
            'Use exactly one sanitizer name as the mapping key, for example: '
            '`{memory: {experimental: true}}`.')
        continue
      sanitizer = next(iter(value))
      if sanitizer not in allowed:
        replacement = _suggest_value(sanitizer, allowed,
                                     VALUE_ALIASES.get(alias_kind, {}))
        fix = (f'Replace `{sanitizer}` with `{replacement}`, for example: '
               f'`{{{replacement}: {{experimental: true}}}}`.'
               if replacement else f'Use one of: {", ".join(allowed)}.')
        result.add_error(
            f'{sanitizer!r} in {key} is not a supported sanitizer.', fix)
      continue

    if not isinstance(value, str):
      result.add_error(
          f'Every entry in "{key}" must be a string, got {value!r}.',
          f'Remove the non-string entry from `{key}` or quote it if it is '
          'meant to be text.')
      continue

    if value not in allowed:
      replacement = _suggest_value(value, allowed,
                                   VALUE_ALIASES.get(alias_kind, {}))
      line = _find_value_line(yaml_text, key, value)
      if replacement:
        fix = (f'Replace `{value}` with `{replacement}` in `{key}`; '
               f'valid values: {", ".join(allowed)}.')
      else:
        fix = f'Use one of these values in `{key}`: {", ".join(allowed)}.'
      result.add_error(
          f'{value!r} in {key} is not supported by this OSS-Fuzz checkout.',
          fix, line)


def _validate_build_files(result):
  """Adds warnings for missing files that commonly lead to zero coverage."""
  project_dir = result.project_dir
  if not project_dir:
    return

  dockerfile = os.path.join(project_dir, 'Dockerfile')
  build_sh = os.path.join(project_dir, 'build.sh')
  language = result.data.get('language', constants.DEFAULT_LANGUAGE)
  builder_image = {
      'c': 'base-builder',
      'c++': 'base-builder',
      'go': 'base-builder-go',
      'javascript': 'base-builder-javascript',
      'jvm': 'base-builder-jvm',
      'python': 'base-builder-python',
      'ruby': 'base-builder-ruby',
      'rust': 'base-builder-rust',
      'swift': 'base-builder-swift',
  }.get(language, 'base-builder')

  if not os.path.exists(dockerfile):
    result.add_warning(
        'Dockerfile was not found; cloud builds and the generated Docker '
        'reproduction flow need one.',
        f'Add `{dockerfile}` starting with `FROM gcr.io/oss-fuzz-base/'
        f'{builder_image}` and `COPY build.sh $SRC/`.')

  if not os.path.exists(build_sh):
    result.add_warning(
        'build.sh was not found; without it OSS-Fuzz cannot compile harnesses.',
        f'Add executable `{build_sh}` that builds each harness into '
        '`"$OUT"` and links it with `"$LIB_FUZZING_ENGINE"`.')
    return

  try:
    with open(build_sh, encoding='utf-8') as file_handle:
      build_contents = file_handle.read()
  except OSError as error:
    result.add_warning(f'Cannot read build.sh: {error}',
                       'Check file permissions and path.')
    return

  if '-lFuzzingEngine' in build_contents:
    result.add_error(
        'build.sh uses deprecated `-lFuzzingEngine`.',
        'Replace `-lFuzzingEngine` with `"$LIB_FUZZING_ENGINE"` so the '
        'selected fuzzing engine and sanitizer flags are used.')

  output_publishers = ('$OUT', '${OUT}', 'compile_python_fuzzer',
                       'compile_go_fuzzer', 'compile_native_go_fuzzer',
                       'compile_javascript_fuzzer', 'bazel_build_fuzz_tests')
  if not any(publisher in build_contents for publisher in output_publishers):
    result.add_warning(
        'build.sh does not mention `$OUT`; binaries left elsewhere are not '
        'published as fuzz targets and produce no coverage.',
        'Write each fuzzer executable to `"$OUT/<fuzzer_name>"`, for example '
        'add `-o "$OUT/my_fuzzer"` to the compiler command.')


def validate_target(target, strict=False):
  """Validates |target| and returns a :class:`ValidationResult`."""
  project_dir, yaml_path = _resolve_target(target)
  if not yaml_path:
    result = ValidationResult(target)
    result.add_error(
        f'Project target does not exist: {target}',
        'Pass an existing project name, project directory, or project.yaml '
        'path. Create a project with `python3 infra/helper.py generate '
        '<project-name> --language c++`.')
    return result

  external = _is_external_layout(yaml_path)
  result = ValidationResult(target, project_dir, yaml_path, external=external)

  if os.path.basename(yaml_path) == 'project.yml':
    result.add_error(
        'Configuration file must be named project.yaml, not project.yml.',
        f'Rename it: `mv {shlex.quote(yaml_path)} '
        f'{shlex.quote(os.path.join(project_dir, "project.yaml"))}`.')
    return result

  if not os.path.isfile(yaml_path):
    result.add_error(
        f'project.yaml was not found at {yaml_path}.',
        'Create it with `language: c++` and `main_repo: <repository-url>`, or '
        'run `python3 infra/helper.py generate <project-name>`.')
    return result

  try:
    with open(yaml_path, encoding='utf-8') as file_handle:
      yaml_text = file_handle.read()
  except OSError as error:
    result.add_error(f'Cannot read project.yaml: {error}',
                     'Check that the file exists and is readable.')
    return result

  try:
    data = yaml.safe_load(yaml_text)
  except yaml.YAMLError as error:
    line = None
    mark = getattr(error, 'problem_mark', None)
    if mark is not None:
      line = mark.line + 1
    result.add_error(
        f'Invalid YAML syntax: {str(error).splitlines()[0]}',
        'Fix indentation (two spaces), quote values containing colons or '
        'special characters, and validate the YAML structure.', line)
    return result

  if data is None:
    data = {}
  if not isinstance(data, dict):
    result.add_error(
        'project.yaml must contain a top-level mapping of keys to values.',
        'Start with e.g. `language: c++` and `main_repo: '
        'https://example.com/repo.git`.')
    return result
  result.data = data

  for key in data:
    if key not in KNOWN_KEYS:
      replacement = KEY_ALIASES.get(str(key).lower()) or _suggest_key(key)
      fix = (f'Rename `{key}` to `{replacement}`.'
             if replacement else f'Remove `{key}` or use a supported key: '
             f'{", ".join(KNOWN_KEYS)}.')
      result.add_error(f'Unknown project.yaml key: {key!r}.', fix)

  language = data.get('language')
  if not language:
    result.add_error(
        'Missing required "language" key.',
        'Add e.g. `language: c++`; supported values: '
        f'{", ".join(constants.LANGUAGES)}.')
  elif not isinstance(language, str):
    result.add_error(
        f'"language" must be a string, got {type(language).__name__}.',
        'Quote the value if needed and use one of: '
        f'{", ".join(constants.LANGUAGES)}.')
    language = None
  elif language not in constants.LANGUAGES:
    replacement = _suggest_value(language, constants.LANGUAGES,
                                 VALUE_ALIASES['language'])
    fix = (f'Replace `language: {language}` with '
           f'`language: {replacement}`.'
           if replacement else f'Use one of: {", ".join(constants.LANGUAGES)}.')
    result.add_error(f'Unsupported language {language!r}.', fix,
                     _find_value_line(yaml_text, 'language', language))

  if not external and not data.get('main_repo'):
    result.add_error(
        'Missing required "main_repo" key.',
        'Add `main_repo: https://github.com/<org>/<repo>.git` (or the '
        "project's canonical source repository URL).")
  elif 'main_repo' in data and not isinstance(data.get('main_repo'), str):
    result.add_error('"main_repo" must be a repository URL string.',
                     'Write it as `main_repo: https://example.com/repo.git`.')

  for key in STRING_KEYS:
    value = data.get(key)
    if value is not None and not isinstance(value, str):
      result.add_error(f'"{key}" must be a string, got {type(value).__name__}.',
                       f'Quote the `{key}` value or replace it with a string.')

  for key in BOOLEAN_KEYS:
    value = data.get(key)
    if value is not None and not isinstance(value, bool):
      result.add_error(
          f'"{key}" must be a boolean (true or false), got {value!r}.',
          f'Set `{key}: true` or `{key}: false`.')

  for key in INTEGER_KEYS:
    value = data.get(key)
    if value is not None and (not isinstance(value, int) or
                              isinstance(value, bool)):
      result.add_error(f'"{key}" must be an integer, got {value!r}.',
                       f'Set `{key}: 2`; allowed range is 1-4 builds per day.')
    elif key == 'builds_per_day' and isinstance(value,
                                                int) and not 1 <= value <= 4:
      result.add_error(
          f'builds_per_day={value} is outside the supported range.',
          'Use an integer from 1 to 4 (OSS-Fuzz schedules at most four '
          'builds per day).')

  for key in DICT_KEYS:
    value = data.get(key)
    if value is not None and not isinstance(value, dict):
      result.add_error(
          f'"{key}" must be a mapping, got {type(value).__name__}.',
          f'Use YAML mapping syntax under `{key}:`.')

  for key in STRING_LIST_KEYS:
    value = data.get(key)
    if value is None:
      continue
    if not isinstance(value, list):
      result.add_error(f'"{key}" must be a list of strings.',
                       f'Use `{key}: ["<value>"]` or a YAML block list.')
    elif key != 'architectures':
      for item in value:
        if not isinstance(item, str):
          result.add_error(f'Entries in `{key}` must be strings.',
                           'Quote values that YAML parses as other types.')

  _validate_choice_list(result, yaml_text, 'architectures',
                        constants.ARCHITECTURES, 'architecture')
  _validate_choice_list(result, yaml_text, 'fuzzing_engines', constants.ENGINES,
                        'engine')
  _validate_choice_list(result, yaml_text, 'sanitizers', constants.SANITIZERS,
                        'sanitizer')

  base_os = data.get('base_os_version')
  allowed_os = ['legacy', 'ubuntu-20-04', 'ubuntu-24-04']
  if base_os is not None and base_os not in allowed_os:
    replacement = _suggest_value(base_os, allowed_os)
    fix = (f'Replace `{base_os}` with `{replacement}`.'
           if replacement else f'Use one of: {", ".join(allowed_os)}.')
    result.add_error(f'Unsupported base_os_version {base_os!r}.', fix)

  for email_key in ('primary_contact',):
    email = data.get(email_key)
    if (email and isinstance(email, str) and
        ('@' not in email or '.' not in email)):
      result.add_error(
          f'{email!r} in {email_key} is not a valid email address.',
          'Use a maintainer email such as `primary_contact: '
          'maintainer@example.com`.')

  for email in data.get('auto_ccs') or []:
    if isinstance(email, str) and ('@' not in email or '.' not in email):
      result.add_error(f'{email!r} in auto_ccs is not a valid email address.',
                       'Replace it with an email address or remove the entry.')

  canonical_name = _canonical_project_name(project_dir)
  if canonical_name and not PROJECT_NAME_REGEX.match(canonical_name):
    result.add_error(
        f'Invalid OSS-Fuzz project directory name: {canonical_name!r}.',
        'Use lowercase letters, digits, underscores, or hyphens; rename the '
        'directory and update any CI references.')

  if data.get('disabled') is True:
    result.add_warning(
        'This project is disabled and will not produce routine coverage.',
        'Set `disabled: false` or remove the `disabled` key when onboarding '
        'is complete.')

  _validate_build_files(result)

  if strict:
    for issue in result.warnings:
      issue.severity = 'error'

  return result


def _first_configured_value(data, key, allowed, default):
  """Returns the first usable scalar from a project.yaml list."""
  values = data.get(key) or []
  if isinstance(values, list):
    for value in values:
      candidate = next(iter(value)) if isinstance(value, dict) else value
      if isinstance(candidate, str) and candidate in allowed:
        return candidate
  return default


def _shell_array(values):
  """Renders Python strings as the contents of a Bash array."""
  return ' '.join(shlex.quote(str(value)) for value in values)


def build_reproduction_script(result,
                              output_path=None,
                              fuzzer_name=None,
                              testcase_path=None,
                              source_path=None,
                              engine=None,
                              sanitizer=None,
                              architecture=None):
  """Builds a minimal locally executable reproduction script."""
  if not result.ok:
    raise ValueError('Refusing to generate a reproduction script for an '
                     'invalid configuration.')

  data = result.data
  engine = engine or _first_configured_value(
      data, 'fuzzing_engines', constants.ENGINES, constants.DEFAULT_ENGINE)
  sanitizer = sanitizer or _first_configured_value(
      data, 'sanitizers', constants.SANITIZERS, constants.DEFAULT_SANITIZER)
  architecture = architecture or _first_configured_value(
      data, 'architectures', constants.ARCHITECTURES,
      constants.DEFAULT_ARCHITECTURE)

  for value, allowed, label in ((engine, constants.ENGINES, 'engine'),
                                (sanitizer, constants.SANITIZERS, 'sanitizer'),
                                (architecture, constants.ARCHITECTURES,
                                 'architecture')):
    if value not in allowed:
      raise ValueError(f'invalid {label}: {value!r}')

  canonical_name = _canonical_project_name(result.project_dir)
  validation_target = result.yaml_path
  if canonical_name:
    project_name = canonical_name
    project_args = [project_name]
  else:
    project_name = os.path.basename(result.project_dir.rstrip(os.sep))
    project_args = ['--external', result.project_dir]

  output_path = output_path or os.path.join(OSS_FUZZ_ROOT, 'build', 'repro',
                                            f'{project_name}-reproduce.sh')
  output_path = os.path.abspath(output_path)
  os.makedirs(os.path.dirname(output_path), exist_ok=True)

  defaults = {
      'root':
          shlex.quote(OSS_FUZZ_ROOT),
      'helper':
          shlex.quote(os.path.join(OSS_FUZZ_ROOT, 'infra', 'helper.py')),
      'python':
          shlex.quote(sys.executable or 'python3'),
      'validate_target':
          shlex.quote(validation_target),
      'project_name':
          shlex.quote(project_name),
      'project_args':
          _shell_array(project_args),
      'fuzzer':
          shlex.quote(fuzzer_name or ''),
      'testcase':
          shlex.quote(os.path.abspath(testcase_path) if testcase_path else ''),
      'source':
          shlex.quote(os.path.abspath(source_path) if source_path else ''),
      'engine':
          shlex.quote(engine),
      'sanitizer':
          shlex.quote(sanitizer),
      'architecture':
          shlex.quote(architecture),
      'output_path':
          shlex.quote(output_path),
  }

  script = f'''#!/usr/bin/env bash
# Generated by `python3 infra/helper.py generate-repro`.
# Minimal build + crash reproduction flow for {defaults['project_name']}.
set -euo pipefail

OSS_FUZZ_ROOT={defaults['root']}
HELPER={defaults['helper']}
DEFAULT_PYTHON={defaults['python']}
PYTHON_BIN="${{PYTHON:-$DEFAULT_PYTHON}}"
VALIDATE_TARGET={defaults['validate_target']}
PROJECT_NAME={defaults['project_name']}
PROJECT_ARGS=({defaults['project_args']})

FUZZER={defaults['fuzzer']}
TESTCASE={defaults['testcase']}
SOURCE_PATH={defaults['source']}
ENGINE={defaults['engine']}
SANITIZER={defaults['sanitizer']}
ARCHITECTURE={defaults['architecture']}

DRY_RUN=0
SKIP_BUILD=0
PULL=0
SHOW_HELP=0
EXTRA_ARGS=()
ORIGINAL_ARGC=$#

usage() {{
  cat <<USAGE
Usage: $0 [options] [FUZZER] [TESTCASE] [-- fuzzer args...]

Build $PROJECT_NAME in OSS-Fuzz containers and reproduce one testcase.

Options:
  --fuzzer NAME          Fuzz target name.
  --testcase PATH        Crash input to reproduce.
  --source PATH          Local source checkout to mount during build.
  --engine NAME          libfuzzer, afl, honggfuzz, centipede, or none.
  --sanitizer NAME       address, memory, undefined, thread, coverage, etc.
  --architecture ARCH    x86_64, i386, or aarch64.
  --skip-build           Reuse existing binaries in build/out/$PROJECT_NAME.
  --pull                 Pull the latest project/base image before building.
  --dry-run              Print Docker-backed commands without running them.
                         Local YAML validation still runs.
  -h, --help             Show this help.

Examples:
  $0 --dry-run my_fuzzer clusterfuzz-testcase-123
  $0 my_fuzzer ./crash-input
  $0 --skip-build my_fuzzer ./crash-input -- -runs=1
USAGE
}}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      SHOW_HELP=1
      shift
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    --skip-build)
      SKIP_BUILD=1
      shift
      ;;
    --pull)
      PULL=1
      shift
      ;;
    --fuzzer)
      FUZZER="$2"
      shift 2
      ;;
    --testcase)
      TESTCASE="$2"
      shift 2
      ;;
    --source)
      SOURCE_PATH="$2"
      shift 2
      ;;
    --engine)
      ENGINE="$2"
      shift 2
      ;;
    --sanitizer)
      SANITIZER="$2"
      shift 2
      ;;
    --architecture)
      ARCHITECTURE="$2"
      shift 2
      ;;
    --)
      shift
      EXTRA_ARGS+=("$@")
      break
      ;;
    *)
      if [[ -z "$FUZZER" ]]; then
        FUZZER="$1"
      elif [[ -z "$TESTCASE" ]]; then
        TESTCASE="$1"
      else
        EXTRA_ARGS+=("$1")
      fi
      shift
      ;;
  esac
done

if [[ "$SHOW_HELP" -eq 1 ]]; then
  usage
  exit 0
fi

if [[ "$ORIGINAL_ARGC" -eq 0 ]]; then
  usage
  exit 0
fi

if [[ "$DRY_RUN" -eq 0 ]] && ! command -v docker >/dev/null 2>&1; then
  echo "Error: docker is required for a real reproduction run." >&2
  echo "Fix: install/start Docker, or rerun with --dry-run." >&2
  exit 127
fi

run() {{
  printf '\\n+'
  printf ' %q' "$@"
  printf '\\n'
  if [[ "$DRY_RUN" -eq 0 ]]; then
    "$@"
  fi
}}

validation_command=("$PYTHON_BIN" "$HELPER" validate-config
                    "$VALIDATE_TARGET")
printf '\\n+'
printf ' %q' "${{validation_command[@]}}"
printf '\\n'
"${{validation_command[@]}}"

if [[ "$SKIP_BUILD" -eq 0 ]]; then
  image_command=("$PYTHON_BIN" "$HELPER" build_image
                 --architecture "$ARCHITECTURE")
  if [[ "$PULL" -eq 1 ]]; then
    image_command+=(--pull)
  else
    image_command+=(--no-pull)
  fi
  image_command+=("${{PROJECT_ARGS[@]}}")
  run "${{image_command[@]}}"

  build_command=("$PYTHON_BIN" "$HELPER" build_fuzzers
                 --engine "$ENGINE"
                 --sanitizer "$SANITIZER"
                 --architecture "$ARCHITECTURE")
  build_command+=("${{PROJECT_ARGS[@]}}")
  if [[ -n "$SOURCE_PATH" ]]; then
    build_command+=("$SOURCE_PATH")
  fi
  run "${{build_command[@]}}"
fi

if [[ -z "$FUZZER" ]]; then
  echo "Build/validation steps are ready. Pass FUZZER and TESTCASE to reproduce."
  exit 0
fi

CLEANUP_TESTCASE=0
if [[ -z "$TESTCASE" ]]; then
  TESTCASE="$(mktemp)"
  printf 'minimal OSS-Fuzz smoke input\\n' > "$TESTCASE"
  CLEANUP_TESTCASE=1
  echo "No TESTCASE supplied; using smoke input $TESTCASE."
fi

if [[ ! -f "$TESTCASE" ]]; then
  echo "Error: testcase does not exist: $TESTCASE" >&2
  echo "Fix (修法): pass the crash file path as the second positional argument." >&2
  exit 2
fi

TESTCASE="$(cd "$(dirname "$TESTCASE")" && pwd)/$(basename "$TESTCASE")"
reproduce_command=("$PYTHON_BIN" "$HELPER" reproduce
                   --architecture "$ARCHITECTURE")
reproduce_command+=("${{PROJECT_ARGS[@]}}")
reproduce_command+=("$FUZZER" "$TESTCASE")
if [[ "${{#EXTRA_ARGS[@]}}" -gt 0 ]]; then
  reproduce_command+=("${{EXTRA_ARGS[@]}}")
fi

run "${{reproduce_command[@]}}"
reproduce_status=$?
if [[ "$CLEANUP_TESTCASE" -eq 1 ]]; then
  rm -f "$TESTCASE"
fi
exit "$reproduce_status"
'''

  with open(output_path, 'w', encoding='utf-8') as file_handle:
    file_handle.write(script)
  os.chmod(
      output_path,
      os.stat(output_path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
  return output_path


def _print_result(result, json_output):
  print(result.format(json_output=json_output))


def validate_cli(args):
  """Implements the standalone/helper validation command."""
  result = validate_target(args.target, strict=args.strict)
  _print_result(result, getattr(args, 'json', False))
  return result.ok


def generate_repro_cli(args):
  """Validates and generates a reproduction script from CLI arguments."""
  result = validate_target(args.target, strict=args.strict)
  _print_result(result, getattr(args, 'json', False))
  if not result.ok and not args.force:
    print('Refusing script generation. Apply the Fix items above and rerun, '
          'or pass --force after correcting the command manually.')
    return False

  output_arg = args.output or getattr(args, 'output_path', None)
  output_path = build_reproduction_script(result,
                                          output_path=output_arg,
                                          fuzzer_name=args.fuzzer,
                                          testcase_path=args.testcase,
                                          source_path=args.source,
                                          engine=args.engine,
                                          sanitizer=args.sanitizer,
                                          architecture=args.architecture)
  print(f'Generated local reproduction script: {output_path}')
  print(f'Inspect commands without Docker: {output_path} --dry-run')
  return True


def get_parser():
  """Builds the standalone command-line parser."""
  parser = argparse.ArgumentParser(
      prog='project_onboarding.py',
      description='Validate OSS-Fuzz project.yaml and create a local '
      'reproduction script.')
  subparsers = parser.add_subparsers(dest='command', required=True)

  validate_parser = subparsers.add_parser(
      'validate',
      aliases=[
          'validate-config', 'validate-project', 'lint', 'lint-config',
          'lint-project', 'check-config', 'doctor'
      ],
      help='Statically validate a project configuration.')
  validate_parser.add_argument('target',
                               help='Project name, project directory, or '
                               'project.yaml path.')
  validate_parser.add_argument('--strict',
                               action='store_true',
                               help='Treat readiness warnings as errors.')
  validate_parser.add_argument('--json',
                               action='store_true',
                               help='Print machine-readable JSON.')
  validate_parser.set_defaults(func=validate_cli)

  generate_parser = subparsers.add_parser(
      'generate-repro',
      aliases=[
          'generate_repro', 'gen-repro', 'repro-script', 'reproduce-script',
          'generate-local-repro', 'local-repro'
      ],
      help='Generate a minimal local reproduction script.')
  generate_parser.add_argument('target',
                               help='Project name, project directory, or '
                               'project.yaml path.')
  generate_parser.add_argument('output_path',
                               nargs='?',
                               help='Optional output script path.')
  generate_parser.add_argument('-o',
                               '--output',
                               '--output-file',
                               '--out',
                               '--script',
                               '--script-path',
                               dest='output',
                               help='Output script path.')
  generate_parser.add_argument('--fuzzer', help='Default fuzz target name.')
  generate_parser.add_argument('--testcase', help='Default crash testcase.')
  generate_parser.add_argument('--source', help='Local source directory.')
  generate_parser.add_argument('--engine', choices=constants.ENGINES)
  generate_parser.add_argument('--sanitizer', choices=constants.SANITIZERS)
  generate_parser.add_argument('--architecture',
                               choices=constants.ARCHITECTURES)
  generate_parser.add_argument('--strict', action='store_true')
  generate_parser.add_argument('--force',
                               action='store_true',
                               help='Generate even if validation has errors.')
  generate_parser.add_argument('--json', action='store_true')
  generate_parser.set_defaults(func=generate_repro_cli)
  return parser


def main(argv=None):
  """Runs the standalone CLI and returns a process exit code."""
  parser = get_parser()
  args = parser.parse_args(argv)
  return 0 if args.func(args) else 1


if __name__ == '__main__':
  sys.exit(main())
