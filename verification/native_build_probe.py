#!/usr/bin/env python3
"""Fixed-policy Linux CPU C++20 compiler/probe adapter.

The caller must bind this runner, role specification, independent probe and the
approved toolchain closure as immutable verifier inputs. This program grants no
build/GPU permit, admission, completion or platform qualification of its own.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import resource
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time

SPEC_SCHEMA = 'forgeflow.native-build-probe.v1'
TOOLCHAIN_SCHEMA = 'forgeflow.native-cxx-toolchain.v1'
HASH = re.compile(r'[0-9a-f]{64}')
CASE_NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}')
SPEC_KEYS = {'schema_version', 'capability', 'card_id', 'source_card_sha256', 'toolchain',
             'source_files', 'include_directories', 'probe', 'cases', 'limits'}
LIMITS = {'compile_timeout_seconds': 300, 'max_output_bytes': 1024 * 1024,
          'max_source_bytes': 16 * 1024 * 1024, 'max_build_bytes': 512 * 1024 * 1024}
MAX_INPUT_BYTES = 1024 * 1024
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
COMPILER_PROGRAMS = ('cc1plus', 'as', 'collect2', 'ld')
# GCC's actual normal Linux link closure, never an inferred SDK availability flag.
LINK_INPUTS = ('Scrt1.o', 'crti.o', 'crtn.o', 'crtbeginS.o', 'crtendS.o',
               'libstdc++.so', 'libgcc.a', 'libgcc_s.so.1', 'libc.so', 'libc.so.6',
               'libc_nonshared.a', 'libm.so', 'libm.so.6', 'libmvec.so.1')


class ProbeError(ValueError):
    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


def require(condition: bool, message: str, code: str = 'SPEC_INVALID') -> None:
    if not condition:
        raise ProbeError(code, message)


def exact(value: object, keys: set[str], label: str) -> None:
    require(type(value) is dict and set(value) == keys, label + ' fields differ from fixed schema')


def digest(path: Path) -> str:
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(block)
    return result.hexdigest()


def strict_json(raw: bytes) -> object:
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value, 'Duplicate JSON field')
            value[key] = item
        return value
    def nonfinite(_value):
        raise ProbeError('JSON_INVALID', 'Nonfinite JSON value')
    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=nonfinite)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProbeError('JSON_INVALID', 'Invalid UTF-8 JSON') from error


def json_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def relative(value: object, *, directory: bool = False) -> str:
    require(type(value) is str and 0 < len(value) <= 1024 and '\\' not in value
            and '\x00' not in value and not any(c.isspace() for c in value), 'Invalid source-relative path')
    if directory and value == '.':
        return value
    path = PurePosixPath(value)
    require(not path.is_absolute() and '..' not in path.parts and str(path) == value
            and value not in ('.', '') and not value.startswith('-'), 'Noncanonical source-relative path')
    return value


def pin_shape(value: object) -> None:
    exact(value, {'path', 'sha256'}, 'File pin')
    require(type(value['path']) is str and Path(value['path']).is_absolute()
            and '\x00' not in value['path'] and '\n' not in value['path'], 'Pin must have an absolute path')
    require(type(value['sha256']) is str and HASH.fullmatch(value['sha256']) is not None, 'Invalid pin SHA256')


def validate_spec(value: object) -> dict:
    """Pure structural validation for publication; performs no filesystem reads."""
    exact(value, SPEC_KEYS, 'Probe specification')
    require(value['schema_version'] == SPEC_SCHEMA, 'Unsupported probe schema')
    require(value['capability'] == 'cpu-cxx20', 'Only cpu-cxx20 is supported', 'CAPABILITY_UNAVAILABLE')
    require(type(value['card_id']) is str and 0 < len(value['card_id']) <= 256, 'Original card identity required')
    require(type(value['source_card_sha256']) is str and HASH.fullmatch(value['source_card_sha256']) is not None,
            'Original source-card SHA256 required')
    pin_shape(value['toolchain'])
    pin_shape(value['probe'])
    files = value['source_files']
    require(type(files) is list and 1 <= len(files) <= 256, 'Bounded native source files required')
    paths = set()
    for item in files:
        exact(item, {'path', 'kind'}, 'Native source file')
        name = relative(item['path'])
        require(name not in paths, 'Duplicate native source file')
        paths.add(name)
        require(item['kind'] in ('translation_unit', 'header'), 'Unknown native source kind')
        if item['kind'] == 'translation_unit':
            require(Path(name).suffix.lower() in ('.cpp', '.cc', '.cxx'), 'C++20 translation unit required')
        else:
            require(Path(name).suffix.lower() in ('.h', '.hpp', '.hxx', '.hh', '.inc', '.inl', '.tpp'),
                    'Explicit C++ header required')
    includes = value['include_directories']
    require(type(includes) is list and len(includes) <= 32, 'Finite include directories required')
    for name in includes:
        relative(name, directory=True)
        require(name == '.' or any(path.startswith(name + '/') for path in paths),
                'Include directory has no declared source files')
    require(len(set(includes)) == len(includes), 'Duplicate include directory')
    exact(value['limits'], set(LIMITS), 'Probe limits')
    for key, maximum in LIMITS.items():
        require(type(value['limits'][key]) is int and 1 <= value['limits'][key] <= maximum, 'Invalid ' + key)
    require(type(value['cases']) is list and 1 <= len(value['cases']) <= 64, 'Finite declared cases required')
    names = set()
    for case in value['cases']:
        exact(case, {'name', 'timeout_seconds'}, 'Native case')
        require(type(case['name']) is str and CASE_NAME.fullmatch(case['name']) is not None, 'Invalid case name')
        require(case['name'] not in names, 'Duplicate native case')
        names.add(case['name'])
        require(type(case['timeout_seconds']) is int and 1 <= case['timeout_seconds'] <= 120, 'Invalid native timeout')
    return value


def validate_toolchain(value: object) -> dict:
    """Pure structural validation; an approved profile still needs real pins."""
    exact(value, {'schema_version', 'capability', 'platform', 'compiler', 'files'}, 'Toolchain manifest')
    require(value['schema_version'] == TOOLCHAIN_SCHEMA and value['capability'] == 'cpu-cxx20',
            'Unsupported toolchain capability', 'CAPABILITY_UNAVAILABLE')
    exact(value['platform'], {'os', 'machine'}, 'Toolchain platform')
    require(value['platform']['os'] == 'linux' and value['platform']['machine'] in ('x86_64', 'aarch64'),
            'Only declared Linux CPU platforms are supported', 'CAPABILITY_UNAVAILABLE')
    pin_shape(value['compiler'])
    require(type(value['files']) is list and 1 <= len(value['files']) <= 4096, 'Finite actual toolchain closure required')
    paths = {}
    for item in value['files']:
        pin_shape(item)
        require(item['path'] not in paths, 'Duplicate toolchain path')
        paths[item['path']] = item['sha256']
    require(paths.get(value['compiler']['path']) == value['compiler']['sha256'], 'Compiler must belong to toolchain closure')
    return value


def pinned_file(pin: dict, *, maximum: int | None = None, readonly: bool = False) -> Path:
    pin_shape(pin)
    path = Path(pin['path'])
    require(path.resolve() == path and path.is_file() and not path.is_symlink(),
            'Pinned input is absent or not a canonical regular file', 'PREREQUISITE_UNAVAILABLE')
    mode = path.stat().st_mode
    require(not readonly or not mode & 0o222, 'Trusted specification/probe must be frozen read-only', 'PREREQUISITE_MUTABLE')
    require(maximum is None or path.stat().st_size <= maximum, 'Pinned input exceeds byte budget', 'INPUT_BUDGET_EXCEEDED')
    require(digest(path) == pin['sha256'], 'Pinned input digest differs', 'PREREQUISITE_CHANGED')
    return path


def bounded_process(argv: list[str], cwd: Path, stdin: bytes, timeout: int, env: dict,
                    logs: Path, name: str, max_output: int, max_build: int) -> tuple[int, bytes, bytes]:
    def child_limits():
        resource.setrlimit(resource.RLIMIT_FSIZE, (max_build, max_build))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    stdin_path, stdout_path, stderr_path = (logs / (name + suffix) for suffix in ('.in', '.out', '.err'))
    stdin_path.write_bytes(stdin)
    process = None
    started = time.monotonic()
    try:
        with stdin_path.open('rb') as source, stdout_path.open('wb') as out, stderr_path.open('wb') as err:
            process = subprocess.Popen(argv, cwd=cwd, stdin=source, stdout=out, stderr=err,
                                       env=env, start_new_session=True, preexec_fn=child_limits)
            while process.poll() is None:
                require(time.monotonic() - started <= timeout, name + ' exceeded deadline', 'PROCESS_TIMEOUT')
                require(stdout_path.stat().st_size + stderr_path.stat().st_size <= max_output,
                        name + ' output exceeds limit', 'OUTPUT_BUDGET_EXCEEDED')
                size = sum(path.stat().st_size for path in logs.rglob('*') if path.is_file() and not path.is_symlink())
                require(size <= max_build, name + ' temporary files exceed limit', 'BUILD_BUDGET_EXCEEDED')
                time.sleep(0.025)
        require(stdout_path.stat().st_size + stderr_path.stat().st_size <= max_output,
                name + ' output exceeds limit', 'OUTPUT_BUDGET_EXCEEDED')
        final_size = sum(path.stat().st_size for path in logs.rglob('*') if path.is_file() and not path.is_symlink())
        require(final_size <= max_build, name + ' temporary files exceed limit', 'BUILD_BUDGET_EXCEEDED')
        stdout, stderr = stdout_path.read_bytes(), stderr_path.read_bytes()
        require(process.returncode >= 0, name + ' terminated by signal', 'PROCESS_SIGNAL')
        return process.returncode, stdout, stderr
    finally:
        if process is not None:
            # The outer Core cgroup owns the full lifecycle. Also stop this
            # invocation's own group, including children left after its leader.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()


def compiler_component(compiler: str, flag: str, env: dict, deadline: float) -> str:
    remaining = deadline - time.monotonic()
    require(remaining > 0, 'Toolchain discovery exceeded compile deadline', 'PROCESS_TIMEOUT')
    result = subprocess.run([compiler, flag], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, env=env, timeout=min(5, remaining), check=False)
    require(result.returncode == 0 and 0 < len(result.stdout) <= 4096,
            'Compiler could not resolve its actual runtime component', 'TOOLCHAIN_INCOMPLETE')
    value = result.stdout.decode('utf-8').strip()
    path = Path(value) if '/' in value else Path(shutil.which(value, path=env['PATH']) or '/unavailable')
    return str(path.resolve())


def dependency_paths(raw: str) -> list[str]:
    """Read GCC Make dependency output with escaped whitespace/backslashes."""
    text = raw.replace('\\\n', '')
    require(': ' in text, 'Compiler dependency output missing', 'DEPENDENCY_UNVERIFIED')
    text = text.split(': ', 1)[1]
    result, current, escape = [], [], False
    for character in text:
        if escape:
            current.append(character)
            escape = False
        elif character == '\\':
            escape = True
        elif character.isspace():
            if current:
                result.append(''.join(current))
                current = []
        else:
            current.append(character)
    require(not escape, 'Incomplete dependency escape', 'DEPENDENCY_UNVERIFIED')
    if current:
        result.append(''.join(current))
    return result


def verify_runtime_dependencies(program: Path, closure: dict[str, str], env: dict,
                                temporary: Path, label: str, deadline: float,
                                limits: dict) -> None:
    inspector = Path('/usr/bin/ldd').resolve()
    require(str(inspector) in closure, 'Actual runtime dependency inspector is not approved', 'TOOLCHAIN_INCOMPLETE')
    remaining = deadline - time.monotonic()
    require(remaining > 0, 'Dependency inspection exceeded compile deadline', 'PROCESS_TIMEOUT')
    code, stdout, stderr = bounded_process([str(inspector), str(program)], temporary, b'',
                                           min(5, remaining), env, temporary, label,
                                           limits['max_output_bytes'], limits['max_build_bytes'])
    require(code == 0 and not stderr.strip(), 'Actual runtime dependency inspection failed', 'TOOLCHAIN_INCOMPLETE')
    for line in stdout.decode('utf-8').splitlines():
        line = line.strip()
        if line.startswith(('linux-vdso.so.', 'linux-gate.so.')):
            continue  # Kernel virtual mapping, not an invented SDK file pin.
        match = re.fullmatch(r'(?:\S+\s+=>\s+)?(/\S+)\s+\(0x[0-9a-fA-F]+\)', line)
        require(match is not None, 'Unresolved or unrecognized runtime dependency', 'TOOLCHAIN_INCOMPLETE')
        path = str(Path(match.group(1)).resolve())
        require(path in closure, 'Actual runtime library was not admitted: ' + path, 'TOOLCHAIN_INCOMPLETE')


def run_probe(spec_path: Path, case_name: str, stdin: bytes) -> int:
    require(spec_path.is_absolute() and spec_path.resolve() == spec_path and spec_path.is_file()
            and not spec_path.stat().st_mode & 0o222 and spec_path.stat().st_size <= MAX_MANIFEST_BYTES,
            'Role specification must be an immutable absolute regular file', 'SPEC_INVALID')
    spec_raw = spec_path.read_bytes()
    spec = validate_spec(strict_json(spec_raw))
    case = next((item for item in spec['cases'] if item['name'] == case_name), None)
    require(case is not None, 'Case was not published in this role specification')
    require(len(stdin) <= MAX_INPUT_BYTES, 'Probe stdin exceeds budget', 'INPUT_BUDGET_EXCEEDED')
    source_root = Path(os.environ.get('SPLATFORGE_SOURCE_ROOT', '/unavailable')).resolve()
    scratch_root = Path(os.environ.get('SPLATFORGE_VERIFIER_SCRATCH', '/unavailable')).resolve()
    require(source_root.is_dir() and source_root == Path.cwd().resolve(), 'Bound candidate root is missing', 'BINDING_UNAVAILABLE')
    require(scratch_root.is_dir() and scratch_root != source_root and not scratch_root.is_relative_to(source_root)
            and not source_root.is_relative_to(scratch_root), 'Separate verifier scratch is missing', 'BINDING_UNAVAILABLE')
    require(not spec_path.is_relative_to(source_root), 'Trusted role specification cannot reside in candidate root')
    toolchain_path = pinned_file(spec['toolchain'], maximum=MAX_MANIFEST_BYTES, readonly=True)
    toolchain = validate_toolchain(strict_json(toolchain_path.read_bytes()))
    require(toolchain['platform'] == {'os': platform.system().lower(), 'machine': platform.machine()},
            'Actual host differs from admitted CPU platform', 'CAPABILITY_UNAVAILABLE')
    closure = {item['path']: item['sha256'] for item in toolchain['files']}
    for item in toolchain['files']:
        pinned_file(item)
    compiler = pinned_file(toolchain['compiler'])
    require(os.access(compiler, os.X_OK) and re.search(r'(?:^|-)g\+\+(?:-\d+)?$', compiler.name),
            'This profile requires the admitted GCC C++ compiler', 'CAPABILITY_UNAVAILABLE')
    probe = pinned_file(spec['probe'], maximum=spec['limits']['max_source_bytes'], readonly=True)
    require(not probe.is_relative_to(source_root), 'Independent probe cannot reside in candidate root')
    before = {}
    total = probe.stat().st_size
    for item in spec['source_files']:
        path = source_root / item['path']
        require(path.resolve() == path and path.is_file() and not path.is_symlink(),
                'Declared product source is missing or redirected', 'SOURCE_UNAVAILABLE')
        total += path.stat().st_size
        before[item['path']] = digest(path)
    require(total <= spec['limits']['max_source_bytes'], 'Product/probe source exceeds budget', 'INPUT_BUDGET_EXCEEDED')
    limits = spec['limits']
    with tempfile.TemporaryDirectory(prefix='native-cxx20-', dir=scratch_root) as name:
        temporary = Path(name)
        source_view = temporary / 'source'
        source_view.mkdir(mode=0o700)
        env = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
               'HOME': str(temporary), 'TMPDIR': str(temporary), 'SOURCE_DATE_EPOCH': '0'}
        compile_deadline = time.monotonic() + limits['compile_timeout_seconds']
        # These fixed discovery queries only read the approved compiler's search
        # configuration. Every resolved executable and link input must be pinned.
        programs = [compiler]
        for component in COMPILER_PROGRAMS:
            actual = compiler_component(str(compiler), '-print-prog-name=' + component, env, compile_deadline)
            require(actual in closure, 'Missing approved compiler component: ' + component, 'TOOLCHAIN_INCOMPLETE')
            programs.append(Path(actual))
        for component in LINK_INPUTS:
            actual = compiler_component(str(compiler), '-print-file-name=' + component, env, compile_deadline)
            require(actual in closure, 'Missing approved linker input: ' + component, 'TOOLCHAIN_INCOMPLETE')
        for index, program in enumerate(programs):
            verify_runtime_dependencies(program, closure, env, temporary, 'tool-runtime-' + str(index), compile_deadline, limits)
        for item in spec['source_files']:
            destination = source_view / item['path']
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            shutil.copyfile(source_root / item['path'], destination)
            destination.chmod(0o400)
            require(digest(destination) == before[item['path']], 'Product source changed during copy', 'SOURCE_CHANGED')
        probe_copy = temporary / 'independent-probe.cpp'
        shutil.copyfile(probe, probe_copy)
        probe_copy.chmod(0o400)
        require(digest(probe_copy) == spec['probe']['sha256'], 'Independent probe changed during copy', 'PREREQUISITE_CHANGED')
        source_paths = [source_view / item['path'] for item in spec['source_files'] if item['kind'] == 'translation_unit']
        source_paths.append(probe_copy)
        product_sources = {str((source_view / item['path']).resolve()) for item in spec['source_files']}
        known_sources = product_sources | {str(probe_copy)}
        actual_dependencies = set()
        objects = []
        for index, translation_unit in enumerate(source_paths):
            obj, deps = temporary / f'unit-{index}.o', temporary / f'unit-{index}.d'
            argv = [str(compiler), '-std=c++20', '-O0', '-g0', '-fdiagnostics-color=never',
                    '-MD', '-MF', str(deps), '-MT', 'unit', '-I', str(source_view)]
            for directory in spec['include_directories']:
                argv += ['-I', str(source_view / directory)]
            argv += ['-c', str(translation_unit), '-o', str(obj)]
            remaining = compile_deadline - time.monotonic()
            require(remaining > 0, 'Compilation exceeded total deadline', 'PROCESS_TIMEOUT')
            code, _out, err = bounded_process(argv, source_view, b'', remaining, env,
                                              temporary, 'compile-' + str(index), limits['max_output_bytes'], limits['max_build_bytes'])
            if err:
                sys.stderr.buffer.write(err)
            require(code == 0, 'Actual product/probe compilation failed', 'COMPILE_FAILED')
            require(deps.is_file(), 'Actual compilation dependency receipt missing', 'DEPENDENCY_UNVERIFIED')
            for dependency in dependency_paths(deps.read_text()):
                absolute = str((source_view / dependency).resolve())
                actual_dependencies.add(absolute)
                require(absolute in known_sources or absolute in closure,
                        'Actual compiler dependency was not admitted: ' + absolute, 'TOOLCHAIN_INCOMPLETE')
            objects.append(str(obj))
        require(product_sources <= actual_dependencies,
                'Declared native source/header was not actually compiled', 'PRODUCT_NOT_EXECUTED')
        binary = temporary / 'native-probe'
        remaining = compile_deadline - time.monotonic()
        require(remaining > 0, 'Compilation exceeded total deadline', 'PROCESS_TIMEOUT')
        code, _out, err = bounded_process([str(compiler), '-Wl,--build-id=none', *objects, '-o', str(binary)],
                                          source_view, b'', remaining, env, temporary,
                                          'link', limits['max_output_bytes'], limits['max_build_bytes'])
        if err:
            sys.stderr.buffer.write(err)
        require(code == 0 and binary.is_file(), 'Actual product/probe linking failed', 'LINK_FAILED')
        binary.chmod(0o500)
        verify_runtime_dependencies(binary, closure, env, temporary, 'probe-runtime', compile_deadline, limits)
        code, stdout, stderr = bounded_process([str(binary), '--case', case_name], temporary, stdin,
                                               case['timeout_seconds'], env, temporary, 'probe',
                                               limits['max_output_bytes'], limits['max_build_bytes'])
        require(code != 125, 'Native exit 125 is reserved for unavailable/invalid execution', 'PROCESS_RESERVED_EXIT')
        actual = strict_json(stdout)
        require(type(actual) in (dict, list), 'Native output must be a real JSON object or array', 'OUTPUT_INVALID')
        # Verify input identities after the executable has actually run. Expected
        # values stay in the separately frozen recipe, never in this adapter.
        require(spec_path.read_bytes() == spec_raw, 'Frozen role specification changed', 'PREREQUISITE_CHANGED')
        for item in spec['source_files']:
            require(digest(source_root / item['path']) == before[item['path']], 'Product source changed', 'SOURCE_CHANGED')
        pinned_file(spec['probe'], readonly=True)
        pinned_file(spec['toolchain'], readonly=True)
        for item in toolchain['files']:
            pinned_file(item)
        if stderr:
            sys.stderr.buffer.write(stderr)
        sys.stdout.buffer.write(json_bytes(actual))
        return code


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--spec', type=Path, required=True)
    parser.add_argument('--case', required=True)
    args = parser.parse_args()
    try:
        stdin = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
        return run_probe(args.spec, args.case, stdin)
    except Exception as error:
        code = error.code if isinstance(error, ProbeError) else 'PROBE_ERROR'
        sys.stderr.buffer.write(json_bytes({'schema_version': 'forgeflow.native-build-probe-error.v1',
                                           'code': code, 'message': str(error), 'business_cases_passed': 0}))
        return 125


if __name__ == '__main__':
    raise SystemExit(main())
