#!/usr/bin/env python3
"""Prepare or inspect one finite real Rust physical-fence proof, never launch it.

The delegated launcher and Root GO perform the separate service start. This
collector only pins inputs or reads retained actual subprocess/kernel evidence.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import stat
import sys

ROOT = Path(__file__).resolve().parents[1]
LIMITS = {'cpu_quota_us': 25000, 'cpu_period_us': 100000,
          'memory_max_bytes': 67108864, 'memory_swap_max_bytes': 0,
          'pids_max': 8, 'memory_oom_group': True}
EXPECTED = {'cpu.max': '25000 100000', 'memory.max': '67108864',
            'memory.swap.max': '0', 'pids.max': '8', 'memory.oom.group': '1'}


def sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def regular(path: Path) -> None:
    if not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError('A regular nonsymlink evidence/input file is required')


def write_json(path: Path, value: object) -> None:
    with path.open('x') as stream:
        os.chmod(path, 0o600)
        stream.write(json.dumps(value, ensure_ascii=False, indent=2) + '\n')
        stream.flush()
        os.fsync(stream.fileno())


def prepare(args: argparse.Namespace) -> None:
    for path in (args.receipt, args.runtime_program): regular(path)
    receipt = json.loads(args.receipt.read_text())
    if receipt.get('schema_version') != 'forgeflow.build-checkpoint.v1':
        raise ValueError('An immutable build-checkpoint receipt is required')
    if not receipt.get('consistent_copy') or not receipt.get('source_unchanged_after_build'):
        raise ValueError('Compilation input consistency is unconfirmed')
    builds = [c for c in receipt['commands'] if c['argv'][:2] == ['cargo', 'build']]
    if not builds or any(c['exit_code'] != 0 for c in builds):
        raise ValueError('Actual successful Cargo build receipt required')
    program_hash = sha(args.runtime_program)
    if program_hash != receipt['binaries']['forgeflow-worker']['sha256']:
        raise ValueError('Runtime Worker binary does not match the build receipt')
    python = Path(sys.executable).resolve(strict=True)
    helper = ROOT / 'verification/physical_resource_helper.py'
    regular(python); regular(helper)
    destination = args.output.absolute()
    if destination.parent.resolve(strict=True) != destination.parent:
        raise ValueError('Proof destination needs an absolute resolved parent')
    destination.mkdir(mode=0o700)
    output_dir = destination / 'runtime'
    # Runtime owns creation of its fresh journal/output directory.
    config = {'schema_version': 'forgeflow.physical-resource-probe.v1',
              'delegation': None, 'program': str(python), 'program_sha256': sha(python),
              'args': ['-I', str(helper)], 'output_dir': str(output_dir),
              'limits': LIMITS, 'timeout_seconds': 20}
    config_path = destination / 'probe-input.json'
    write_json(config_path, config)
    preparation = {
        'schema_version': 'forgeflow.physical-resource-proof-preparation.v1',
        'status': 'PREPARED_NO_ACTOR', 'models': 0, 'apis': 0, 'worker_services': 0,
        'root_go_required_for_actor_start': True,
        'runtime_program': {'path': str(args.runtime_program.absolute()), 'sha256': program_hash},
        'build_receipt': {'path': str(args.receipt.absolute()), 'sha256': sha(args.receipt),
                          'source_identity': receipt['source_identity']},
        'helper': {'path': str(helper), 'sha256': sha(helper)},
        'python': {'path': str(python), 'sha256': config['program_sha256']},
        'probe_input': {'path': str(config_path), 'sha256': sha(config_path)},
        'output_dir': str(output_dir), 'limits': LIMITS,
        'predeclared_oracles': {
            'cpu_seconds': 8, 'quota_allowance_periods': 2,
            'max_fork_attempts': 16, 'requested_memory_bytes': 128 * 1024 * 1024,
            'memory_chunk_bytes': 4 * 1024 * 1024, 'total_timeout_seconds': 20,
            'cpu_requirement': 'positive nr_throttled/throttled_usec and usage bounded by exactquota*wall/period plus2quota allowance;host starvation without throttling is INCONCLUSIVE',
            'memory_requirement': 'actual memory.events.local oom_kill delta>0, SIGKILL, child wait/reap and group populated0; transient memory.peak>memory.max is not itself failure',
            'pids_requirement': 'actual fork EAGAIN plus positive pids.events max delta and all forked children reaped',
            'supervisor_requirement': 'actual supervisor remains alive outside limited attempt leaf through group-empty check',
        },
        'qualification': 'At most one local finite CPU/memory/pids physical fence through real Rust supervise_physical; no canonical admission, DSH, provider,100+ or production qualification',
    }
    prepared_path = destination / 'prepared.json'
    write_json(prepared_path, preparation)
    print(json.dumps({'status': preparation['status'], 'prepared': str(prepared_path),
                      'prepared_sha256': sha(prepared_path), 'probe_input': str(config_path),
                      'runtime_program_sha256': program_hash, 'actor_started': False}))


def counters(value: str | None) -> dict[str, int]:
    if value is None: return {}
    return {line.split()[0]: int(line.split()[1]) for line in value.splitlines()}


def collect(args: argparse.Namespace) -> bool:
    regular(args.prepared)
    if sha(args.prepared) != args.prepared_sha256:
        raise ValueError('Prepared proof identity changed')
    prepared = json.loads(args.prepared.read_text())
    for key in ('runtime_program', 'build_receipt', 'helper', 'python', 'probe_input'):
        item = prepared[key]; path = Path(item['path']); regular(path)
        if sha(path) != item['sha256']: raise ValueError('Pinned input changed: ' + key)
    directory = Path(prepared['output_dir'])
    report_path = directory / 'runtime-report.json'
    stdout_path = directory / 'stdout.ndjson'
    stderr_path = directory / 'stderr.log'
    for path in (report_path, stdout_path, stderr_path): regular(path)
    runtime = json.loads(report_path.read_text())
    records = []
    truncated_final_line = None
    raw_lines = stdout_path.read_bytes().splitlines(keepends=True)
    for index, raw in enumerate(raw_lines):
        try: records.append(json.loads(raw))
        except (ValueError, UnicodeDecodeError):
            if index != len(raw_lines) - 1 or raw.endswith(b'\n'):
                raise ValueError('Malformed complete helper observation')
            truncated_final_line = {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
    by_stage = {}
    for record in records:
        if record.get('schema_version') != 'forgeflow.physical-helper-observation.v1':
            raise ValueError('Unexpected helper observation schema')
        by_stage.setdefault(record['stage'], []).append(record)
    checks = []
    def check(name, passed, detail=None):
        checks.append({'name': name, 'passed': bool(passed), 'detail': detail})
    def one(name):
        values = by_stage.get(name, [])
        if len(values) != 1: raise ValueError('Expected one actual helper observation: ' + name)
        return values[0]
    initial = one('membership_before_work'); cpu = one('cpu_complete')
    pids = one('pids_denial'); pids_reaped = one('pids_children_reaped'); memory = one('memory_begin')
    launch = runtime['launch_receipt']; stop = runtime['stop_receipt']
    identity = launch['process']
    check('actual_runtime_supervise_physical_path', runtime.get('runtime_api') == 'supervise_physical')
    check('membership_before_any_work', initial['workload_started'] is False)
    check('exact_process_launch_identity', initial['pid'] == identity['pid'] and
          int(initial['start_ticks']) == identity['start_ticks'] and initial['boot_id'] == identity['boot_id'])
    group = runtime['attempt_cgroup']
    check('helper_inside_exact_attempt_leaf', initial['cgroup_path'] == group and
          initial['membership'] == '0::' + group.removeprefix('/sys/fs/cgroup') and
          not group.endswith('/supervisor'))
    check('actual_exact_limits_before_work', all(initial['actual_files'].get(k) == v for k, v in EXPECTED.items()))
    check('runtime_limit_readbacks', all(runtime['limits_readback'].get(k) == v for k, v in EXPECTED.items()))
    cpu_before = counters(initial['actual_files']['cpu.stat']); cpu_after = counters(cpu['actual_files']['cpu.stat'])
    delta = {k: cpu_after.get(k, 0) - cpu_before.get(k, 0) for k in ('usage_usec', 'nr_throttled', 'throttled_usec')}
    elapsed = cpu['elapsed_ns'] / 1e9
    allowed = math.ceil(elapsed * 1e6 * LIMITS['cpu_quota_us'] / LIMITS['cpu_period_us']) + 2 * LIMITS['cpu_quota_us']
    check('actual_cpu_phase8s', 8 <= elapsed <= 12, {'elapsed_seconds': elapsed})
    check('actual_cpu_throttle_positive', delta['nr_throttled'] > 0 and delta['throttled_usec'] > 0, delta)
    check('cpu_usage_with_predeclared_allowance', 0 < delta['usage_usec'] <= allowed,
          {'usage_usec': delta['usage_usec'], 'allowed_usec': allowed, 'allowance_periods': 2})
    pids_delta = counters(pids['actual_files']['pids.events']).get('max', 0) - counters(pids['files_before']['pids.events']).get('max', 0)
    check('actual_finite_fork_EAGAIN', pids['fork_errno'] == 11 and 0 < pids['successful_forks'] < 16)
    check('actual_positive_pids_max_event', pids_delta > 0, {'max_event_delta': pids_delta})
    check('fork_children_reaped', pids_reaped['child_count'] == pids['successful_forks'] and
          int(pids_reaped['actual_files']['pids.current']) == 1)
    memory_before = counters(memory['actual_files'].get('memory.events.local') or memory['actual_files']['memory.events'])
    memory_after = counters(runtime['files_after'].get('memory.events.local') or runtime['files_after']['memory.events'])
    memory_delta = {k: memory_after.get(k, 0) - memory_before.get(k, 0) for k in ('oom', 'oom_kill', 'oom_group_kill')}
    check('actual_memory_OOM_kill', memory_delta['oom'] > 0 and memory_delta['oom_kill'] > 0, memory_delta)
    check('expected_oom_signal_and_actual_reap', stop['signal'] == 9 and stop['process_exit_confirmed'] and runtime['child_reaped'])
    check('no_false_memory_completion', 'unexpected_memory_completion' not in by_stage)
    check('positive_attempt_group_empty', runtime['cgroup_empty'] and
          counters(runtime['files_after']['cgroup.events']).get('populated') == 0 and
          not runtime['files_after']['cgroup.procs'].strip())
    check('supervisor_alive_outside_attempt', runtime['supervisor_alive_after'] and
          runtime['supervisor_pid'] != initial['pid'] and
          runtime['supervisor_membership'].strip() == '0::' + runtime['delegation']['root_path'].removeprefix('/sys/fs/cgroup') + '/supervisor')
    failed = [c['name'] for c in checks if not c['passed']]
    status = 'PASS_LOCAL_PHYSICAL_FENCE' if not failed else 'FAIL'
    if failed == ['actual_cpu_throttle_positive']:
        status = 'INCONCLUSIVE_NO_OBSERVED_CPU_THROTTLING'
    result = {'schema_version': 'forgeflow.physical-resource-oracle.v1', 'status': status,
              'scope': prepared['qualification'], 'checks': checks, 'assertions': len(checks),
              'failed': len(failed), 'failed_names': failed, 'cpu': {'elapsed_seconds': elapsed, **delta},
              'memory_event_delta': memory_delta, 'pids_max_event_delta': pids_delta,
              'incomplete_final_line_retained': truncated_final_line,
              'original_inputs': prepared, 'runtime_report_sha256': sha(report_path),
              'stdout_sha256': sha(stdout_path), 'stderr_sha256': sha(stderr_path),
              'models': 0, 'apis': 0, 'main_runtime_changed': False,
              'limitations': ['Only one finite trusted-helper/kernel/UID/unit/binary scope',
                              'No canonical admission, native-child pool, hostile workload, DSH, provider/model cost or100+ qualification',
                              'CPU bandwidth is not exclusive core allocation; memory.max can transiently overrun',
                              'No controller or membership writes by this read-only collector']}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    write_json(args.output, result)
    print(json.dumps({'status': status, 'report': str(args.output), 'report_sha256': sha(args.output),
                      'assertions': len(checks), 'failed': len(failed)}))
    return status == 'PASS_LOCAL_PHYSICAL_FENCE'


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('prepare')
    p.add_argument('--runtime-program', type=Path, required=True)
    p.add_argument('--receipt', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p = sub.add_parser('collect')
    p.add_argument('--prepared', type=Path, required=True)
    p.add_argument('--prepared-sha256', required=True)
    p.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == 'prepare': prepare(args)
        else: return 0 if collect(args) else 1
    except (OSError, ValueError, KeyError, TypeError) as error:
        failure = {'status': 'INCONCLUSIVE_INFRASTRUCTURE', 'error_type': type(error).__name__,
                   'message': str(error), 'original_evidence_preserved': True}
        if args.command == 'collect' and not args.output.exists():
            try:
                args.output.parent.mkdir(parents=True, exist_ok=True)
                write_json(args.output, failure)
            except OSError:
                pass
        print(json.dumps(failure), file=sys.stderr)
        return 1
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
