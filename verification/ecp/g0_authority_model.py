#!/usr/bin/env python3
"""Bounded transition exploration for G0 theory; NOT a production verifier.

Two symbolic principals/workspaces, one task, one parent grant, two generations,
worker IDs and payloads. It models safety only; no DB, real credentials, Gate,
clock/expiry, crash, multi-task, fairness, or implementation equivalence.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import re
from pathlib import Path
import subprocess
from collections import deque
from dataclasses import asdict, dataclass, replace
import json


@dataclass(frozen=True)
class State:
    grant: str  # ABSENT, ACTIVE, REVOKED
    generation: int = 0
    active: bool = False
    claimed: bool = False
    lease_generation: int = 0
    fence_epoch: int = 0
    binding: tuple[int, int] | None = None  # principal, workspace; grant is symbolic
    pending: tuple[int, int, int] | None = None  # principal, workspace, payload
    checked: bool = False  # authorization seen before an unlocked commit
    cached: tuple[int, int, int] | None = None  # principal, workspace, payload
    event_payload: int = 0
    effects: int = 0  # saturated at 2; enough to witness duplicate effect


@dataclass(frozen=True)
class Policy:
    name: str
    subject_binding: bool = True
    check_at_commit: bool = True
    auth_before_replay: bool = True
    enforce_fence: bool = True
    auth_at_effect: bool = True
    require_claim: bool = True
    deduplicate_event: bool = True
    reject_conflicting_payload: bool = True


POLICIES = (
    Policy('candidate'),
    Policy('unbound_subject', subject_binding=False),
    Policy('unlocked_check_then_commit', check_at_commit=False),
    Policy('replay_before_auth', auth_before_replay=False),
    Policy('missing_fence', enforce_fence=False),
    Policy('effect_after_revoke', auth_at_effect=False),
    Policy('effect_before_claim', require_claim=False),
    Policy('duplicate_effect', deduplicate_event=False),
    Policy('accept_payload_conflict', reject_conflicting_payload=False),
)
EXPECTED = {
    'unbound_subject': 'E01_UNBOUND_ADMISSION',
    'unlocked_check_then_commit': 'E02_POST_REVOKE_COMMIT',
    'replay_before_auth': 'E02_POST_REVOKE_REPLAY',
    'missing_fence': 'I05_OLD_GENERATION',
    'effect_after_revoke': 'E02_POST_REVOKE_EFFECT',
    'effect_before_claim': 'DISPATCH_EFFECT_WITHOUT_CLAIM',
    'duplicate_effect': 'I06_DUPLICATE_EFFECT',
    'accept_payload_conflict': 'E06_CONFLICT_ACCEPTED',
}


def authority(state: State, principal: int, workspace: int) -> bool:
    # Only p0 has an active grant in w0; the other principal/workspace are denied.
    return state.grant == 'ACTIVE' and principal == 0 and workspace == 0


def raw_transitions(state: State, policy: Policy):
    """Yield semantic transitions; violations are checked separately."""
    if state.grant == 'ACTIVE':
        yield 'revoke_commit', replace(state, grant='REVOKED'), ('revocation',)
    if not state.active and state.pending is None and state.generation < 2:
        for principal in range(2):
            for workspace in range(2):
                for payload in (1, 2):
                    checked = authority(state, principal, workspace)
                    yield f'begin_admit(p{principal},w{workspace},v{payload})', replace(
                        state, pending=(principal, workspace, payload), checked=checked
                    ), ()
    if state.pending is not None:
        principal, workspace, payload = state.pending
        if not policy.subject_binding:
            allowed = True
        elif policy.check_at_commit:
            # Abstract atomic permission check + binding + commit; no separate
            # authorization revocation can interleave in this single step.
            allowed = authority(state, principal, workspace)
        else:
            allowed = state.checked
        if allowed:
            cached = state.cached or (principal, workspace, payload)
            tags = ('admission', 'second_generation') if state.generation == 1 else ('admission',)
            yield 'admit_commit', replace(state, generation=state.generation + 1,
                active=True, claimed=False, lease_generation=state.generation + 1, fence_epoch=state.generation + 1,
                binding=(principal, workspace), pending=None, checked=False, cached=cached), tags
        else:
            tags = ['admit_denial']
            if state.grant == 'ACTIVE' and principal != 0 and workspace == 0: tags.append('wrong_principal_rejected')
            if state.grant == 'ACTIVE' and principal == 0 and workspace != 0: tags.append('wrong_workspace_rejected')
            yield 'admit_deny', replace(state, pending=None, checked=False), tuple(tags)
    if state.active:
        yield 'close_attempt', replace(state, active=False, claimed=False), ('close',)
        if not state.claimed:
            if state.binding is not None and authority(state, *state.binding):
                yield 'claim_allow', replace(state, claimed=True), ('claim',)
            elif state.grant == 'REVOKED':
                yield 'claim_deny', state, ('revoked_claim_rejected',)
    if state.cached is not None:
        principal, workspace, original = state.cached
        for payload in (1, 2):
            authorized = authority(state, principal, workspace)
            replay_authorized = authorized or not policy.auth_before_replay
            conflict = payload != original
            accepted = replay_authorized and (not conflict or not policy.reject_conflicting_payload)
            tags = []
            if accepted and not conflict: tags.append('matching_replay')
            if not accepted and conflict and authorized: tags.append('conflict_rejected')
            if not accepted and state.grant == 'REVOKED' and not conflict: tags.append('unauthorized_replay_rejected')
            yield f'replay(v{payload},{"return" if accepted else "deny"})', state, tuple(tags)
    if state.active:
        for gen in (1, 2):
            for worker in (0, 1):
                for payload in (1, 2):
                    auth = state.binding is not None and authority(state, *state.binding)
                    identity = (gen == state.generation == state.lease_generation == state.fence_epoch
                                and worker == 0)
                    can_run = ((auth or not policy.auth_at_effect) and (identity or not policy.enforce_fence)
                               and (state.claimed or not policy.require_claim))
                    tags = []
                    outcome = 'deny'
                    next_state = state
                    if can_run:
                        if state.event_payload == 0:
                            outcome = 'effect'
                            next_state = replace(state, event_payload=payload, effects=1)
                            tags.append('event_effect')
                        elif payload == state.event_payload:
                            outcome = 'replay'
                            if not policy.deduplicate_event:
                                next_state = replace(state, effects=min(2, state.effects + 1))
                            else:
                                tags.append('event_replay_without_effect')
                        elif not policy.reject_conflicting_payload:
                            outcome = 'conflict_return'
                        else:
                            outcome = 'conflict_reject'
                            tags.append('event_conflict_rejected')
                    else:
                        if auth and state.claimed and gen < state.generation and worker == 0: tags.append('stale_generation_rejected')
                        if auth and state.claimed and gen == state.generation and worker != 0: tags.append('wrong_worker_rejected')
                        if state.grant == 'REVOKED' and state.claimed and identity: tags.append('revoked_effect_rejected')
                        if auth and not state.claimed and identity: tags.append('preclaim_effect_rejected')
                    yield f'event(g{gen},w{worker},v{payload},{outcome})', next_state, tuple(tags)


def check_edge(before: State, label: str, after: State):
    """Independent assertions over transition observations, not policy flags."""
    violations = []
    if label == 'admit_commit':
        principal, workspace, _ = before.pending
        if principal != 0 or workspace != 0 or before.grant == 'ABSENT':
            violations.append('E01_UNBOUND_ADMISSION')
        if before.grant == 'REVOKED':
            violations.append('E02_POST_REVOKE_COMMIT')
    replay = re.fullmatch(r'replay\(v([12]),(return|deny)\)', label)
    if label.startswith('replay(') and replay is None:
        raise ValueError('unrecognized replay transition')
    if replay and replay.group(2) == 'return':
        payload = int(replay.group(1))
        if before.grant == 'REVOKED':
            violations.append('E02_POST_REVOKE_REPLAY')
        if payload != before.cached[2]:
            violations.append('E06_CONFLICT_ACCEPTED')
    event = re.fullmatch(r'event\(g([12]),w([01]),v([12]),(deny|effect|replay|conflict_return|conflict_reject)\)', label)
    if label.startswith('event(') and event is None:
        raise ValueError('unrecognized event transition')
    if event and event.group(4) in ('effect', 'replay', 'conflict_return'):
        gen, worker, payload = map(int, event.group(1, 2, 3))
        if not before.claimed:
            violations.append('DISPATCH_EFFECT_WITHOUT_CLAIM')
        if before.grant == 'REVOKED' and after.effects > before.effects:
            violations.append('E02_POST_REVOKE_EFFECT')
        if gen < before.generation:
            violations.append('I05_OLD_GENERATION')
        elif gen > before.generation:
            violations.append('I05_FUTURE_GENERATION')
        if worker != 0:
            violations.append('I05_WRONG_WORKER')
        if before.event_payload == payload and after.effects > before.effects:
            violations.append('I06_DUPLICATE_EFFECT')
        if before.event_payload and before.event_payload != payload and event.group(4) == 'conflict_return':
            violations.append('E06_CONFLICT_ACCEPTED')
    if (not label.startswith(('begin_admit(', 'replay(', 'event('))
            and label not in ('revoke_commit', 'admit_commit', 'admit_deny', 'close_attempt', 'claim_allow', 'claim_deny')):
        raise ValueError('unrecognized transition')
    return tuple(violations)


def transitions(state: State, policy: Policy):
    for label, after, tags in raw_transitions(state, policy):
        yield label, after, check_edge(state, label, after), tags


def trace(parents, state):
    out = []
    while parents[state] is not None:
        previous, label = parents[state]
        out.append(label)
        state = previous
    out.reverse()
    return out


def explore(policy: Policy):
    # Two initial states distinguish absent from active grant; no grant is
    # manufactured by a transition. A revoke only changes ACTIVE to REVOKED.
    starts = (State('ABSENT'), State('ACTIVE'))
    parents = {state: None for state in starts}
    todo = deque(starts)
    violations, witnesses = {}, {}
    edges = 0
    while todo:
        state = todo.popleft()
        for label, next_state, errors, tags in transitions(state, policy):
            edges += 1
            path = [f'initial_grant={state_origin(parents, state).grant}', *trace(parents, state), label]
            for error in errors:
                violations.setdefault(error, path)
            for tag in tags:
                witnesses.setdefault(tag, path)
            if next_state not in parents:
                parents[next_state] = (state, label)
                todo.append(next_state)
    return {'policy': policy.name, 'states': len(parents), 'transitions': edges,
            'violations': violations, 'witnesses': witnesses, 'complete_within_declared_bounds': True}


def state_origin(parents, state):
    while parents[state] is not None:
        state = parents[state][0]
    return state


@dataclass(frozen=True)
class LockState:
    pc0: int = 0
    pc1: int = 0
    a: int = -1  # -1 free, 0/1 owner
    b: int = -1


def lock_transitions(s: LockState, reversed_second: bool):
    # Each transaction obtains two exclusive locks, performs one abstract
    # commit, then releases both. No abort/timeout/other lock is modeled.
    for actor in (0, 1):
        pc = s.pc0 if actor == 0 else s.pc1
        if pc >= 3: continue
        if pc == 2:
            yield f't{actor}:commit_release', replace(s, **{f'pc{actor}': 3, 'a': -1, 'b': -1})
            continue
        first, second = ('b', 'a') if actor == 1 and reversed_second else ('a', 'b')
        name = first if pc == 0 else second
        if getattr(s, name) == -1:
            yield f't{actor}:lock_{name}', replace(s, **{f'pc{actor}': pc + 1, name: actor})


def explore_locks(reversed_second: bool):
    start = LockState()
    parents = {start: None}
    todo = deque([start])
    edges, deadlocks, completed = 0, [], None
    while todo:
        state = todo.popleft()
        choices = list(lock_transitions(state, reversed_second))
        if not choices and (state.pc0 != 3 or state.pc1 != 3):
            deadlocks.append([*trace(parents, state), f'blocked: {asdict(state)}'])
        if state.pc0 == state.pc1 == 3 and completed is None:
            completed = trace(parents, state)
        for label, next_state in choices:
            edges += 1
            if next_state not in parents:
                parents[next_state] = (state, label)
                todo.append(next_state)
    return {'states': len(parents), 'transitions': edges, 'deadlocks': len(deadlocks),
            'deadlock_witness': deadlocks[0] if deadlocks else None, 'completion_witness': completed}


REQUIRED_WITNESSES = frozenset({'admission', 'admit_denial', 'revocation', 'matching_replay',
    'conflict_rejected', 'unauthorized_replay_rejected', 'event_effect', 'event_replay_without_effect',
    'event_conflict_rejected', 'stale_generation_rejected', 'wrong_worker_rejected', 'close',
    'wrong_principal_rejected', 'wrong_workspace_rejected', 'second_generation', 'revoked_effect_rejected',
    'claim', 'revoked_claim_rejected', 'preclaim_effect_rejected'})


def source_identity():
    source_file = Path(__file__).resolve()
    root = source_file.parents[2]
    env = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
    env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull, GIT_OPTIONAL_LOCKS='0')
    try:
        result = subprocess.run(['git', '-C', str(root), 'rev-parse', '--verify', 'HEAD^{commit}'],
                                text=True, capture_output=True, timeout=10, check=False, env=env)
        head = result.stdout.strip() if result.returncode == 0 else None
    except (OSError, subprocess.SubprocessError):
        head = None
    return {'source_head': head, 'source_worktree_state': 'NOT_ASSESSED',
            'model_sha256': hashlib.sha256(source_file.read_bytes()).hexdigest()}


def campaign():
    results = {p.name: explore(p) for p in POLICIES}
    candidate = results['candidate']
    missing = sorted(REQUIRED_WITNESSES - candidate['witnesses'].keys())
    failed_mutations = [name for name, expected in EXPECTED.items() if expected not in results[name]['violations']]
    if 'I05_WRONG_WORKER' not in results['missing_fence']['violations']:
        failed_mutations.append('missing_fence_wrong_worker')
    wrong = explore_locks(True)
    ordered = explore_locks(False)
    good = (candidate['states'] > 0 and candidate['transitions'] > 0 and not candidate['violations']
            and not missing and not failed_mutations and wrong['deadlocks'] > 0
            and ordered['deadlocks'] == 0 and ordered['completion_witness'] is not None)
    return {'schema_version': 'forgeflow.ecp-g0-authority-model.v1',
            'status': 'OBSERVED_NOT_GATE' if good else 'FAIL', 'product_gate_effect': 'NONE',
            'scope': 'bounded abstract graph only; no claim about production implementation',
            'source_identity': source_identity(),
            'bounds': {'principals': 2, 'workspaces': 2, 'tasks': 1, 'generations': 2,
                       'workers': 2, 'payloads': 2, 'concurrent_admit_transactions': 1,
                       'concurrent_revocations': 1, 'effect_count_saturation': 2},
            'missing_candidate_witnesses': missing, 'missed_mutations': failed_mutations,
            'policies': results, 'locks': {'opposite_order': wrong, 'same_order': ordered}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', help='new evidence file; existing files are never overwritten')
    args = parser.parse_args()
    report = campaign()
    data = json.dumps(report, sort_keys=True, indent=2) + '\n'
    if args.output:
        with open(args.output, 'x', encoding='utf-8') as stream:
            stream.write(data)
    print(data, end='')
    return 0 if report['status'] == 'OBSERVED_NOT_GATE' else 10


if __name__ == '__main__':
    raise SystemExit(main())
