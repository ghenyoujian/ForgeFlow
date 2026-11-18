"""Check bounded model exploration and mutation witnesses, not product behavior."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import g0_authority_model as model


def replay(policy, path):
    initial = path[0].split('=', 1)[1]
    state = model.State(initial)
    last_errors, last_tags = (), ()
    for expected in path[1:]:
        choices = [(next_state, errors, tags) for label, next_state, errors, tags
                   in model.transitions(state, policy) if label == expected]
        if len(choices) != 1:
            raise AssertionError(f'non-replayable or ambiguous step {expected!r}: {choices!r}')
        state, last_errors, last_tags = choices[0]
    return state, last_errors, last_tags


class AuthorityModelTests(unittest.TestCase):
    def test_candidate_graph_is_closed_under_every_transition(self):
        policy = model.POLICIES[0]
        result = model.explore(policy)
        # Independent depth-first traversal checks the BFS counts and every
        # generated edge, including self loops and all initial states.
        visited, stack, edges = set(), [model.State('ABSENT'), model.State('ACTIVE')], 0
        while stack:
            state = stack.pop()
            if state in visited:
                continue
            visited.add(state)
            self.assertIn(state.grant, ('ABSENT', 'ACTIVE', 'REVOKED'))
            self.assertIn(state.generation, (0, 1, 2))
            self.assertIn(state.effects, (0, 1, 2))
            self.assertIn(state.lease_generation, (0, 1, 2))
            self.assertIn(state.fence_epoch, (0, 1, 2))
            if state.active:
                self.assertEqual(state.generation, state.lease_generation)
                self.assertEqual(state.generation, state.fence_epoch)
                self.assertEqual(state.binding, (0, 0))
            for _, target, violations, _ in model.transitions(state, policy):
                edges += 1
                self.assertFalse(violations, (state, target, violations))
                if target not in visited:
                    stack.append(target)
        self.assertGreater(len(visited), 0)
        self.assertGreater(edges, len(visited))
        self.assertEqual((len(visited), edges), (result['states'], result['transitions']))
        self.assertTrue(result['complete_within_declared_bounds'])
        self.assertFalse(result['violations'])

    def test_candidate_witnesses_are_replayable_and_nonvacuous(self):
        policy = model.POLICIES[0]
        witnesses = model.explore(policy)['witnesses']
        self.assertFalse(model.REQUIRED_WITNESSES - witnesses.keys())
        for name in model.REQUIRED_WITNESSES:
            with self.subTest(name=name):
                _, violations, tags = replay(policy, witnesses[name])
                self.assertIn(name, tags)
                self.assertFalse(violations)
        self.assertIn('admit_commit', witnesses['second_generation'])
        self.assertIn('revoke_commit', witnesses['revoked_effect_rejected'])
        self.assertIn('revoke_commit', witnesses['unauthorized_replay_rejected'])
        self.assertIn('event(g1,w0', witnesses['stale_generation_rejected'][-1])

    def test_each_single_mutation_has_replayable_expected_counterexample(self):
        reference = model.POLICIES[0]
        flags = set(reference.__dataclass_fields__) - {'name'}
        self.assertEqual({p.name for p in model.POLICIES[1:]}, set(model.EXPECTED))
        for policy in model.POLICIES[1:]:
            with self.subTest(policy=policy.name):
                changed = [key for key in flags if getattr(reference, key) != getattr(policy, key)]
                self.assertEqual(len(changed), 1, changed)
                result = model.explore(policy)
                expected = model.EXPECTED[policy.name]
                path = result['violations'][expected]
                _, violations, _ = replay(policy, path)
                self.assertIn(expected, violations)
                self.assertGreater(result['states'], 0)
                self.assertGreater(result['transitions'], 0)
                # The abstract Store baseline counterexample has no grant;
                # unrelated HTTP authentication remains outside the model.
                if policy.name == 'unbound_subject':
                    self.assertEqual(path[0], 'initial_grant=ABSENT')
                if policy.name == 'missing_fence':
                    self.assertIn('I05_WRONG_WORKER', result['violations'])
                    self.assertIn('close_attempt', path)
                    self.assertIn('event(g1,w0', path[-1])
                if policy.name in ('unlocked_check_then_commit', 'replay_before_auth', 'effect_after_revoke'):
                    self.assertIn('revoke_commit', path)

    def test_lock_mutation_deadlocks_while_ordered_graph_completes(self):
        wrong = model.explore_locks(True)
        ordered = model.explore_locks(False)
        self.assertGreater(wrong['states'], 0)
        self.assertGreater(wrong['deadlocks'], 0)
        self.assertIsNotNone(wrong['deadlock_witness'])
        self.assertIsNotNone(wrong['completion_witness'])
        self.assertEqual(ordered['deadlocks'], 0)
        self.assertIsNotNone(ordered['completion_witness'])
        self.assertGreater(ordered['transitions'], 0)

    def test_cli_preserves_existing_evidence_and_never_issues_gate(self):
        program = Path(model.__file__)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'result.json'
            run = subprocess.run([sys.executable, str(program), '--output', str(output)], capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            report = json.loads(output.read_text())
            self.assertEqual(report['status'], 'OBSERVED_NOT_GATE')
            self.assertEqual(report['product_gate_effect'], 'NONE')
            original = output.read_bytes()
            retry = subprocess.run([sys.executable, str(program), '--output', str(output)], capture_output=True, text=True)
            self.assertNotEqual(retry.returncode, 0)
            self.assertEqual(output.read_bytes(), original)


if __name__ == '__main__':
    unittest.main()
