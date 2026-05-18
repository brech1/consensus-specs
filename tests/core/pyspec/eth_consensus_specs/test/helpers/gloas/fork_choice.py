from typing import NamedTuple

from eth_consensus_specs.test.helpers.attestations import (
    get_valid_attestation,
    sign_attestation,
)
from eth_consensus_specs.test.helpers.block import build_empty_block_for_next_slot
from eth_consensus_specs.test.helpers.execution_payload import (
    build_signed_execution_payload_envelope,
)
from eth_consensus_specs.test.helpers.fork_choice import (
    add_attestation,
    add_execution_payload,
    add_latest_messages_check,
    advance_store_to_slot,
    tick_and_add_block,
)
from eth_consensus_specs.test.helpers.state import state_transition_and_sign_block


class CrossEpochAttester(NamedTuple):
    validator_index: int
    slot_0: int
    slot_1: int
    index_0: int
    index_1: int


def build_attestation(
    spec, state, slot=None, payload_index=0, root=None, index=None, signed=True, empty=False
):
    kwargs = {
        "slot": state.slot if slot is None else slot,
        "payload_index": payload_index,
        "signed": signed,
    }
    if root is not None:
        kwargs["beacon_block_root"] = root
    if index is not None:
        kwargs["index"] = index
    if empty:
        kwargs["filter_participant_set"] = lambda participants: set()
    return get_valid_attestation(spec, state, **kwargs)


def retarget_attestation(spec, state, attestation, epoch, root):
    attestation.data.target = spec.Checkpoint(epoch=spec.Epoch(epoch), root=root)
    sign_attestation(spec, state, attestation)
    return attestation


def state_at_slot(spec, state, slot):
    state = state.copy()
    if state.slot < slot:
        spec.process_slots(state, slot)
    return state


def attesting_indices(spec, state, attestation, k=1):
    return sorted(int(i) for i in spec.get_attesting_indices(state, attestation))[:k]


def assert_latest_message(spec, store, validator_index, attestation, payload_present):
    message = store.latest_messages[spec.ValidatorIndex(validator_index)]
    assert message.root == attestation.data.beacon_block_root
    assert message.slot == attestation.data.slot
    assert message.payload_present == payload_present


def add_execution_payload_envelope(spec, store, block_state, block_root, signed_block, steps):
    envelope = build_signed_execution_payload_envelope(spec, block_state, block_root, signed_block)
    yield from add_execution_payload(spec, store, envelope, steps)


def add_checked_attestation(spec, store, attestation_state, attestation, steps, k=1):
    """
    Add a valid attestation and emit latest-message checks for ``k`` attesters.
    """
    advance_store_to_slot(spec, store, attestation.data.slot + 1, steps)
    yield from add_attestation(spec, store, attestation, steps)
    indices = attesting_indices(spec, attestation_state, attestation, k)
    for index in indices:
        assert_latest_message(spec, store, index, attestation, attestation.data.index == 1)
    add_latest_messages_check(spec, store, indices, steps)
    return indices


def add_invalid_attestation(spec, store, attestation_state, attestation, steps, check_indices=None):
    """
    Add an invalid attestation and optionally assert selected latest messages
    remain absent or unchanged.
    """
    yield from add_attestation(spec, store, attestation, steps, valid=False)
    if check_indices is None:
        check_indices = attesting_indices(spec, attestation_state, attestation)
    if check_indices:
        add_latest_messages_check(spec, store, check_indices, steps)


def add_empty_block(spec, store, state, steps, graffiti=None):
    block = build_empty_block_for_next_slot(spec, state)
    if graffiti is not None:
        block.body.graffiti = graffiti
    signed_block = state_transition_and_sign_block(spec, state, block)
    yield from tick_and_add_block(spec, store, signed_block, steps)
    root = signed_block.message.hash_tree_root()
    return root, store.block_states[root], signed_block


def add_empty_blocks_through_slot(spec, store, state, slot, steps, capture_slots=()):
    """
    Add empty blocks until ``state.slot == slot``.

    Captures are only produced for blocks built by this helper. If the caller
    needs the initial state/root, it must pass that value separately.
    """
    captures = {}
    capture_slots = {int(slot) for slot in capture_slots}
    while state.slot < slot:
        root, block_state, signed_block = yield from add_empty_block(spec, store, state, steps)
        if int(state.slot) in capture_slots:
            captures[int(state.slot)] = (root, block_state.copy(), signed_block)
    return captures


def find_cross_epoch_attester(spec, state, require_peers=False):
    epoch_start = int(spec.compute_start_slot_at_epoch(spec.Epoch(1)))
    safe_upper = 2 * spec.SLOTS_PER_EPOCH - 1
    for validator_index in range(len(state.validators)):
        first = spec.get_committee_assignment(
            state, spec.Epoch(0), spec.ValidatorIndex(validator_index)
        )
        second = spec.get_committee_assignment(
            state, spec.Epoch(1), spec.ValidatorIndex(validator_index)
        )
        if first is None or second is None:
            continue
        _, index_0, slot_0 = first
        committee_1, index_1, slot_1 = second
        if int(slot_0) < 2 or int(slot_1) <= epoch_start or int(slot_1) >= safe_upper:
            continue
        if require_peers and len(committee_1) < 2:
            continue
        return CrossEpochAttester(
            validator_index=validator_index,
            slot_0=int(slot_0),
            slot_1=int(slot_1),
            index_0=int(index_0),
            index_1=int(index_1),
        )
    raise AssertionError("no usable cross-epoch attester found")


def assert_checkpoint_state(store, checkpoint, expected_state):
    assert checkpoint in store.checkpoint_states
    checkpoint_state = store.checkpoint_states[checkpoint]
    assert checkpoint_state.slot == expected_state.slot
    assert checkpoint_state.hash_tree_root() == expected_state.hash_tree_root()
