from eth_consensus_specs.test.context import (
    always_bls,
    spec_state_test,
    with_gloas_and_later,
)
from eth_consensus_specs.test.helpers.attester_slashings import (
    get_valid_attester_slashing_by_indices,
)
from eth_consensus_specs.test.helpers.block import build_empty_block_for_next_slot
from eth_consensus_specs.test.helpers.fork_choice import (
    add_attestation,
    add_attester_slashing,
    add_checkpoint_state_check,
    add_latest_messages_check,
    advance_store_to_slot,
    setup_one_block_store,
    tick_and_add_block,
)
from eth_consensus_specs.test.helpers.gloas.fork_choice import (
    add_checked_attestation,
    add_empty_block,
    add_empty_blocks_through_slot,
    add_execution_payload_envelope,
    add_invalid_attestation,
    assert_checkpoint_state,
    assert_latest_message,
    attesting_indices,
    build_attestation,
    find_cross_epoch_attester,
    retarget_attestation,
    state_at_slot,
)
from eth_consensus_specs.test.helpers.state import state_transition_and_sign_block


@with_gloas_and_later
@spec_state_test
def test_on_attestation_payload_index_rules(spec, state):
    """
    Test Gloas payload-index validation:
    invalid index, same-slot full-node vote, full-node vote without payload,
    and the valid empty/full paths.
    """
    store, block_root, block_state, signed_block, steps = yield from setup_one_block_store(
        spec, state
    )

    # Same-slot empty-node vote is valid with or without a payload.
    same_empty = build_attestation(spec, block_state)
    same_indices = yield from add_checked_attestation(
        spec, store, block_state, same_empty, steps, k=len(state.validators)
    )

    # Same-slot full-node vote is invalid even if the payload is verified.
    yield from add_execution_payload_envelope(
        spec, store, block_state, block_root, signed_block, steps
    )
    same_full = build_attestation(spec, block_state, payload_index=1)
    yield from add_invalid_attestation(
        spec, store, block_state, same_full, steps, check_indices=same_indices
    )

    # Later-slot full-node vote is valid when it references a verified payload.
    state_at_2 = state_at_slot(spec, block_state, spec.Slot(2))
    full_verified = build_attestation(
        spec, state_at_2, slot=spec.Slot(2), payload_index=1, root=block_root
    )
    full_indices = yield from add_checked_attestation(spec, store, state_at_2, full_verified, steps)

    # Payload index must be either 0 or 1.
    bad_index = build_attestation(spec, state_at_2, slot=spec.Slot(2), payload_index=2)
    yield from add_invalid_attestation(
        spec, store, state_at_2, bad_index, steps, check_indices=full_indices
    )

    # A full-node vote checks the attested beacon block root, not just the target root.
    target_slot = spec.Slot(spec.SLOTS_PER_EPOCH)
    beacon_slot = spec.Slot(target_slot + 1)
    captures = yield from add_empty_blocks_through_slot(
        spec,
        store,
        block_state.copy(),
        beacon_slot,
        steps,
        capture_slots=(target_slot, beacon_slot),
    )
    target_root, target_state, target_block = captures[int(target_slot)]
    beacon_root, beacon_state, _ = captures[int(beacon_slot)]
    yield from add_execution_payload_envelope(
        spec, store, target_state, target_root, target_block, steps
    )

    later_state = state_at_slot(spec, beacon_state, beacon_slot + 1)
    unverified_beacon = build_attestation(spec, later_state, slot=beacon_slot + 1, payload_index=1)
    assert unverified_beacon.data.target.root == target_root
    assert unverified_beacon.data.beacon_block_root == beacon_root
    yield from add_invalid_attestation(spec, store, later_state, unverified_beacon, steps)

    yield "steps", steps


@with_gloas_and_later
@spec_state_test
@always_bls
def test_on_attestation_validation_failures(spec, state):
    """
    Test inherited validation failures in one ordered vector.
    Each rejected attestation is followed by a latest-message check for the
    attesters whose messages would have changed if validation had leaked state.
    """
    store, block_root, block_state, _, steps = yield from setup_one_block_store(spec, state)

    # Wire target epoch is too new.
    too_new = build_attestation(spec, block_state, signed=False)
    retarget_attestation(spec, block_state, too_new, 2, block_root)
    block_state_indices = attesting_indices(spec, block_state, too_new)
    yield from add_invalid_attestation(spec, store, block_state, too_new, steps)

    # Attestation slot is not yet in the past.
    block_2_root, state_at_2, _ = yield from add_empty_block(spec, store, block_state.copy(), steps)
    too_early = build_attestation(spec, state_at_2)
    state_at_2_indices = attesting_indices(spec, state_at_2, too_early)
    yield from add_invalid_attestation(spec, store, state_at_2, too_early, steps)

    advance_store_to_slot(spec, store, spec.Slot(3), steps)

    # Target root is unknown.
    unknown_target = build_attestation(spec, block_state, signed=False)
    unknown_target.data.target.root = spec.Root(b"\xee" * 32)
    retarget_attestation(
        spec,
        block_state,
        unknown_target,
        unknown_target.data.target.epoch,
        unknown_target.data.target.root,
    )
    yield from add_invalid_attestation(
        spec, store, block_state, unknown_target, steps, check_indices=block_state_indices
    )

    # Beacon block root is unknown.
    unknown_block = build_attestation(spec, block_state, root=spec.Root(b"\xff" * 32))
    yield from add_invalid_attestation(
        spec, store, block_state, unknown_block, steps, check_indices=block_state_indices
    )

    # Referenced block slot is after the attestation slot.
    future_block = build_attestation(spec, block_state, root=block_2_root)
    yield from add_invalid_attestation(
        spec, store, block_state, future_block, steps, check_indices=block_state_indices
    )

    # Aggregate signature must match the indexed attestation.
    invalid_signature = build_attestation(spec, block_state)
    invalid_signature_indices = attesting_indices(spec, block_state, invalid_signature)
    invalid_signature.signature = spec.BLSSignature()
    yield from add_invalid_attestation(
        spec, store, block_state, invalid_signature, steps, check_indices=invalid_signature_indices
    )

    # Empty participant set fails indexed-attestation validation.
    empty_participants = build_attestation(spec, state_at_2, signed=False, empty=True)
    assert len(spec.get_attesting_indices(state_at_2, empty_participants)) == 0
    yield from add_invalid_attestation(
        spec, store, state_at_2, empty_participants, steps, check_indices=state_at_2_indices
    )

    # Target checkpoint must match the checkpoint block for the beacon root.
    state_iter = state_at_2.copy()
    yield from add_empty_blocks_through_slot(
        spec, store, state_iter, spec.SLOTS_PER_EPOCH + 1, steps
    )
    epoch_1_root = spec.get_block_root(state_iter, spec.Epoch(1))
    wrong_target = build_attestation(spec, state_iter, slot=spec.SLOTS_PER_EPOCH, signed=False)
    assert epoch_1_root != block_root
    retarget_attestation(spec, state_iter, wrong_target, 1, block_root)
    wrong_target_indices = attesting_indices(spec, state_iter, wrong_target)
    yield from add_invalid_attestation(
        spec, store, state_iter, wrong_target, steps, check_indices=wrong_target_indices
    )

    # Target epoch must match the attestation slot epoch.
    epoch_mismatch = build_attestation(spec, block_state, signed=False)
    retarget_attestation(spec, block_state, epoch_mismatch, 1, block_root)
    yield from add_invalid_attestation(
        spec, store, block_state, epoch_mismatch, steps, check_indices=block_state_indices
    )

    # Wire target epoch is too old.
    advance_store_to_slot(spec, store, 2 * spec.SLOTS_PER_EPOCH, steps)
    too_old = build_attestation(spec, block_state)
    yield from add_invalid_attestation(
        spec, store, block_state, too_old, steps, check_indices=block_state_indices
    )

    yield "steps", steps


@with_gloas_and_later
@spec_state_test
def test_on_attestation_from_block_bypasses_wire_time(spec, state):
    """
    Test that block-origin attestations bypass the wire target-epoch time check.
    """
    store, block_root, block_state, _, steps = yield from setup_one_block_store(spec, state)

    attestation = build_attestation(spec, block_state, root=block_root)
    containing_state = state_at_slot(spec, block_state, spec.SLOTS_PER_EPOCH)
    block = build_empty_block_for_next_slot(spec, containing_state)
    block.body.attestations.append(attestation)
    signed_block = state_transition_and_sign_block(spec, containing_state, block)

    # The same attestation is too old on the wire, but valid inside a block.
    advance_store_to_slot(spec, store, 2 * spec.SLOTS_PER_EPOCH + 1, steps)
    yield from add_attestation(spec, store, attestation, steps, valid=False)
    yield from tick_and_add_block(spec, store, signed_block, steps)

    indices = attesting_indices(spec, block_state, attestation)
    assert_latest_message(spec, store, indices[0], attestation, payload_present=False)
    add_latest_messages_check(spec, store, indices, steps)
    yield "steps", steps


@with_gloas_and_later
@spec_state_test
def test_on_attestation_latest_message_overwrite_rules(spec, state):
    """
    Test Gloas latest-message overwrite rules:
    newer slots overwrite older slots, and older slots do not overwrite newer ones.
    """
    store, block_root, block_state, signed_block, steps = yield from setup_one_block_store(
        spec, state
    )

    attester = find_cross_epoch_attester(spec, block_state)
    previous_slot = attester.slot_0 - 1
    captures = yield from add_empty_blocks_through_slot(
        spec,
        store,
        block_state.copy(),
        attester.slot_1,
        steps,
        capture_slots=(previous_slot, attester.slot_0, attester.slot_1),
    )

    if previous_slot == int(block_state.slot):
        previous_root, previous_state, previous_block = block_root, block_state, signed_block
    else:
        previous_root, previous_state, previous_block = captures[previous_slot]
    yield from add_execution_payload_envelope(
        spec, store, previous_state, previous_root, previous_block, steps
    )

    old_full = build_attestation(
        spec,
        captures[attester.slot_0][1],
        slot=attester.slot_0,
        index=attester.index_0,
        payload_index=1,
        root=previous_root,
    )
    new_empty = build_attestation(
        spec, captures[attester.slot_1][1], slot=attester.slot_1, index=attester.index_1
    )

    # Newer empty-node vote overwrites the older full-node vote and payload flag.
    advance_store_to_slot(spec, store, attester.slot_1 + 1, steps)
    yield from add_attestation(spec, store, old_full, steps)
    assert_latest_message(spec, store, attester.validator_index, old_full, payload_present=True)
    yield from add_attestation(spec, store, new_empty, steps)
    assert_latest_message(spec, store, attester.validator_index, new_empty, payload_present=False)
    add_latest_messages_check(spec, store, [attester.validator_index], steps)

    # Replaying the older vote does not overwrite the newer latest message.
    yield from add_attestation(spec, store, old_full, steps)
    assert_latest_message(spec, store, attester.validator_index, new_empty, payload_present=False)
    add_latest_messages_check(spec, store, [attester.validator_index], steps)
    yield "steps", steps


@with_gloas_and_later
@spec_state_test
def test_on_attestation_equal_slot_does_not_overwrite(spec, state):
    """
    Test that equal-slot attestations do not overwrite existing latest messages.
    """
    store, block_root, block_state, _, steps = yield from setup_one_block_store(spec, state)

    # Build a second slot-1 branch so the equal-slot vote has a different root.
    branch_state = store.block_states[store.justified_checkpoint.root].copy()
    branch_root, branch_block_state, branch_block = yield from add_empty_block(
        spec, store, branch_state, steps, graffiti=spec.Bytes32(b"\x44" * 32)
    )
    yield from add_execution_payload_envelope(
        spec, store, branch_block_state, branch_root, branch_block, steps
    )

    state_at_2 = state_at_slot(spec, block_state, spec.Slot(2))
    first = build_attestation(spec, state_at_2, slot=spec.Slot(2), root=block_root)
    second = build_attestation(
        spec, state_at_2, slot=spec.Slot(2), payload_index=1, root=branch_root
    )
    assert branch_root != block_root
    assert first.data.beacon_block_root != second.data.beacon_block_root

    indices = yield from add_checked_attestation(spec, store, state_at_2, first, steps)
    yield from add_attestation(spec, store, second, steps)
    assert_latest_message(spec, store, indices[0], first, payload_present=False)
    add_latest_messages_check(spec, store, indices, steps)
    yield "steps", steps


@with_gloas_and_later
@spec_state_test
def test_on_attestation_equivocating_validator_is_skipped(spec, state):
    """
    Test that equivocating validators are skipped while non-equivocating peers
    in the same valid attestation are still updated.
    """
    store, _, block_state, _, steps = yield from setup_one_block_store(spec, state)

    attester = find_cross_epoch_attester(spec, block_state, require_peers=True)
    captures = yield from add_empty_blocks_through_slot(
        spec,
        store,
        block_state.copy(),
        attester.slot_1,
        steps,
        capture_slots=(attester.slot_0, attester.slot_1),
    )
    first = build_attestation(
        spec, captures[attester.slot_0][1], slot=attester.slot_0, index=attester.index_0
    )
    second = build_attestation(
        spec, captures[attester.slot_1][1], slot=attester.slot_1, index=attester.index_1
    )

    slashing = get_valid_attester_slashing_by_indices(
        spec,
        state,
        indices_1=[attester.validator_index],
        indices_2=[attester.validator_index],
        signed_1=True,
        signed_2=True,
    )

    advance_store_to_slot(spec, store, attester.slot_1 + 1, steps)
    yield from add_attestation(spec, store, first, steps)
    yield from add_attester_slashing(spec, store, slashing, steps)
    yield from add_attestation(spec, store, second, steps)

    peer = next(
        i
        for i in attesting_indices(spec, captures[attester.slot_1][1], second, k=4)
        if i != attester.validator_index
    )
    assert_latest_message(spec, store, attester.validator_index, first, payload_present=False)
    assert_latest_message(spec, store, peer, second, payload_present=False)
    add_latest_messages_check(spec, store, [attester.validator_index, peer], steps)
    yield "steps", steps


@with_gloas_and_later
@spec_state_test
def test_on_attestation_target_checkpoint_states_are_stored(spec, state):
    """
    Test that target checkpoint states are stored for both exact boundary
    blocks and skipped-boundary checkpoint roots.
    """
    store, _, block_state, _, steps = yield from setup_one_block_store(spec, state)
    state_iter = block_state.copy()

    # Target block exists exactly at the epoch boundary.
    target_slot = spec.Slot(spec.SLOTS_PER_EPOCH)
    captures = yield from add_empty_blocks_through_slot(
        spec, store, state_iter, target_slot, steps, capture_slots=(target_slot,)
    )
    target_state = captures[int(target_slot)][1]
    attestation = build_attestation(spec, target_state, slot=target_slot)
    assert attestation.data.target not in store.checkpoint_states
    yield from add_checked_attestation(spec, store, target_state, attestation, steps)
    assert_checkpoint_state(store, attestation.data.target, target_state)
    add_checkpoint_state_check(store, attestation.data.target, steps)

    # Boundary slot is skipped; checkpoint state is advanced from the previous block.
    skipped_slot = spec.Slot(2 * spec.SLOTS_PER_EPOCH)
    previous_slot = spec.Slot(skipped_slot - 1)
    captures = yield from add_empty_blocks_through_slot(
        spec, store, state_iter, previous_slot, steps, capture_slots=(previous_slot,)
    )
    previous_root, previous_state, _ = captures[int(previous_slot)]
    skipped_state = state_at_slot(spec, previous_state, skipped_slot)
    skipped_attestation = build_attestation(spec, skipped_state, slot=skipped_slot)
    assert skipped_attestation.data.target.root == previous_root
    assert skipped_attestation.data.target not in store.checkpoint_states
    yield from add_checked_attestation(spec, store, skipped_state, skipped_attestation, steps)
    assert_checkpoint_state(store, skipped_attestation.data.target, skipped_state)
    add_checkpoint_state_check(store, skipped_attestation.data.target, steps)
    yield "steps", steps
