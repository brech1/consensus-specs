from eth_consensus_specs.test.context import (
    expect_assertion_error,
    spec_state_test,
    with_gloas_and_later,
)
from eth_consensus_specs.test.helpers.block import (
    build_empty_block_for_next_slot,
)
from eth_consensus_specs.test.helpers.fork_choice import (
    get_genesis_forkchoice_store_and_block,
    on_tick_and_append_step,
    tick_and_add_block,
)
from eth_consensus_specs.test.helpers.keys import privkeys
from eth_consensus_specs.test.helpers.state import (
    state_transition_and_sign_block,
)


def _build_payload_attestation_message(
    spec, state, block_root, validator_index, payload_present=True, blob_data_available=True
):
    """Build a signed PayloadAttestationMessage for a given block root and validator."""
    data = spec.PayloadAttestationData(
        beacon_block_root=block_root,
        slot=state.slot,
        payload_present=payload_present,
        blob_data_available=blob_data_available,
    )

    domain = spec.get_domain(state, spec.DOMAIN_PTC_ATTESTER, spec.compute_epoch_at_slot(data.slot))
    signing_root = spec.compute_signing_root(data, domain)
    signature = spec.bls.Sign(privkeys[validator_index], signing_root)

    return spec.PayloadAttestationMessage(
        validator_index=validator_index,
        data=data,
        signature=signature,
    )


def _setup_store(spec, state, test_steps):
    store, anchor_block = get_genesis_forkchoice_store_and_block(spec, state)
    yield "anchor_state", state
    yield "anchor_block", anchor_block

    current_time = state.slot * (spec.config.SLOT_DURATION_MS // 1000) + store.genesis_time
    on_tick_and_append_step(spec, store, current_time, test_steps)
    return store


def _setup_ptc_block(spec, store, state, test_steps):
    block = build_empty_block_for_next_slot(spec, state)
    signed_block = state_transition_and_sign_block(spec, state, block)
    yield from tick_and_add_block(spec, store, signed_block, test_steps)

    block_root = signed_block.message.hash_tree_root()
    block_state = store.block_states[block_root]
    ptc = spec.get_ptc(block_state, block_state.slot)
    assert len(ptc) > 0

    return block_root, block_state, ptc


def _move_store_to_slot(spec, store, slot, test_steps):
    slot_time = store.genesis_time + slot * spec.config.SLOT_DURATION_MS // 1000
    if store.time < slot_time:
        on_tick_and_append_step(spec, store, slot_time, test_steps)


def _get_non_ptc_member(state, ptc):
    ptc_set = set(ptc)
    for validator_index in range(len(state.validators)):
        if validator_index not in ptc_set:
            return validator_index
    raise AssertionError("expected a validator outside the PTC")


@with_gloas_and_later
@spec_state_test
def test_on_payload_attestation_updates_votes(spec, state):
    """
    Test that valid messages (is_from_block=False) update vote arrays in both directions.
    """
    test_steps = []

    store = yield from _setup_store(spec, state, test_steps)
    block_root, block_state, ptc = yield from _setup_ptc_block(spec, store, state, test_steps)
    _move_store_to_slot(spec, store, block_state.slot, test_steps)

    assert all(v == False for v in store.payload_timeliness_vote[block_root])
    assert all(v == False for v in store.payload_data_availability_vote[block_root])

    ptc_member = ptc[0]
    ptc_index = ptc.index(ptc_member)

    spec.on_payload_attestation_message(
        store,
        _build_payload_attestation_message(
            spec,
            block_state,
            block_root,
            ptc_member,
            payload_present=True,
            blob_data_available=True,
        ),
        is_from_block=False,
    )
    assert store.payload_timeliness_vote[block_root][ptc_index] == True
    assert store.payload_data_availability_vote[block_root][ptc_index] == True

    spec.on_payload_attestation_message(
        store,
        _build_payload_attestation_message(
            spec,
            block_state,
            block_root,
            ptc_member,
            payload_present=False,
            blob_data_available=True,
        ),
        is_from_block=False,
    )

    assert store.payload_timeliness_vote[block_root][ptc_index] == False
    assert store.payload_data_availability_vote[block_root][ptc_index] == True

    yield "steps", test_steps


@with_gloas_and_later
@spec_state_test
def test_on_payload_attestation_not_ptc_member(spec, state):
    """
    Test that a message from a validator outside the PTC is rejected.
    """
    test_steps = []

    store = yield from _setup_store(spec, state, test_steps)
    block_root, block_state, ptc = yield from _setup_ptc_block(spec, store, state, test_steps)
    _move_store_to_slot(spec, store, block_state.slot, test_steps)

    non_ptc_member = _get_non_ptc_member(state, ptc)
    ptc_message = _build_payload_attestation_message(
        spec,
        block_state,
        block_root,
        non_ptc_member,
        payload_present=True,
    )

    expect_assertion_error(
        lambda: spec.on_payload_attestation_message(store, ptc_message, is_from_block=False)
    )

    yield "steps", test_steps


@with_gloas_and_later
@spec_state_test
def test_on_payload_attestation_checks_current_slot_and_signature(spec, state):
    """
    Test that non-block messages enforce the current-slot and signature checks.
    """
    test_steps = []

    store = yield from _setup_store(spec, state, test_steps)
    block_root, block_state, ptc = yield from _setup_ptc_block(spec, store, state, test_steps)
    _move_store_to_slot(spec, store, block_state.slot, test_steps)

    invalid_signature_message = _build_payload_attestation_message(
        spec,
        block_state,
        block_root,
        ptc[0],
        payload_present=True,
    )
    invalid_signature_message.signature = spec.BLSSignature()
    expect_assertion_error(
        lambda: spec.on_payload_attestation_message(
            store,
            invalid_signature_message,
            is_from_block=False,
        )
    )

    valid_message = _build_payload_attestation_message(
        spec,
        block_state,
        block_root,
        ptc[0],
        payload_present=True,
    )
    _move_store_to_slot(spec, store, block_state.slot + 1, test_steps)
    expect_assertion_error(
        lambda: spec.on_payload_attestation_message(store, valid_message, is_from_block=False)
    )

    yield "steps", test_steps


@with_gloas_and_later
@spec_state_test
def test_on_payload_attestation_off_slot_message_is_ignored(spec, state):
    """
    Test that messages for a different slot than the attested block are ignored.
    """
    test_steps = []

    store = yield from _setup_store(spec, state, test_steps)
    block_root, block_state, ptc = yield from _setup_ptc_block(spec, store, state, test_steps)
    ptc_message = _build_payload_attestation_message(
        spec,
        block_state,
        block_root,
        ptc[0],
        payload_present=True,
    )
    ptc_message.data.slot = spec.Slot(block_state.slot + 1)
    ptc_message.signature = spec.BLSSignature()

    before_timeliness = list(store.payload_timeliness_vote[block_root])
    before_availability = list(store.payload_data_availability_vote[block_root])

    spec.on_payload_attestation_message(store, ptc_message, is_from_block=False)

    assert list(store.payload_timeliness_vote[block_root]) == before_timeliness
    assert list(store.payload_data_availability_vote[block_root]) == before_availability

    yield "steps", test_steps


@with_gloas_and_later
@spec_state_test
def test_on_payload_attestation_unknown_block_root(spec, state):
    """
    Test that messages for an unknown beacon_block_root are rejected.
    """
    test_steps = []

    store = yield from _setup_store(spec, state, test_steps)
    block_root, block_state, ptc = yield from _setup_ptc_block(spec, store, state, test_steps)
    _move_store_to_slot(spec, store, block_state.slot, test_steps)

    ptc_message = _build_payload_attestation_message(
        spec,
        block_state,
        block_root,
        ptc[0],
        payload_present=True,
    )
    ptc_message.data.beacon_block_root = spec.Root(b"\xff" * 32)

    expect_assertion_error(
        lambda: spec.on_payload_attestation_message(store, ptc_message, is_from_block=False)
    )

    yield "steps", test_steps


@with_gloas_and_later
@spec_state_test
def test_on_payload_attestation_from_block_skips_signature_and_slot_checks(spec, state):
    """
    Test that is_from_block=True skips signature and current-slot checks.
    """
    test_steps = []

    store = yield from _setup_store(spec, state, test_steps)
    block_root, block_state, ptc = yield from _setup_ptc_block(spec, store, state, test_steps)
    ptc_member = ptc[0]
    ptc_message = _build_payload_attestation_message(
        spec,
        block_state,
        block_root,
        ptc_member,
        payload_present=True,
    )
    ptc_message.signature = spec.BLSSignature()

    _move_store_to_slot(spec, store, block_state.slot + 1, test_steps)

    spec.on_payload_attestation_message(store, ptc_message, is_from_block=True)

    ptc_index = ptc.index(ptc_member)
    assert store.payload_timeliness_vote[block_root][ptc_index] == True
    assert store.payload_data_availability_vote[block_root][ptc_index] == True

    yield "steps", test_steps
