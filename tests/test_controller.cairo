%lang starknet
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin, HashBuiltin, SignatureBuiltin
from starkware.cairo.common.cairo_secp.ec import EcPoint
from starkware.cairo.common.cairo_secp.bigint import BigInt3

from src.controller.library import Controller

@external
func __setup__{syscall_ptr: felt*, range_check_ptr, pedersen_ptr: HashBuiltin*}() {
    %{ max_examples(10) %}
    return ();
}

@external
func setup_is_valid_webauthn_signature() {
    %{
        given(
            origin = strategy.short_strings(),
        )
    %}
    return ();
}

@external
func test_is_valid_webauthn_signature{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        range_check_ptr,
        ecdsa_ptr: SignatureBuiltin*,
        bitwise_ptr: BitwiseBuiltin*,
    }(origin: felt) {
    alloc_locals;
    local x0;
    local x1;
    local x2;
    local y0;
    local y1;
    local y2;

    local r0;
    local r1;
    local r2;
    local s0;
    local s1;
    local s2;
    local challenge_offset_len;
    local challenge_offset_rem;
    local challenge_len;
    local challenge_rem;
    local client_data_json_len;
    local client_data_json_rem;
    local authenticator_data_len;
    local authenticator_data_rem;

    local transaction_hash;
    let (local client_data_json_parts: felt*) = alloc();
    let (local authenticator_data_parts: felt*) = alloc();

    %{
        from tests.signer import WebauthnSigner
        signer = WebauthnSigner(ids.origin)
        (x0, x1, x2, y0, y1, y2) = signer.public_key
        (transaction_hash, r0, r1, r2, s0, s1, s2, challenge_offset_len, challenge_offset_rem, challenge_len, challenge_rem,
        client_data_json_len, client_data_json_rem, client_data_json_parts,
        authenticator_data_len, authenticator_data_rem, authenticator_data_parts) = signer.sign_transaction(123, [(1234, 'add_public_key', [0])], 0, 0)

        ids.x0 = x0
        ids.x1 = x1
        ids.x2 = x2
        ids.y0 = y0
        ids.y1 = y1
        ids.y2 = y2

        ids.r0 = r0
        ids.r1 = r1
        ids.r2 = r2
        ids.s0 = s0
        ids.s1 = s1
        ids.s2 = s2
        ids.challenge_offset_len = challenge_offset_len
        ids.challenge_offset_rem = challenge_offset_rem
        ids.challenge_len = challenge_len
        ids.challenge_rem = challenge_rem
        ids.client_data_json_len = client_data_json_len
        ids.client_data_json_rem = client_data_json_rem
        ids.authenticator_data_len = authenticator_data_len
        ids.authenticator_data_rem = authenticator_data_rem

        ids.transaction_hash = transaction_hash
        segments.write_arg(ids.client_data_json_parts, client_data_json_parts)
        segments.write_arg(ids.authenticator_data_parts, authenticator_data_parts)
    %}

    Controller.is_valid_webauth_signature(
        EcPoint(BigInt3(x0, x1, x2), BigInt3(y0, y1, y2)), transaction_hash,
        BigInt3(r0, r1, r2),
        BigInt3(s0, s1, s2),
        challenge_offset_len,
        challenge_offset_rem,
        client_data_json_len,
        client_data_json_rem,
        client_data_json_parts,
        authenticator_data_len,
        authenticator_data_rem,
        authenticator_data_parts);

    return ();
}

@contract_interface
namespace IController {
    func initialize(
        plugin_calldata_len: felt, plugin_calldata: felt*
    ){
    }
}

@external
func test_initialize{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        range_check_ptr,
        ecdsa_ptr: SignatureBuiltin*,
        bitwise_ptr: BitwiseBuiltin*,
    }() {
    alloc_locals;

    local controller_address: felt;
    %{ ids.controller_address = deploy_contract("./src/controller/Controller.cairo", []).contract_address %}

    let (local plugin_calldata: felt*) = alloc();
    assert plugin_calldata[0] = 0x1;
    assert plugin_calldata[1] = 0x1;
    assert plugin_calldata[2] = 0x1;
    assert plugin_calldata[3] = 0x1;
    assert plugin_calldata[4] = 0x1;
    assert plugin_calldata[5] = 0x1;
    assert plugin_calldata[6] = 0x1;

    IController.initialize(controller_address, 7, plugin_calldata);

    %{ expect_revert(error_message="Controller: account already initialized") %}
    IController.initialize(controller_address, 7, plugin_calldata);

    return ();
}

@external
func test_verify{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        range_check_ptr,
        ecdsa_ptr: SignatureBuiltin*,
        bitwise_ptr: BitwiseBuiltin*,
    }() {
    alloc_locals;

    let sig_r0 = BigInt3(65546257809207752398516129, 74656500423935402038188120, 10917538219687308733253964);
    let sig_s0 = BigInt3(66876101101625119369777982, 30503904999956572755782373, 11705175908723778676784935);
    let challenge_offset_len = 9;
    let challenge_offset_rem = 0;
    let client_data_json_len = 34;
    let client_data_json_rem = 2;

    let (local client_data_json: felt*) = alloc();
    assert client_data_json[0] = 2065855609;
    assert client_data_json[1] = 1885676090;
    assert client_data_json[2] = 578250082;
    assert client_data_json[3] = 1635087464;
    assert client_data_json[4] = 1848534885;
    assert client_data_json[5] = 1948396578;
    assert client_data_json[6] = 1667785068;
    assert client_data_json[7] = 1818586727;
    assert client_data_json[8] = 1696741922;
    assert client_data_json[9] = 1114917719;
    assert client_data_json[10] = 1852725849;
    assert client_data_json[11] = 877606445;
    assert client_data_json[12] = 1919764824;
    assert client_data_json[13] = 876046201;
    assert client_data_json[14] = 1632842606;
    assert client_data_json[15] = 1732407145;
    assert client_data_json[16] = 876178797;
    assert client_data_json[17] = 1851338830;
    assert client_data_json[18] = 1178889528;
    assert client_data_json[19] = 946823970;
    assert client_data_json[20] = 740454258;
    assert client_data_json[21] = 1768384878;
    assert client_data_json[22] = 574235240;
    assert client_data_json[23] = 1953788019;
    assert client_data_json[24] = 976170872;
    assert client_data_json[25] = 778264946;
    assert client_data_json[26] = 1953655140;
    assert client_data_json[27] = 1734684263;
    assert client_data_json[28] = 1730292770;
    assert client_data_json[29] = 1668444019;
    assert client_data_json[30] = 1934586473;
    assert client_data_json[31] = 1734962722;
    assert client_data_json[32] = 980710005;
    assert client_data_json[33] = 1702690816;

    let authenticator_data_len = 10;
    let authenticator_data_rem = 3;

    let (local authenticator_data: felt*) = alloc();
    assert authenticator_data[0] = 547978947;
    assert authenticator_data[1] = 4176460842;
    assert authenticator_data[2] = 3389847498;
    assert authenticator_data[3] = 3141667658;
    assert authenticator_data[4] = 164671177;
    assert authenticator_data[5] = 2421450441;
    assert authenticator_data[6] = 2918684036;
    assert authenticator_data[7] = 4202036947;
    assert authenticator_data[8] = 83886080;
    assert authenticator_data[9] = 0;

    let transaction_hash = 0x06d2969e7658e0eebeae6217e3b832692de7801a22e3d9a69d8d0d1439bcf287;

    Controller.is_valid_webauth_signature(
        EcPoint(
            BigInt3(41954307354962613599163780, 19663556749369154724636657, 3805171173402616775588440),
            BigInt3(21280206910955492062951095, 36564985731785099000333311, 16704533755628810607549113),
        ),
        transaction_hash,
        sig_r0,
        sig_s0,
        challenge_offset_len,
        challenge_offset_rem,
        client_data_json_len,
        client_data_json_rem,
        client_data_json,
        authenticator_data_len,
        authenticator_data_rem,
        authenticator_data);

    return ();
}
