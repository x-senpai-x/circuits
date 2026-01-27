// Partial SHA256 Library
// Custom implementation for splitting SHA256 computation across multiple circuits.
//
// Based on RFC 6234 (SHA-256) specification and zkEmail's approach.
// Uses std::hash::sha256_compression (standard library) for the compression function.
// Only implements message block construction and SHA-256 padding logic.
//
// SHA256 padding (RFC 6234):
// 1. Append 0x80 byte after message
// 2. Append zeros until message length mod 512 = 448 bits
// 3. Append original message length as 64-bit big-endian integer

use poseidon::poseidon2::Poseidon2;
use std::hash::sha256_compression;

// SHA256 block size in bytes
pub global BLOCK_SIZE: u32 = 64;

// SHA256 initial hash values (IV) from RFC 6234
pub global SHA256_IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

// Type alias for SHA256 intermediate state (8 x 32-bit words = 256 bits)
pub type SHA256State = [u32; 8];

// Internal: Build a message block from bytes
// Packs bytes into u32 words in big-endian format (as required by SHA-256)
fn build_msg_block<let N: u32>(msg: [u8; N], msg_start: u32, valid_bytes: u32) -> [u32; 16] {
    let mut block: [u32; 16] = [0; 16];
    for i in 0..16 {
        let byte_idx = msg_start + i * 4;
        let mut word: u32 = 0;
        for j in 0..4 {
            word = word << 8;
            let idx = byte_idx + j;
            if idx < msg_start + valid_bytes {
                word = word + msg[idx] as u32;
            }
        }
        block[i] = word;
    }
    block
}

// Internal: Convert SHA-256 state to hash output (big-endian)
fn state_to_hash(state: SHA256State) -> [u8; 32] {
    let mut hash: [u8; 32] = [0; 32];
    for i in 0..8 {
        let word = state[i];
        hash[i * 4] = ((word >> 24) & 0xff) as u8;
        hash[i * 4 + 1] = ((word >> 16) & 0xff) as u8;
        hash[i * 4 + 2] = ((word >> 8) & 0xff) as u8;
        hash[i * 4 + 3] = (word & 0xff) as u8;
    }
    hash
}

/// Process the first N bytes of a message (must be multiple of 64)
/// Returns the intermediate SHA256 state after processing these blocks
pub fn sha256_start<let N: u32>(msg: [u8; N]) -> SHA256State {
    assert(N % BLOCK_SIZE == 0, "Message size must be a multiple of 64 bytes");
    let num_blocks = N / BLOCK_SIZE;
    let mut state = SHA256_IV;

    for i in 0..num_blocks {
        let block = build_msg_block(msg, i * BLOCK_SIZE, BLOCK_SIZE);
        state = sha256_compression(block, state);
    }
    state
}

/// Continue processing message blocks given a previous state
/// N must be a multiple of 64
pub fn sha256_continue<let N: u32>(
    state: SHA256State,
    msg: [u8; N],
    msg_size: u32,
) -> SHA256State {
    assert(msg_size % BLOCK_SIZE == 0, "Message size must be a multiple of 64 bytes");
    assert(msg_size <= N, "Message size exceeds buffer size");

    let num_blocks = msg_size / BLOCK_SIZE;
    let mut current_state = state;

    for i in 0..num_blocks {
        let block = build_msg_block(msg, i * BLOCK_SIZE, BLOCK_SIZE);
        current_state = sha256_compression(block, current_state);
    }
    current_state
}

/// Finalize the SHA256 hash given a previous state and remaining message
/// msg_size: bytes of actual data in msg buffer (can be any value 0..N)
/// total_msg_size: TOTAL size of the entire message (for length padding)
///
/// Implements SHA-256 padding per RFC 6234:
/// - Append 0x80 byte
/// - Pad with zeros
/// - Append 64-bit message length in bits (big-endian)
pub fn sha256_finalize<let N: u32>(
    state: SHA256State,
    msg: [u8; N],
    msg_size: u32,
    total_msg_size: u32,
) -> [u8; 32] {
    assert(msg_size <= N, "Message size exceeds buffer size");
    assert(msg_size < BLOCK_SIZE, "Use sha256_continue for full blocks first");

    let mut current_state = state;

    // Build final block with remaining data + 0x80 padding byte
    let mut final_block: [u32; 16] = [0; 16];

    // Copy remaining bytes and add 0x80 padding
    for i in 0..16 {
        let byte_idx = i * 4;
        let mut word: u32 = 0;
        for j in 0..4 {
            word = word << 8;
            let idx = byte_idx + j;
            if idx < msg_size {
                word = word + msg[idx] as u32;
            } else if idx == msg_size {
                // Append 0x80 byte as per SHA-256 spec
                word = word + 0x80;
            }
            // Remaining bytes are implicitly 0 (zero-padding)
        }
        final_block[i] = word;
    }

    // Compute message length in bits
    let total_bits = total_msg_size as u64 * 8;

    // Check if length fits in current block (need 8 bytes = 64 bits at end)
    // If msg_size + 1 (for 0x80) + 8 (for length) > 64, need two blocks
    if msg_size + 9 > BLOCK_SIZE {
        // Compress current block, then create length block
        current_state = sha256_compression(final_block, current_state);

        // Length-only block: all zeros except last 64 bits
        let mut length_block: [u32; 16] = [0; 16];
        length_block[14] = (total_bits >> 32) as u32;  // High 32 bits
        length_block[15] = (total_bits & 0xffffffff) as u32;  // Low 32 bits
        current_state = sha256_compression(length_block, current_state);
    } else {
        // Length fits in current block
        final_block[14] = (total_bits >> 32) as u32;
        final_block[15] = (total_bits & 0xffffffff) as u32;
        current_state = sha256_compression(final_block, current_state);
    }

    state_to_hash(current_state)
}

/// Commits to SHA256 intermediate state for chaining between circuits
/// Output: Poseidon2(salt, state[0..7], processed_bytes)
pub fn commit_to_sha256_state(
    salt: Field,
    state: SHA256State,
    processed_bytes: u32,
) -> Field {
    let mut hash_inputs: [Field; 10] = std::mem::zeroed();
    hash_inputs[0] = salt;
    for i in 0..8 {
        hash_inputs[1 + i] = state[i] as Field;
    }
    hash_inputs[9] = processed_bytes as Field;
    Poseidon2::hash(hash_inputs, 10)
}

/// Verifies a SHA256 state commitment
pub fn verify_sha256_state_commitment(
    comm_in: Field,
    salt: Field,
    state: SHA256State,
    processed_bytes: u32,
) {
    let expected = commit_to_sha256_state(salt, state, processed_bytes);
    assert(comm_in == expected, "SHA256 state commitment verification failed");
}

/// Commits to SHA256 state along with a data commitment (for binding data to state)
/// Output: Poseidon2(salt, state[0..7], processed_bytes, data_commitment)
pub fn commit_to_sha256_state_and_data(
    salt: Field,
    state: SHA256State,
    processed_bytes: u32,
    data_commitment: Field,
) -> Field {
    let mut hash_inputs: [Field; 11] = std::mem::zeroed();
    hash_inputs[0] = salt;
    for i in 0..8 {
        hash_inputs[1 + i] = state[i] as Field;
    }
    hash_inputs[9] = processed_bytes as Field;
    hash_inputs[10] = data_commitment;
    Poseidon2::hash(hash_inputs, 11)
}

/// Verifies a SHA256 state + data commitment
pub fn verify_sha256_state_and_data_commitment(
    comm_in: Field,
    salt: Field,
    state: SHA256State,
    processed_bytes: u32,
    data_commitment: Field,
) {
    let expected = commit_to_sha256_state_and_data(salt, state, processed_bytes, data_commitment);
    assert(comm_in == expected, "SHA256 state+data commitment verification failed");
}

/// Commit to a chunk of message data for binding in the chain
pub fn commit_to_data_chunk<let N: u32>(salt: Field, data: [u8; N]) -> Field {
    let packed: [Field; (N + 30) / 31] = utils::pack_be_bytes_into_fields::<N, _, 31>(data);
    let mut hash_inputs: [Field; 1 + (N + 30) / 31] = std::mem::zeroed();
    hash_inputs[0] = salt;
    for i in 0..((N + 30) / 31) {
        hash_inputs[1 + i] = packed[i];
    }
    Poseidon2::hash(hash_inputs, 1 + (N + 30) / 31)
}

/// Chain two data commitments together
/// Output: Poseidon2(comm1, comm2)
pub fn chain_data_commitments(comm1: Field, comm2: Field) -> Field {
    Poseidon2::hash([comm1, comm2], 2)
}

/// Verify a chained data commitment for two chunks
pub fn verify_data_chain(
    data_chain: Field,
    salt: Field,
    chunk1: [u8; 320],
    chunk2: [u8; 320],
) {
    let data_comm1 = commit_to_data_chunk(salt, chunk1);
    let data_comm2 = commit_to_data_chunk(salt, chunk2);
    let expected = chain_data_commitments(data_comm1, data_comm2);
    assert(data_chain == expected, "Data chain commitment verification failed");
}
