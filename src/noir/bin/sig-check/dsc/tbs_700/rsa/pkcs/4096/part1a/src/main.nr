// Part 1a: SHA256 Start - Process first 320 bytes (5 blocks) of TBS certificate
// This is the first circuit in the partial SHA256 chain for memory reduction.
//
// Flow: part1a -> part1b -> part1c -> part2
//
// Security: We commit to both the SHA256 state AND a commitment to the data chunk.
// This ensures the data processed here is cryptographically bound to the chain.
use partial_sha256::{
    SHA256State, sha256_start, commit_to_sha256_state_and_data, commit_to_data_chunk,
};

// First chunk size: 320 bytes = 5 SHA256 blocks
global CHUNK1_SIZE: u32 = 320;

fn main(
    // Private inputs
    salt: Field,
    chunk1: [u8; CHUNK1_SIZE],  // Bytes 0-319 of TBS certificate
) -> pub Field {
    // Step 1: Process the first 5 blocks of SHA256
    let state1: SHA256State = sha256_start(chunk1);

    // Step 2: Commit to the data chunk (for later verification)
    let data_comm1 = commit_to_data_chunk(salt, chunk1);

    // Step 3: Output commitment: binds state + data together
    // This commitment will be verified by part1b
    let comm_out = commit_to_sha256_state_and_data(salt, state1, CHUNK1_SIZE, data_comm1);

    comm_out
}
