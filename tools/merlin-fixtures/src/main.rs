//! Emits contracts/test/fixtures/merlin.json.
//!
//! Every `expected` value in that file is produced by the SAME crates
//! MobileCoin links -- `merlin` 3.0.0 and `mc-crypto-digestible` 7.1.0 from
//! vendor/mobilecoin -- driven through their public APIs. Nothing here
//! reimplements STROBE, Merlin or the digestible AST framing. The Solidity in
//! contracts/src/Merlin.sol does, and contracts/test/merlin.mjs asserts the
//! two agree byte for byte.
//!
//! Run: `cargo run --offline` from this directory.

use mc_crypto_digestible::{DigestTranscript, Digestible, MerlinTranscript};
use serde_json::{json, Map, Value};
use std::path::PathBuf;

/// The digestible AST methods take `&'static [u8]` contexts, but a fixture
/// table is runtime data. Leaking is fine in a build-time generator that exits.
fn stat(b: &[u8]) -> &'static [u8] {
    Box::leak(b.to_vec().into_boxed_slice())
}

/// One transcript operation. Serialised into the fixture and, separately,
/// replayed against the real crate to obtain the expected bytes.
#[derive(Clone)]
enum Op {
    /// merlin `Transcript::append_message`
    Append(Vec<u8>, Vec<u8>),
    /// merlin `Transcript::challenge_bytes`; its output is concatenated into
    /// the case's expected value
    Challenge(Vec<u8>, usize),
    /// merlin `Transcript::append_u64`
    U64(Vec<u8>, u64),
    /// digestible `DigestTranscript::append_primitive`
    Prim(Vec<u8>, Vec<u8>, Vec<u8>),
    /// digestible `DigestTranscript::append_none`
    None_(Vec<u8>),
    /// digestible `DigestTranscript::append_seq_header`
    Seq(Vec<u8>, u64),
    /// digestible `DigestTranscript::append_agg_header`
    Agg(Vec<u8>, Vec<u8>),
    /// digestible `DigestTranscript::append_agg_closer`
    AggEnd(Vec<u8>, Vec<u8>),
    /// digestible `DigestTranscript::append_var_header`
    Var(Vec<u8>, Vec<u8>, u32),
}

impl Op {
    fn to_json(&self) -> Value {
        match self {
            Op::Append(c, d) => {
                json!({"op":"append","ctx":hex::encode(c),"data":hex::encode(d)})
            }
            Op::Challenge(c, n) => {
                json!({"op":"challenge","ctx":hex::encode(c),"len":n})
            }
            Op::U64(c, v) => {
                json!({"op":"u64","ctx":hex::encode(c),"value":v.to_string()})
            }
            Op::Prim(c, t, d) => json!({
                "op":"prim","ctx":hex::encode(c),
                "typename":hex::encode(t),"data":hex::encode(d)
            }),
            Op::None_(c) => json!({"op":"none","ctx":hex::encode(c)}),
            Op::Seq(c, n) => {
                json!({"op":"seq","ctx":hex::encode(c),"len":n.to_string()})
            }
            Op::Agg(c, n) => {
                json!({"op":"agg","ctx":hex::encode(c),"name":hex::encode(n)})
            }
            Op::AggEnd(c, n) => {
                json!({"op":"aggend","ctx":hex::encode(c),"name":hex::encode(n)})
            }
            Op::Var(c, n, w) => json!({
                "op":"var","ctx":hex::encode(c),"name":hex::encode(n),"which":w
            }),
        }
    }
}

/// Replay a script against a real `merlin::Transcript`, concatenating every
/// challenge output. This is the oracle.
fn run(label: &[u8], ops: &[Op]) -> Vec<u8> {
    let mut t = MerlinTranscript::new(stat(label));
    let mut out = Vec::new();
    for op in ops {
        match op {
            Op::Append(c, d) => t.append_message(stat(c), d),
            Op::Challenge(c, n) => {
                let mut buf = vec![0u8; *n];
                t.challenge_bytes(stat(c), &mut buf);
                out.extend_from_slice(&buf);
            }
            Op::U64(c, v) => t.append_u64(stat(c), *v),
            Op::Prim(c, ty, d) => t.append_primitive(stat(c), stat(ty), d),
            Op::None_(c) => t.append_none(stat(c)),
            Op::Seq(c, n) => t.append_seq_header(stat(c), *n as usize),
            Op::Agg(c, n) => t.append_agg_header(stat(c), n),
            Op::AggEnd(c, n) => t.append_agg_closer(stat(c), n),
            Op::Var(c, n, w) => t.append_var_header(stat(c), n, *w),
        }
    }
    out
}

fn case(name: &str, label: &[u8], ops: Vec<Op>) -> Value {
    let expected = run(label, &ops);
    json!({
        "name": name,
        "label": hex::encode(label),
        "ops": ops.iter().map(Op::to_json).collect::<Vec<_>>(),
        "expected": hex::encode(expected),
    })
}

// ---------------------------------------------------------------------------
// Transcribed MobileCoin types
// ---------------------------------------------------------------------------
//
// These five declarations are copied from mobilecoin rev 05cb699f, with only
// the non-digestible derives (prost::Message, serde, Zeroize, Ord, ...) and
// doc comments removed. They exist here because linking the real
// `mc-blockchain-types` is not possible on this toolchain: it pulls in
// `mc-common`, which turns on hashbrown's `nightly` feature, and
// hashbrown 0.14.x's `min_specialization` use no longer compiles on current
// rustc. See README.md -- this is the one gap in the chain and it is a real
// one.
//
// What IS real here: the `#[derive(Digestible)]` macro expanding these, and
// the merlin transcript underneath it. Only the field names, field order,
// type names and `#[digestible]` attributes are transcribed.
//
//   transaction/core/src/membership_proofs/range.rs:21-31
#[derive(Digestible)]
pub struct Range {
    pub from: u64,
    pub to: u64,
}

//   transaction/core/src/tx.rs:594-608
#[derive(Digestible)]
#[digestible(transparent)]
pub struct TxOutMembershipHash(pub [u8; 32]);

//   transaction/core/src/tx.rs:570-581
#[derive(Digestible)]
pub struct TxOutMembershipElement {
    pub range: Range,
    pub hash: TxOutMembershipHash,
}

//   blockchain/types/src/block_id.rs:16-20
#[derive(Digestible)]
#[digestible(transparent)]
pub struct BlockID(pub [u8; 32]);

//   blockchain/types/src/block_contents.rs:46-50
#[derive(Digestible)]
#[digestible(transparent)]
pub struct BlockContentsHash(pub [u8; 32]);

//   blockchain/types/src/block.rs:177-287 `compute_block_id`, verbatim
fn compute_block_id(
    version: u32,
    parent_id: &BlockID,
    index: u64,
    cumulative_txo_count: u64,
    root_element: &TxOutMembershipElement,
    contents_hash: &BlockContentsHash,
) -> [u8; 32] {
    let mut transcript = MerlinTranscript::new(b"mobilecoin-block-id");

    version.append_to_transcript(b"version", &mut transcript);
    parent_id.append_to_transcript(b"parent_id", &mut transcript);
    index.append_to_transcript(b"index", &mut transcript);
    cumulative_txo_count.append_to_transcript(b"cumulative_txo_count", &mut transcript);
    root_element.append_to_transcript(b"root_element", &mut transcript);
    contents_hash.append_to_transcript(b"contents_hash", &mut transcript);

    let mut result = [0u8; 32];
    transcript.extract_digest(&mut result);
    result
}

fn block_id_case(
    name: &str,
    version: u32,
    parent: [u8; 32],
    index: u64,
    cumulative_txo_count: u64,
    from: u64,
    to: u64,
    root_hash: [u8; 32],
    contents_hash: [u8; 32],
) -> Value {
    let element = TxOutMembershipElement {
        range: Range { from, to },
        hash: TxOutMembershipHash(root_hash),
    };
    let id = compute_block_id(
        version,
        &BlockID(parent),
        index,
        cumulative_txo_count,
        &element,
        &BlockContentsHash(contents_hash),
    );
    json!({
        "name": name,
        "version": version,
        "parentId": hex::encode(parent),
        "index": index.to_string(),
        "cumulativeTxoCount": cumulative_txo_count.to_string(),
        "rangeFrom": from.to_string(),
        "rangeTo": to.to_string(),
        "rootHash": hex::encode(root_hash),
        "contentsHash": hex::encode(contents_hash),
        "blockId": hex::encode(id),
    })
}

// ---------------------------------------------------------------------------

fn rep(b: u8, n: usize) -> Vec<u8> {
    vec![b; n]
}

/// Deterministic filler with no structure a byte-oriented bug could hide in
/// (a run of equal bytes would mask an off-by-one in the state cursor).
fn counter(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i.wrapping_mul(37).wrapping_add(11) & 0xff) as u8).collect()
}

fn main() {
    let mut cases: Vec<Value> = Vec::new();

    // The empty script isolates STROBE init and the dom-sep append. If this
    // one disagrees, nothing downstream is worth reading.
    cases.push(case("init-only", b"test protocol", vec![Op::Challenge(b"c".to_vec(), 32)]));

    // A domain separator long enough to cross the 166-byte rate during
    // Transcript::new itself.
    cases.push(case(
        "long-dom-sep",
        &counter(400),
        vec![Op::Challenge(b"c".to_vec(), 32)],
    ));

    // merlin's own `equivalence_simple`.
    cases.push(case(
        "equivalence-simple",
        b"test protocol",
        vec![
            Op::Append(b"some label".to_vec(), b"some data".to_vec()),
            Op::Challenge(b"challenge".to_vec(), 32),
        ],
    ));

    // Message lengths straddling every rate boundary the absorb loop can hit.
    // 166 is the rate; the interesting cases are the ones where run_f fires on
    // the last byte of the message, or on the first byte of the next
    // operation's two-byte header.
    for n in [0usize, 1, 2, 150, 160, 161, 162, 163, 164, 165, 166, 167, 168, 331, 332, 333, 500] {
        cases.push(case(
            &format!("absorb-len-{n}"),
            b"boundary",
            vec![
                Op::Append(b"m".to_vec(), counter(n)),
                Op::Challenge(b"c".to_vec(), 32),
            ],
        ));
    }

    // Challenge lengths straddling the rate, so the squeeze loop wraps.
    for n in [0usize, 1, 31, 32, 165, 166, 167, 200, 400] {
        cases.push(case(
            &format!("squeeze-len-{n}"),
            b"boundary",
            vec![
                Op::Append(b"m".to_vec(), b"seed".to_vec()),
                Op::Challenge(b"c".to_vec(), n),
                Op::Challenge(b"after".to_vec(), 32),
            ],
        ));
    }

    // Label lengths matter too: the label is absorbed inside the meta-AD that
    // the LE32 length continues, so a label that crosses the rate exercises
    // the `more = true` path across a permutation.
    for n in [0usize, 1, 163, 164, 165, 166, 167] {
        cases.push(case(
            &format!("label-len-{n}"),
            b"boundary",
            vec![
                Op::Append(counter(n), b"x".to_vec()),
                Op::Challenge(b"c".to_vec(), 32),
            ],
        ));
    }

    // merlin's own `equivalence_complex`: 32 rounds of challenge, 1024-byte
    // append, and append-of-the-challenge.
    {
        let mut ops = vec![Op::Append(b"step1".to_vec(), b"some data".to_vec())];
        for _ in 0..32 {
            ops.push(Op::Challenge(b"challenge".to_vec(), 32));
            ops.push(Op::Append(b"bigdata".to_vec(), rep(99, 1024)));
            // The real test re-appends the challenge it just read; the script
            // format has no way to reference an earlier output, so this
            // appends a fixed stand-in of the same length. The property under
            // test -- long runs of alternating absorb and squeeze -- is
            // unaffected.
            ops.push(Op::Append(b"challengedata".to_vec(), counter(32)));
        }
        cases.push(case("equivalence-complex", b"test protocol", ops));
    }

    // append_u64 framing.
    cases.push(case(
        "u64s",
        b"u64 protocol",
        vec![
            Op::U64(b"a".to_vec(), 0),
            Op::U64(b"b".to_vec(), 1),
            Op::U64(b"c".to_vec(), u64::MAX),
            Op::U64(b"d".to_vec(), 0x0123_4567_89ab_cdef),
            Op::Challenge(b"out".to_vec(), 48),
        ],
    ));

    // Back-to-back challenges with no intervening append: each PRF forces a
    // permutation on begin_op, so this pins the force_f branch.
    cases.push(case(
        "repeated-challenges",
        b"prf protocol",
        vec![
            Op::Challenge(b"c".to_vec(), 1),
            Op::Challenge(b"c".to_vec(), 1),
            Op::Challenge(b"c".to_vec(), 1),
            Op::Challenge(b"c".to_vec(), 64),
        ],
    ));

    // Every digestible AST node type, in one transcript, so an error in any
    // one separator string shows up.
    cases.push(case(
        "digestible-ast-nodes",
        b"digestible",
        vec![
            Op::Agg(b"root".to_vec(), b"Outer".to_vec()),
            Op::Prim(b"a".to_vec(), b"uint".to_vec(), vec![1, 0, 0, 0]),
            Op::None_(b"b".to_vec()),
            Op::Seq(b"c".to_vec(), 3),
            Op::Prim(b"".to_vec(), b"uint".to_vec(), vec![1, 0, 0, 0]),
            Op::Prim(b"".to_vec(), b"uint".to_vec(), vec![2, 0, 0, 0]),
            Op::Prim(b"".to_vec(), b"uint".to_vec(), vec![3, 0, 0, 0]),
            Op::Var(b"d".to_vec(), b"Enum".to_vec(), 7),
            Op::Prim(b"".to_vec(), b"bytes".to_vec(), b"payload".to_vec()),
            Op::AggEnd(b"root".to_vec(), b"Outer".to_vec()),
            Op::Challenge(b"digest32".to_vec(), 32),
        ],
    ));

    // ---------------- upstream known-answer vectors ----------------
    //
    // These expected values are ALSO hardcoded in mobilecoin
    // crypto/digestible/tests/basic.rs (`primitives_test_vectors`,
    // `test_digest_option`, `test_digest_vec`), written by MobileCoin. The
    // assertion below checks that replaying the AST through the real crate
    // reproduces them; the JSON then requires the Solidity to reproduce them
    // too. So the Solidity is pinned to a value MobileCoin published, not
    // merely to a value this program computed.
    let mut kats: Vec<Value> = Vec::new();
    let mut kat = |name: &str, ops: Vec<Op>, upstream: [u8; 32]| {
        let got = run(b"digestible", &ops);
        assert_eq!(
            got[..],
            upstream[..],
            "{name}: replaying the AST through the real crates did not \
             reproduce the digest hardcoded in mobilecoin \
             crypto/digestible/tests/basic.rs"
        );
        kats.push(json!({
            "name": name,
            "label": hex::encode(b"digestible"),
            "ops": ops.iter().map(Op::to_json).collect::<Vec<_>>(),
            "expected": hex::encode(got),
            "upstream": "mobilecoin crypto/digestible/tests/basic.rs",
        }));
    };

    let uint = |d: Vec<u8>| {
        vec![
            Op::Prim(b"test".to_vec(), b"uint".to_vec(), d),
            Op::Challenge(b"digest32".to_vec(), 32),
        ]
    };

    kat(
        "u64-0",
        uint(0u64.to_le_bytes().to_vec()),
        [
            3, 240, 99, 152, 14, 1, 149, 80, 250, 86, 180, 216, 110, 25, 51, 107, 30, 14, 87, 217,
            133, 130, 167, 71, 103, 51, 29, 107, 225, 251, 61, 28,
        ],
    );
    kat(
        "u64-1",
        uint(1u64.to_le_bytes().to_vec()),
        [
            186, 128, 104, 76, 244, 56, 203, 3, 127, 123, 0, 222, 158, 227, 240, 30, 219, 188, 27,
            39, 214, 51, 157, 82, 8, 136, 185, 253, 100, 4, 117, 110,
        ],
    );
    kat(
        "u64-max",
        uint(u64::MAX.to_le_bytes().to_vec()),
        [
            199, 212, 113, 79, 91, 56, 22, 48, 131, 244, 165, 157, 170, 131, 255, 29, 59, 249, 175,
            89, 255, 57, 43, 50, 76, 217, 9, 219, 85, 103, 113, 88,
        ],
    );
    kat(
        "u32-4",
        uint(4u32.to_le_bytes().to_vec()),
        [
            218, 122, 37, 225, 130, 175, 190, 151, 120, 87, 222, 168, 127, 47, 73, 201, 25, 40,
            226, 20, 74, 27, 254, 195, 163, 126, 64, 237, 139, 63, 95, 193,
        ],
    );
    kat(
        "u16-4",
        uint(4u16.to_le_bytes().to_vec()),
        [
            162, 203, 81, 231, 249, 140, 154, 24, 65, 158, 148, 64, 96, 21, 48, 84, 126, 206, 225,
            124, 197, 61, 5, 150, 125, 45, 85, 113, 176, 112, 16, 74,
        ],
    );
    // i64 is `int`, not `uint` -- a distinct typename, hence a distinct digest
    // for the same bytes.
    kat(
        "i64-neg19",
        vec![
            Op::Prim(b"test".to_vec(), b"int".to_vec(), (-19i64).to_le_bytes().to_vec()),
            Op::Challenge(b"digest32".to_vec(), 32),
        ],
        [
            40, 117, 43, 212, 193, 213, 3, 244, 43, 51, 234, 26, 235, 38, 254, 187, 55, 184, 30,
            147, 157, 178, 45, 2, 206, 64, 250, 109, 179, 41, 250, 207,
        ],
    );
    kat(
        "bool-true",
        vec![
            Op::Prim(b"test".to_vec(), b"bool".to_vec(), vec![1]),
            Op::Challenge(b"digest32".to_vec(), 32),
        ],
        [
            43, 47, 123, 204, 127, 100, 113, 181, 186, 75, 237, 124, 118, 82, 178, 18, 36, 68, 200,
            197, 226, 119, 254, 216, 248, 169, 80, 213, 177, 105, 74, 139,
        ],
    );
    kat(
        "bytes-Moose",
        vec![
            Op::Prim(b"test".to_vec(), b"bytes".to_vec(), b"Moose".to_vec()),
            Op::Challenge(b"digest32".to_vec(), 32),
        ],
        [
            74, 2, 88, 165, 144, 53, 142, 180, 217, 188, 176, 227, 153, 178, 153, 12, 62, 157, 215,
            120, 135, 160, 117, 114, 95, 201, 169, 182, 238, 153, 17, 21,
        ],
    );
    // Same bytes as above, different typename: the two must not collide.
    kat(
        "str-Moose",
        vec![
            Op::Prim(b"test".to_vec(), b"str".to_vec(), b"Moose".to_vec()),
            Op::Challenge(b"digest32".to_vec(), 32),
        ],
        [
            249, 27, 225, 46, 77, 153, 89, 235, 98, 17, 218, 128, 114, 96, 244, 217, 150, 240, 195,
            131, 181, 176, 181, 189, 249, 164, 14, 96, 213, 124, 5, 231,
        ],
    );
    kat(
        "scalar-10",
        vec![
            Op::Prim(b"test".to_vec(), b"scalar".to_vec(), {
                let mut v = vec![0u8; 32];
                v[0] = 10;
                v
            }),
            Op::Challenge(b"digest32".to_vec(), 32),
        ],
        [
            174, 15, 64, 233, 225, 254, 36, 100, 145, 155, 193, 51, 53, 242, 199, 217, 148, 118,
            26, 152, 227, 191, 65, 98, 185, 116, 209, 84, 57, 190, 233, 197,
        ],
    );
    kat(
        "none",
        vec![
            Op::None_(b"test".to_vec()),
            Op::Challenge(b"digest32".to_vec(), 32),
        ],
        [
            35, 213, 109, 195, 226, 235, 162, 166, 228, 183, 30, 23, 226, 184, 19, 8, 12, 166, 24,
            194, 247, 84, 216, 45, 122, 19, 75, 140, 159, 233, 85, 6,
        ],
    );
    kat(
        "vec-u32-1-2-3",
        vec![
            Op::Seq(b"test".to_vec(), 3),
            Op::Prim(b"".to_vec(), b"uint".to_vec(), 1u32.to_le_bytes().to_vec()),
            Op::Prim(b"".to_vec(), b"uint".to_vec(), 2u32.to_le_bytes().to_vec()),
            Op::Prim(b"".to_vec(), b"uint".to_vec(), 3u32.to_le_bytes().to_vec()),
            Op::Challenge(b"digest32".to_vec(), 32),
        ],
        [
            57, 188, 233, 215, 161, 193, 239, 222, 47, 27, 96, 29, 63, 204, 63, 47, 197, 53, 50,
            58, 62, 148, 55, 17, 109, 143, 127, 120, 19, 50, 44, 18,
        ],
    );
    kat(
        "vec-u64-1-2-3",
        vec![
            Op::Seq(b"test".to_vec(), 3),
            Op::Prim(b"".to_vec(), b"uint".to_vec(), 1u64.to_le_bytes().to_vec()),
            Op::Prim(b"".to_vec(), b"uint".to_vec(), 2u64.to_le_bytes().to_vec()),
            Op::Prim(b"".to_vec(), b"uint".to_vec(), 3u64.to_le_bytes().to_vec()),
            Op::Challenge(b"digest32".to_vec(), 32),
        ],
        [
            24, 143, 163, 51, 160, 229, 9, 222, 149, 104, 49, 33, 194, 75, 205, 201, 10, 100, 27,
            224, 134, 252, 82, 178, 105, 246, 138, 217, 42, 232, 222, 58,
        ],
    );

    // ---------------- block ids ----------------
    //
    // Inputs chosen to move every field independently, plus the origin-block
    // shape (all zero, version 0) and an all-max shape.
    let block_ids = vec![
        block_id_case("origin-shaped", 0, [0u8; 32], 0, 0, 0, 0, [0u8; 32], [0u8; 32]),
        // The header values mobilecoin's own block tests use for `get_block`:
        // version 1, parent [14; 32], index 3, cumulative_txo_count 400,
        // range 0..15, root hash zero. The contents hash there comes from a
        // seeded RNG we cannot reproduce, so a fixed stand-in is used.
        block_id_case(
            "mc-block-test-shape",
            1,
            [14u8; 32],
            3,
            400,
            0,
            15,
            [0u8; 32],
            counter(32).try_into().unwrap(),
        ),
        block_id_case(
            "version-bumped",
            2,
            [14u8; 32],
            3,
            400,
            0,
            15,
            [0u8; 32],
            counter(32).try_into().unwrap(),
        ),
        block_id_case(
            "range-moved",
            1,
            [14u8; 32],
            3,
            400,
            13,
            17,
            [0u8; 32],
            counter(32).try_into().unwrap(),
        ),
        block_id_case(
            "all-max",
            u32::MAX,
            [0xffu8; 32],
            u64::MAX,
            u64::MAX,
            u64::MAX,
            u64::MAX,
            [0xffu8; 32],
            [0xffu8; 32],
        ),
        block_id_case(
            "mixed",
            7,
            counter(32).try_into().unwrap(),
            0x0123_4567_89ab_cdef,
            1_000_000,
            42,
            99,
            rep(0xa5, 32).try_into().unwrap(),
            rep(0x5a, 32).try_into().unwrap(),
        ),
    ];

    let mut root = Map::new();
    root.insert(
        "_generator".into(),
        json!("tools/merlin-fixtures -- do not edit by hand"),
    );
    root.insert("merlinVersion".into(), json!("3.0.0"));
    root.insert("digestibleVersion".into(), json!("7.1.0"));
    root.insert("cases".into(), Value::Array(cases));
    root.insert("digestibleKats".into(), Value::Array(kats));
    root.insert("blockIds".into(), Value::Array(block_ids));

    let out: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../contracts/test/fixtures/merlin.json");
    std::fs::create_dir_all(out.parent().unwrap()).unwrap();
    std::fs::write(&out, serde_json::to_string_pretty(&Value::Object(root)).unwrap() + "\n")
        .unwrap();
    println!("wrote {}", out.display());
}
