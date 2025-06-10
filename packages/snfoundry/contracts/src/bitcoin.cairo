use core::integer::u128_byte_reverse;
use core::option::OptionTrait;
use core::sha256::{compute_sha256_byte_array, compute_sha256_u32_array};
use core::traits::TryInto;
use garaga::basic_field_ops::{inv_mod_p, mul_mod_p};
use garaga::definitions::get_curve_order_modulus;
use garaga::ec_ops::{G1Point, G1PointTrait, u384};
use starknet::SyscallResultTrait;
use starknet::secp256_trait::{Secp256PointTrait, Secp256Trait};
use starknet::secp256k1::Secp256k1Point;
use utils::hash::{Digest, DigestTrait};
use utils::word_array::{WordArray, WordArrayTrait};

#[derive(Copy, Drop, Debug, PartialEq, Serde, Hash)]
pub struct Secp256Signature {
    pub r: u256,
    pub s: u256,
}

#[derive(Copy, Drop, Debug, PartialEq, Serde, Hash)]
pub struct BitcoinPublicKey {
    pub x: u256,
    pub y: u256,
}


const TWO_POW_32: u128 = 0x100000000;
const TWO_POW_64: u128 = 0x10000000000000000;
const TWO_POW_96: u128 = 0x1000000000000000000000000;

fn is_bitcoin_signature_valid(
    hash: u256, pubkey: BitcoinPublicKey, signature: Secp256Signature,
) -> bool {
    let curve_id = 2; // curve id 2 is for secp256k1

    let public_key_point =
        match Secp256Trait::<Secp256k1Point>::secp256_ec_new_syscall(pubkey.x, pubkey.y)
            .unwrap_syscall() {
        Option::Some(point) => point,
        Option::None => { return false; },
    };

    // Verify public key is on curve
    let pk_point = G1Point { x: pubkey.x.into(), y: pubkey.y.into() };
    if !pk_point.is_on_curve(curve_id) {
        return false;
    }

    // to verify bitcoin signature, we need three things
    // 1. Public Key `Q`
    // 2. Message Hash `z`
    // 3. Signature `(r, s)`

    // first we need to find point 1, start with the generator point G, and multiply it by
    // inverse(s) * z.
    // then find point 2, start with the public key point Q, and multiply it by inverse(s) * r.
    // add these points together to give us Point 3:

    // get generator
    let G = Secp256Trait::<Secp256k1Point>::get_generator_point();
    let modulus = get_curve_order_modulus(curve_id);
    let s_u384: u384 = signature.s.into();
    let s_inv = inv_mod_p(s_u384, modulus); // get inverse of s

    let u1: u256 = mul_mod_p(hash.into(), s_inv, modulus).try_into().unwrap();
    let u2: u256 = mul_mod_p(signature.r.into(), s_inv, modulus).try_into().unwrap();

    let point1 = G.mul(u1).unwrap_syscall();
    let point2 = public_key_point.mul(u2).unwrap_syscall();
    let R = point1.add(point2).unwrap_syscall();
    let (Rx, _Ry) = R.get_coordinates().unwrap_syscall();
    Rx == signature.r
}

pub fn hex_char_to_nibble(hex_char: u8) -> u8 {
    if hex_char >= 48 && hex_char <= 57 {
        // 0-9
        hex_char - 48
    } else if hex_char >= 65 && hex_char <= 70 {
        // A-F
        hex_char - 55
    } else if hex_char >= 97 && hex_char <= 102 {
        // a-f
        hex_char - 87
    } else {
        panic!("Invalid hex character: {hex_char}");
        0
    }
}

pub fn words_from_hex(hex_string: ByteArray) -> WordArray {
    let num_characters = hex_string.len();
    assert!(num_characters % 2 == 0, "Invalid hex string length");

    let mut words: WordArray = Default::default();
    let mut i = 0;

    while i != num_characters {
        let hi = hex_char_to_nibble(hex_string[i]);
        let lo = hex_char_to_nibble(hex_string[i + 1]);
        words.append_u8(hi * 16 + lo);
        i += 2;
    }

    words
}

fn u64_byte_reverse(word: u64) -> u64 {
    (u128_byte_reverse(word.into()) / 0x10000000000000000).try_into().unwrap()
}

fn u32_byte_reverse(word: u32) -> u32 {
    let word64: u64 = word.into();
    let reversed64: u64 = u64_byte_reverse(word64);
    let result64: u64 = reversed64 / 0x1_0000_0000; // shift down 32 bits
    return result64.try_into().unwrap(); // convert back to u32
}

fn calculate_bitcoin_hash(message: ByteArray) -> u256 {
    let input1 = compute_sha256_byte_array(@message);
    let mut array = ArrayTrait::new();
    array.append_span(input1.span());
    DigestTrait::new(compute_sha256_u32_array(array, 0, 0)).into()
}


/// @dev The only function needed to be called from the contract
pub fn is_valid_bitcoin_signature(
    message: u256, public_key: BitcoinPublicKey, signature: Secp256Signature,
) -> bool {
    is_bitcoin_signature_valid(message, public_key, signature)
}
