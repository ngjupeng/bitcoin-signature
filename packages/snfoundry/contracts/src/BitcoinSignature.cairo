use contracts::bitcoin::{BitcoinPublicKey, Secp256Signature, is_valid_bitcoin_signature};


#[starknet::interface]
pub trait IBitcoinSignature<TContractState> {
    fn verify_message(
        self: @TContractState,
        message: ByteArray,
        signature: Secp256Signature,
        public_key: BitcoinPublicKey,
    ) -> bool;

    fn step1(self: @TContractState, message: felt252) -> u256;

    fn sha256(self: @TContractState, message: ByteArray) -> bool;
}


#[starknet::contract]
pub mod BitcoinSignature {
    use core::integer::u128_byte_reverse;
    use core::sha256::{compute_sha256_byte_array, compute_sha256_u32_array};
    use utils::hash::{Digest, DigestTrait};
    use super::{BitcoinPublicKey, IBitcoinSignature, Secp256Signature, is_valid_bitcoin_signature};

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        BitcoinMessageHashing: BitcoinMessageHashing,
    }

    #[derive(Drop, starknet::Event)]
    struct BitcoinMessageHashing {
        #[key]
        step1: u256,
        step2: u256,
    }

    #[storage]
    struct Storage {}


    #[abi(embed_v0)]
    impl BitcoinSignatureImpl of IBitcoinSignature<ContractState> {
        fn verify_message(
            self: @ContractState,
            message: ByteArray,
            signature: Secp256Signature,
            public_key: BitcoinPublicKey,
        ) -> bool {
            is_valid_bitcoin_signature(message, public_key, signature)
        }

        fn sha256(self: @ContractState, message: ByteArray) -> bool {
            let hash: ByteArray = DigestTrait::new(compute_sha256_byte_array(@message)).into();
            hash == "84342368487090800366523834928142263660104883695016514377462985829716817089965"
        }

        fn step1(self: @ContractState, message: felt252) -> u256 {
            // 0x42697463 0x6f696e20 0x5369676e 0x6564204d 0x65737361 0x67653a5c 0x6e3332

            let shift_4_bytes: u256 = 0x100000000;
            let shift_8_bytes: u256 = 0x10000000000000000;

            let rest: u256 = message.into();
            let (rest, tx_hash_part_9) = DivRem::div_rem(rest, shift_4_bytes.try_into().unwrap());
            let (rest, tx_hash_part_8) = DivRem::div_rem(rest, shift_4_bytes.try_into().unwrap());
            let (rest, tx_hash_part_7) = DivRem::div_rem(rest, shift_4_bytes.try_into().unwrap());
            let (rest, tx_hash_part_6) = DivRem::div_rem(rest, shift_4_bytes.try_into().unwrap());
            let (rest, tx_hash_part_5) = DivRem::div_rem(rest, shift_4_bytes.try_into().unwrap());
            let (rest, tx_hash_part_4) = DivRem::div_rem(rest, shift_4_bytes.try_into().unwrap());
            let (rest, tx_hash_part_3) = DivRem::div_rem(rest, shift_4_bytes.try_into().unwrap());
            let (tx_hash_part_1, tx_hash_part_2) = DivRem::div_rem(
                rest, shift_8_bytes.try_into().unwrap(),
            );

            let tx_hash_part_1: u32 = tx_hash_part_1.try_into().unwrap(); // 4 bytes 
            let tx_hash_part_2: u32 = tx_hash_part_2.try_into().unwrap(); // 4 bytes 
            let tx_hash_part_3: u32 = tx_hash_part_3.try_into().unwrap(); // 4 bytes 
            let tx_hash_part_4: u32 = tx_hash_part_4.try_into().unwrap(); // 4 bytes 
            let tx_hash_part_5: u32 = tx_hash_part_5.try_into().unwrap(); // 4 bytes 
            let tx_hash_part_6: u32 = tx_hash_part_6.try_into().unwrap(); // 4 bytes 
            let tx_hash_part_7: u32 = tx_hash_part_7.try_into().unwrap(); // 4 bytes 
            let tx_hash_part_8: u32 = tx_hash_part_8.try_into().unwrap(); // 4 bytes 
            let tx_hash_part_9: u32 = tx_hash_part_9.try_into().unwrap(); // 4 bytes 

            let hash_input = array![
                self.u32_byte_reverse(0x42697463),
                self.u32_byte_reverse(0x6f696e20),
                self.u32_byte_reverse(0x5369676e),
                self.u32_byte_reverse(0x6564204d),
                self.u32_byte_reverse(0x65737361),
                self.u32_byte_reverse(0x67653a5c),
                self.u32_byte_reverse(0x6e333200),
                self.u32_byte_reverse(tx_hash_part_1),
                self.u32_byte_reverse(tx_hash_part_2),
                self.u32_byte_reverse(tx_hash_part_3),
                self.u32_byte_reverse(tx_hash_part_4),
                self.u32_byte_reverse(tx_hash_part_5),
                self.u32_byte_reverse(tx_hash_part_6),
                self.u32_byte_reverse(tx_hash_part_7),
                self.u32_byte_reverse(tx_hash_part_8),
                self.u32_byte_reverse(tx_hash_part_9),
            ];

            let step1: u256 = DigestTrait::new(compute_sha256_u32_array(hash_input, 0, 0)).into();
            step1
        }
    }

    #[generate_trait]
    impl Private of PrivateTrait {
        fn u64_byte_reverse(self: @ContractState, word: u64) -> u64 {
            (u128_byte_reverse(word.into()) / 0x10000000000000000).try_into().unwrap()
        }

        fn u32_byte_reverse(self: @ContractState, word: u32) -> u32 {
            let word64: u64 = word.into();
            let reversed64: u64 = self.u64_byte_reverse(word64);
            let result64: u64 = reversed64 / 0x1_0000_0000; // shift down 32 bits
            return result64.try_into().unwrap(); // convert back to u32
        }
    }
}
