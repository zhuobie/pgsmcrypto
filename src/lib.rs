pub mod sm3;
pub mod sm2;
pub mod sm4;

use pgrx::prelude::*;

pgrx::pg_module_magic!();

#[pg_extern(immutable, parallel_safe)]
fn sm3_hash(msg: &[u8]) -> String {
    sm3::sm3_hash(msg)
}

#[pg_extern(immutable, parallel_safe)]
fn sm3_hash_string(msg_str: &str) -> String {
    sm3::sm3_hash_string(msg_str)
}

#[pg_extern(immutable, parallel_safe)]
fn sm2_privkey_valid(private_key: &str) -> i32 {
    match sm2::privkey_valid(private_key) {
        true => 1,
        false => 0,
    }
}

#[pg_extern(immutable, parallel_safe)]
fn sm2_pubkey_valid(public_key: &str) -> i32 {
    match sm2::pubkey_valid(public_key) {
        true => 1,
        false => 0,
    }
}

#[pg_extern(immutable, parallel_safe)]
fn sm2_keypair_from_pem_bytes(pem_bytes: Vec<u8>) -> Vec<String> {
    let keypair = sm2::keypair_from_pem_bytes(pem_bytes);
    let private_key = keypair.0;
    let public_key = keypair.1;
    vec![private_key, public_key]
}

#[pg_extern(immutable, parallel_safe)]
fn sm2_pubkey_from_pem_bytes(pem_bytes: Vec<u8>) -> String {
    sm2::pubkey_from_pem_bytes(pem_bytes)
}

#[pg_extern(immutable, parallel_safe)]
fn sm2_keypair_to_pem_bytes(private_key: &str) -> Vec<u8> {
    sm2::keypair_to_pem_bytes(private_key)
}

#[pg_extern(immutable, parallel_safe)]
fn sm2_pubkey_to_pem_bytes(public_key: &str) -> Vec<u8> {
    sm2::pubkey_to_pem_bytes(public_key)
}

#[pg_extern(immutable, parallel_safe)]
fn sm2_gen_keypair() -> Vec<String> {
    let keypair = sm2::gen_keypair();
    let private_key = keypair.0;
    let public_key = keypair.1;
    vec![private_key, public_key]
}

#[pg_extern(immutable, parallel_safe)]
fn sm2_pk_from_sk(private_key: &str) -> String {
    sm2::pk_from_sk(private_key)
}

#[pg_extern(immutable, parallel_safe)]
fn sm2_sign_raw(data: &[u8], private_key: &str) -> Vec<u8> {
    sm2::sign_raw(data, private_key)
}

#[pg_extern(immutable, parallel_safe)]
fn sm2_verify_raw(data: &[u8], sign: &[u8], public_key: &str) -> i32 {
    match sm2::verify_raw(data, sign, public_key) {
        true => 1,
        false => 0,
    }
}

#[pg_extern(immutable, parallel_safe)]
fn sm2_sign(id: &[u8], data: &[u8], private_key: &str) -> Vec<u8> {
    sm2::sign(id, data, private_key)
}

#[pg_extern(immutable, parallel_safe)]
fn sm2_verify(id: &[u8], data: &[u8], sign: &[u8], public_key: &str) -> i32 {
    match sm2::verify(id, data, sign, public_key) {
        true => 1,
        false => 0,
    }
}

#[pg_extern(immutable, parallel_safe)]
fn sm2_encrypt(data: &[u8], public_key: &str) -> Vec<u8> {
    sm2::encrypt(data, public_key)
}

#[pg_extern(immutable, parallel_safe)]
fn sm2_decrypt(data: &[u8], private_key: &str) -> Vec<u8> {
    sm2::decrypt(data, private_key)
}

#[pg_extern(immutable, parallel_safe)]
fn sm2_encrypt_c1c2c3(data: &[u8], public_key: &str) -> Vec<u8> {
    sm2::encrypt_c1c2c3(data, public_key)
}

#[pg_extern(immutable, parallel_safe)]
fn sm2_decrypt_c1c2c3(data: &[u8], private_key: &str) -> Vec<u8> {
    sm2::decrypt_c1c2c3(data, private_key)
}

#[pg_extern(immutable, parallel_safe)]
fn sm2_encrypt_asna1(data: &[u8], public_key: &str) -> Vec<u8> {
    sm2::encrypt_asna1(data, public_key)
}

#[pg_extern(immutable, parallel_safe)]
fn sm2_decrypt_asna1(data: &[u8], private_key: &str) -> Vec<u8> {
    sm2::decrypt_asna1(data, private_key)
}

#[pg_extern(immutable, parallel_safe)]
fn sm2_encrypt_hex(data: &[u8], public_key: &str) -> String {
    sm2::encrypt_hex(data, public_key)
}

#[pg_extern(immutable, parallel_safe)]
fn sm2_decrypt_hex(data: &str, private_key: &str) -> Vec<u8> {
    sm2::decrypt_hex(data, private_key)
}

#[pg_extern(immutable, parallel_safe)]
fn sm2_encrypt_base64(data: &[u8], public_key: &str) -> String {
    sm2::encrypt_base64(data, public_key)
}

#[pg_extern(immutable, parallel_safe)]
fn sm2_decrypt_base64(data: &str, private_key: &str) -> Vec<u8> {
    sm2::decrypt_base64(data, private_key)
}

#[pg_extern(immutable, parallel_safe)]
fn sm4_encrypt_ecb(input_data: &[u8], key: &[u8]) -> Vec<u8> {
    sm4::encrypt_ecb(input_data, key)
}

#[pg_extern(immutable, parallel_safe)]
fn sm4_encrypt_ecb_base64(input_data: &[u8], key: &[u8]) -> String {
    sm4::encrypt_ecb_base64(input_data, key)
}

#[pg_extern(immutable, parallel_safe)]
fn sm4_encrypt_ecb_hex(input_data: &[u8], key: &[u8]) -> String {
    sm4::encrypt_ecb_hex(input_data, key)
}

#[pg_extern(immutable, parallel_safe)]
fn sm4_decrypt_ecb(input_data: &[u8], key: &[u8]) -> Vec<u8> {
    sm4::decrypt_ecb(input_data, key)
}

#[pg_extern(immutable, parallel_safe)]
fn sm4_decrypt_ecb_base64(input_data: &str, key: &[u8]) -> Vec<u8> {
    sm4::decrypt_ecb_base64(input_data, key)
}

#[pg_extern(immutable, parallel_safe)]
fn sm4_decrypt_ecb_hex(input_data: &str, key: &[u8]) -> Vec<u8> {
    sm4::decrypt_ecb_hex(input_data, key)
}

#[pg_extern(immutable, parallel_safe)]
fn sm4_encrypt_cbc(input_data: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    sm4::encrypt_cbc(input_data, key, iv)
}

#[pg_extern(immutable, parallel_safe)]
fn sm4_encrypt_cbc_base64(input_data: &[u8], key: &[u8], iv: &[u8]) -> String {
    sm4::encrypt_cbc_base64(input_data, key, iv)
}

#[pg_extern(immutable, parallel_safe)]
fn sm4_encrypt_cbc_hex(input_data: &[u8], key: &[u8], iv: &[u8]) -> String {
    sm4::encrypt_cbc_hex(input_data, key, iv)
}

#[pg_extern(immutable, parallel_safe)]
fn sm4_decrypt_cbc(input_data: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    sm4::decrypt_cbc(input_data, key, iv)
}

#[pg_extern(immutable, parallel_safe)]
fn sm4_decrypt_cbc_base64(input_data: &str, key: &[u8], iv: &[u8]) -> Vec<u8> {
    sm4::decrypt_cbc_base64(input_data, key, iv)
}

#[pg_extern(immutable, parallel_safe)]
fn sm4_decrypt_cbc_hex(input_data: &str, key: &[u8], iv: &[u8]) -> Vec<u8> {
    sm4::decrypt_cbc_hex(input_data, key, iv)
}
