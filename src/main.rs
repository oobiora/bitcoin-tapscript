use bitcoin::address::Address;
use bitcoin::blockdata::opcodes::all;
use bitcoin::blockdata::script::{Builder, PushBytes, PushBytesBuf, PushBytesError, ScriptBuf};
use bitcoin::network::constants::Network;
use jsonrpsee::core::traits::ToRpcParams;
use jsonrpsee::RpcModule;
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use sha3::{Digest, Keccak256};

// computes arbitrary s hash -- should add in matcher to insure that s_hash would be similar if
// selector is similar
pub fn compute_s_hash(selector: String) -> Vec<u8> {
    selector.into_bytes()
}

pub fn compute_p_hash(payload: &[u8]) -> Result<Vec<u8>, &'static str> {
    let hash = Keccak256::new().chain_update(payload).finalize();

    Ok(hash.to_vec())
}

// should compute g_hash given transaction params
pub fn compute_g_hash(
    p_hash: &[u8],
    s_hash: &[u8],
    to: &[u8],
    nonce: &[u8],
) -> Result<Vec<u8>, &'static str> {
    let hash = Keccak256::new()
        .chain_update(p_hash)
        .chain_update(s_hash)
        .chain_update(to)
        .chain_update(nonce)
        .finalize();

    Ok(hash.to_vec())
}

pub fn to_address(
    g_hash: String,
    g_pubkey_hash: String,
) -> Result<bitcoin::Address, bitcoin::address::Error> {
    let mut g_hash_push_bytes = PushBytesBuf::new();
    g_hash_push_bytes.extend_from_slice(g_hash.as_bytes());

    let mut g_pubkey_hash_push_bytes = PushBytesBuf::new();
    g_pubkey_hash_push_bytes.extend_from_slice(g_pubkey_hash.as_bytes());

    let g_script = gateway_address(
        g_hash_push_bytes.as_push_bytes(),
        g_pubkey_hash_push_bytes.as_push_bytes(),
    )
    .unwrap();
    Address::p2sh(g_script.as_script(), Network::Bitcoin)
}
/*
 * returns script buffer for the p2sh
 */
pub fn gateway_address(
    g_hash: &PushBytes,
    g_pubkey_hash: &PushBytes,
) -> Result<ScriptBuf, &'static str> {
    let test_script: ScriptBuf = Builder::new()
        .push_slice(g_hash)
        .push_opcode(all::OP_DROP)
        .push_opcode(all::OP_DUP)
        .push_opcode(all::OP_HASH160)
        .push_slice(g_pubkey_hash)
        .push_opcode(all::OP_EQUALVERIFY)
        .push_opcode(all::OP_CHECKMULTISIG)
        .into_script()
        .to_p2sh();

    match test_script.is_p2sh() {
        true => Ok(test_script),
        false => Err("failed to create p2sh"),
    }
}

#[derive(Deserialize, Serialize, Debug)]
struct DepositTransaction {
    hash: String,
    selector: String,
    version: i8,
    v: TransactionData,
}

#[derive(Deserialize, Serialize, Debug)]
struct TransactionData {
    amount: i32,
    ghash: String,
    gpubkey: String,
    nhash: String,
    nonce: String,
    payload: String,
    phash: String,
    to: String,
    txid: String,
    txindex: String,
}

impl ToRpcParams for DepositTransaction {
    fn to_rpc_params(
        self,
    ) -> Result<Option<Box<jsonrpsee::core::JsonRawValue>>, jsonrpsee::core::Error> {
        let s = String::from_utf8(serde_json::to_vec(&self)?).expect("Valid UTF8 format");
        RawValue::from_string(s)
            .map(Some)
            .map_err(jsonrpsee::core::error::Error::ParseError)
    }
}

#[tokio::main]
async fn main() {
    let mut module = RpcModule::new(());
    module
        .register_method("test_rpc", |params, _| {
            let tx = params.parse::<DepositTransaction>().unwrap();
            let address: Address = to_address(tx.v.ghash, tx.v.gpubkey).unwrap();
            println!("{}", address);
            Ok(())
        })
        .unwrap();

    let param_data = DepositTransaction {
        hash: "testhash".to_string(),
        selector: "testselector".to_string(),
        version: 1,
        v: TransactionData {
            amount: 8,
            ghash: "testghash".to_string(),
            gpubkey: "testgpubkey".to_string(),
            nhash: "testnhash".to_string(),
            nonce: "testnonce".to_string(),
            payload: "testpayload".to_string(),
            phash: "testphash".to_string(),
            to: "testto".to_string(),
            txid: "testtxid".to_string(),
            txindex: "testtxindex".to_string(),
        },
    };

    let _: () = module.call("test_rpc", param_data).await.unwrap();
}
