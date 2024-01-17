#![feature(async_closure, async_fn_in_trait)]

mod error;
mod global;
mod types;
mod web_client;

use std::convert::TryInto;

use crate::error::Error;
use crate::global::Global;
use crate::types::*;
use bitcoin::Network;
use js_sys::{Array, Uint8Array};
use nomic::app::{Dest, IbcDest, InnerApp, Nom};
use nomic::bitcoin::Nbtc;
use nomic::constants::MAIN_NATIVE_TOKEN_DENOM;
use nomic::orga::client::wallet::Unsigned;
use nomic::orga::client::AppClient;
use nomic::orga::coins::Address;
use nomic::orga::coins::Symbol;
use nomic::orga::encoding::{Adapter, Encode};
use nomic::orga::plugins::sdk_compat::sdk;
use nomic::orga::plugins::MIN_FEE;
use nomic::orga::Error as OrgaError;
use wasm_bindgen::prelude::{wasm_bindgen, JsError, JsValue};
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_client::WebClient;
use web_sys::{Request, RequestInit, RequestMode, Response};

const ONE_DAY_MS: u64 = 86_400_000;

#[wasm_bindgen(start)]
pub fn main_js() -> std::result::Result<(), JsValue> {
    console_error_panic_hook::set_once();
    Ok(())
}

#[wasm_bindgen]
#[derive(Copy, Clone, Debug)]
pub enum NetWorkEnum {
    /// Classic Bitcoin
    Bitcoin = "bitcoin",
    /// Bitcoin's testnet
    Testnet = "testnet",
    /// Bitcoin's signet
    Signet = "signet",
    /// Bitcoin's regtest
    Regtest = "regtest",
}

#[allow(non_snake_case)]
#[wasm_bindgen]
pub struct OraiBtc {
    client: AppClient<InnerApp, InnerApp, WebClient, Nom, Unsigned>,
    chain_id: String,
    network: Network,
}

#[wasm_bindgen]
impl OraiBtc {
    #[wasm_bindgen(constructor)]
    pub fn new(url: &str, chain_id: &str, bitcoin_network: NetWorkEnum) -> Self {
        Self {
            client: AppClient::new(WebClient::new(url.to_string()), Unsigned),
            chain_id: chain_id.to_string(),
            network: match bitcoin_network {
                NetWorkEnum::Bitcoin => Network::Bitcoin,
                NetWorkEnum::Signet => Network::Signet,
                NetWorkEnum::Regtest => Network::Regtest,
                _ => Network::Testnet,
            },
        }
    }

    pub async fn balance(&self, addr: String) -> Result<u64, JsError> {
        let address = addr.parse().map_err(|e| Error::Wasm(format!("{:?}", e)))?;

        Ok(self
            .client
            .query(|app: InnerApp| app.accounts.balance(address))
            .await?
            .into())
    }

    #[allow(non_snake_case)]
    #[wasm_bindgen(js_name=nomRewardBalance)]
    pub async fn nom_reward_balance(&self, addr: String) -> Result<u64, JsError> {
        let address = addr.parse().map_err(|e| Error::Wasm(format!("{:?}", e)))?;

        let delegations = self
            .client
            .query(|app: InnerApp| app.staking.delegations(address))
            .await?;

        Ok(delegations
            .iter()
            .map(|(_, d)| -> u64 {
                d.liquid
                    .iter()
                    .find(|(denom, _)| *denom == Nom::INDEX)
                    .unwrap_or(&(0, 0.into()))
                    .1
                    .into()
            })
            .sum::<u64>())
    }

    #[allow(non_snake_case)]
    #[wasm_bindgen(js_name=nbtcRewardBalance)]
    pub async fn nbtc_reward_balance(&self, addr: String) -> Result<u64, JsError> {
        let address = addr.parse().map_err(|e| Error::Wasm(format!("{:?}", e)))?;

        let delegations = self
            .client
            .query(|app: InnerApp| app.staking.delegations(address))
            .await?;

        Ok(delegations
            .iter()
            .map(|(_, d)| -> u64 {
                d.liquid
                    .iter()
                    .find(|(denom, _)| *denom == Nbtc::INDEX)
                    .unwrap_or(&(0, 0.into()))
                    .1
                    .into()
            })
            .sum::<u64>())
    }

    pub async fn delegations(&self, addr: String) -> Result<Array, JsError> {
        let address = addr.parse().map_err(|e| Error::Wasm(format!("{:?}", e)))?;

        let delegations = self
            .client
            .query(|app: InnerApp| app.staking.delegations(address))
            .await?;
        Ok(delegations
            .iter()
            .map(|(address, delegation)| Delegation {
                address: address.to_string(),
                staked: delegation.staked.into(),
                liquid: delegation
                    .liquid
                    .iter()
                    .map(|(denom, amount)| {
                        Coin {
                            denom: *denom,
                            amount: (*amount).into(),
                        }
                        .into()
                    })
                    .collect(),
                unbonding: delegation
                    .unbonding
                    .iter()
                    .map(|u| UnbondInfo {
                        start_seconds: u.start_seconds as u64,
                        amount: u.amount.into(),
                    })
                    .map(JsValue::from)
                    .collect(),
            })
            .map(JsValue::from)
            .collect())
    }

    #[allow(non_snake_case)]
    #[wasm_bindgen(js_name=allValidators)]
    pub async fn validators(&self) -> Result<Array, JsError> {
        let validators = self
            .client
            .query(|app: InnerApp| app.staking.validators())
            .await?;
        Ok(validators
            .iter()
            .map(|v| {
                let info_bytes: Vec<u8> = v.info.clone().into();

                ValidatorQueryInfo {
                    jailed: v.jailed,
                    address: v.address.to_string(),
                    commission: v.commission.rate.to_string(),
                    in_active_set: v.in_active_set,
                    info: String::from_utf8(info_bytes).unwrap_or_default(),
                    amount_staked: v.amount_staked.into(),
                }
            })
            .map(JsValue::from)
            .collect())
    }

    pub async fn claim(&self, address: String) -> Result<String, JsError> {
        let address = address
            .parse()
            .map_err(|e| Error::Wasm(format!("{:?}", e)))?;
        self.gen_call_bytes(
            address,
            sdk::Msg {
                type_: "nomic/MsgClaimRewards".to_string(),
                value: serde_json::Map::new().into(),
            },
        )
        .await
    }

    #[allow(non_snake_case)]
    #[wasm_bindgen(js_name=claimIncomingIbcBtc)]
    pub async fn claim_incoming_ibc_btc(&self, address: String) -> Result<String, JsError> {
        let address = address
            .parse()
            .map_err(|e| Error::Wasm(format!("{:?}", e)))?;
        self.gen_call_bytes(
            address,
            sdk::Msg {
                type_: "nomic/MsgClaimIbcBitcoin".to_string(),
                value: serde_json::Map::new().into(),
            },
        )
        .await
    }

    #[allow(non_snake_case)]
    #[wasm_bindgen(js_name=setRecoveryAddress)]
    pub async fn set_recovery_address(
        &self,
        address: String,
        recovery_address: String,
    ) -> Result<String, JsError> {
        let mut value = serde_json::Map::new();
        value.insert("recovery_address".to_string(), recovery_address.into());

        self.gen_call_bytes(
            address,
            sdk::Msg {
                type_: "nomic/MsgSetRecoveryAddress".to_string(),
                value: value.into(),
            },
        )
        .await
    }

    #[allow(non_snake_case)]
    #[wasm_bindgen(js_name=getRecoveryAddress)]
    pub async fn get_recovery_address(&self, address: String) -> Result<String, JsError> {
        let address = address
            .parse()
            .map_err(|e| Error::Wasm(format!("{:?}", e)))?;
        Ok(self
            .client
            .query(|app: InnerApp| {
                Ok(match app.bitcoin.recovery_scripts.get(address)? {
                    Some(script) => bitcoin::Address::from_script(&script, self.network)
                        .map_err(|e| OrgaError::App(format!("{:?}", e)))?
                        .to_string(),
                    None => "".to_string(),
                })
            })
            .await?)
    }

    //bytes
    pub async fn transfer(
        &self,
        from_addr: String,
        to_addr: String,
        amount: u64,
    ) -> Result<String, JsError> {
        let mut amount_obj = serde_json::Map::new();
        amount_obj.insert("amount".to_string(), amount.to_string().into());
        amount_obj.insert("denom".to_string(), MAIN_NATIVE_TOKEN_DENOM.into());

        let mut value = serde_json::Map::new();
        value.insert("from_address".to_string(), from_addr.clone().into());
        value.insert("to_address".to_string(), to_addr.into());
        value.insert(
            "amount".to_string(),
            serde_json::Value::Array(vec![amount_obj.into()]),
        );

        self.gen_call_bytes(
            from_addr,
            sdk::Msg {
                type_: "cosmos-sdk/MsgSend".to_string(),
                value: value.into(),
            },
        )
        .await
    }

    //bytes
    pub async fn delegate(
        &self,
        from_addr: String,
        to_addr: String,
        amount: u64,
    ) -> Result<String, JsError> {
        let mut amount_obj = serde_json::Map::new();
        amount_obj.insert("amount".to_string(), amount.to_string().into());
        amount_obj.insert("denom".to_string(), MAIN_NATIVE_TOKEN_DENOM.into());

        let mut value = serde_json::Map::new();
        value.insert("delegator_address".to_string(), from_addr.clone().into());
        value.insert("validator_address".to_string(), to_addr.into());
        value.insert("amount".to_string(), amount_obj.into());

        self.gen_call_bytes(
            from_addr,
            sdk::Msg {
                type_: "cosmos-sdk/MsgDelegate".to_string(),
                value: value.into(),
            },
        )
        .await
    }

    pub async fn unbond(
        &self,
        address: String,
        val_addr: String,
        amount: u64,
    ) -> Result<String, JsError> {
        let mut amount_obj = serde_json::Map::new();
        amount_obj.insert("amount".to_string(), amount.to_string().into());
        amount_obj.insert("denom".to_string(), MAIN_NATIVE_TOKEN_DENOM.into());

        let mut value = serde_json::Map::new();
        value.insert("delegator_address".to_string(), address.clone().into());
        value.insert("validator_address".to_string(), val_addr.into());
        value.insert("amount".to_string(), amount_obj.into());

        let address = address
            .parse()
            .map_err(|e| Error::Wasm(format!("{:?}", e)))?;
        self.gen_call_bytes(
            address,
            sdk::Msg {
                type_: "cosmos-sdk/MsgUndelegate".to_string(),
                value: value.into(),
            },
        )
        .await
    }

    pub async fn redelegate(
        &self,
        address: String,
        src_addr: String,
        dst_addr: String,
        amount: u64,
    ) -> Result<String, JsError> {
        let mut amount_obj = serde_json::Map::new();
        amount_obj.insert("amount".to_string(), amount.to_string().into());
        amount_obj.insert("denom".to_string(), MAIN_NATIVE_TOKEN_DENOM.into());

        let mut value = serde_json::Map::new();
        value.insert("delegator_address".to_string(), address.clone().into());
        value.insert("validator_src_address".to_string(), src_addr.into());
        value.insert("validator_dst_address".to_string(), dst_addr.into());
        value.insert("amount".to_string(), amount_obj.into());

        let address = address
            .parse()
            .map_err(|e| Error::Wasm(format!("{:?}", e)))?;
        self.gen_call_bytes(
            address,
            sdk::Msg {
                type_: "cosmos-sdk/MsgBeginRedelegate".to_string(),
                value: value.into(),
            },
        )
        .await
    }

    pub async fn nonce(&self, addr: String) -> Result<u64, JsError> {
        let address = addr.parse().map_err(|e| Error::Wasm(format!("{:?}", e)))?;
        let nonce = self
            .client
            .query_root(|app| app.inner.inner.borrow().inner.inner.inner.nonce(address))
            .await?;
        Ok(nonce)
    }

    #[allow(non_snake_case)]
    #[wasm_bindgen(js_name=generateDepositAddress)]
    pub async fn gen_deposit_addr(
        &self,
        receiver: String,
        channel: Option<String>,
        sender: Option<String>,
        memo: Option<String>,
        timeoutSeconds: Option<u32>,
    ) -> Result<DepositAddress, JsError> {
        let (sigset, threshold) = self
            .client
            .query(|app: InnerApp| {
                Ok((
                    app.bitcoin.checkpoints.active_sigset()?,
                    app.bitcoin.checkpoints.config.sigset_threshold,
                ))
            })
            .await?;

        let dest = if let Some(channel) = channel {
            let mut timeout_timestamp_ms = js_sys::Date::now() as u64;
            if let Some(timeout) = timeoutSeconds {
                timeout_timestamp_ms += (timeout as u64) * 1_000;
            } else {
                timeout_timestamp_ms += ONE_DAY_MS * 5 - timeout_timestamp_ms % 3_600_000;
            }

            let timeout_timestamp = timeout_timestamp_ms * 1_000_000;

            let memo = memo.unwrap_or_default();
            if memo.len() > 255 {
                return Err(JsError::new("Memo must be less than 256 characters"));
            }

            let sender = sender.unwrap_or_default();

            Dest::Ibc(IbcDest {
                source_port: "transfer".to_string().try_into()?,
                source_channel: channel.try_into()?,
                sender: Adapter(sender.into()),
                receiver: Adapter(receiver.into()),
                timeout_timestamp,
                memo: memo.try_into()?,
            })
        } else {
            Dest::Address(
                receiver
                    .parse()
                    .map_err(|e| Error::Wasm(format!("{:?}", e)))?,
            )
        };

        let script = sigset.output_script(dest.commitment_bytes()?.as_slice(), threshold)?;

        let btc_addr = bitcoin::Address::from_script(&script, self.network)?;

        Ok(DepositAddress {
            address: btc_addr.to_string(),
            sigset_index: sigset.index(),
            expiration: sigset.deposit_timeout() * 1000,
        })
    }

    #[allow(non_snake_case)]
    #[wasm_bindgen(js_name=nbtcBalance)]
    pub async fn nbtc_balance(&self, addr: String) -> Result<u64, JsError> {
        let addr = addr.parse().map_err(|e| Error::Wasm(format!("{:?}", e)))?;
        let balance = self
            .client
            .query(|app: InnerApp| app.bitcoin.accounts.balance(addr))
            .await?
            .into();

        Ok(balance)
    }

    #[allow(non_snake_case)]
    #[wasm_bindgen(js_name=incomingIbcNbtcBalance)]
    pub async fn incoming_ibc_nbtc_balance(&self, addr: String) -> Result<u64, JsError> {
        let address: Address = addr.parse().map_err(|e| Error::Wasm(format!("{:?}", e)))?;

        let balance = self
            .client
            .query(|app: InnerApp| app.escrowed_nbtc(address))
            .await?;
        Ok(balance.into())
    }

    #[allow(non_snake_case)]
    #[wasm_bindgen(js_name=valueLocked)]
    pub async fn value_locked(&self) -> Result<u64, JsError> {
        Ok(self
            .client
            .query(|app: InnerApp| Ok(app.bitcoin.value_locked()?))
            .await?)
    }

    #[allow(non_snake_case)]
    #[wasm_bindgen(js_name=latestCheckpointHash)]
    pub async fn latest_checkpoint_hash(&self) -> Result<String, JsError> {
        let last_checkpoint_id = self
            .client
            .query(|app: InnerApp| Ok(app.bitcoin.checkpoints.last_completed_tx()?.txid()))
            .await?;

        Ok(last_checkpoint_id.to_string())
    }

    #[allow(non_snake_case)]
    #[wasm_bindgen(js_name=bitcoinHeight)]
    pub async fn bitcoin_height(&self) -> Result<u32, JsError> {
        Ok(self
            .client
            .query(|app: InnerApp| Ok(app.bitcoin.headers.height()?))
            .await?)
    }

    #[allow(non_snake_case)]
    #[wasm_bindgen(js_name=capacityLimit)]
    pub async fn capacity_limit(&self) -> Result<u64, JsError> {
        Ok(self
            .client
            .query(|app: InnerApp| Ok(app.bitcoin.config.capacity_limit))
            .await?)
    }

    #[allow(non_snake_case)]
    #[wasm_bindgen(js_name=depositsEnabled)]
    pub async fn deposits_enabled(&self) -> Result<bool, JsError> {
        Ok(self
            .client
            .query(|app: InnerApp| Ok(!app.bitcoin.checkpoints.last_completed()?.deposits_enabled))
            .await?)
    }

    #[allow(non_snake_case)]
    #[wasm_bindgen(js_name=broadcastDepositAddress)]
    pub async fn broadcast_deposit_addr(
        &self,
        dest_addr: String,
        sigset_index: u32,
        relayers: js_sys::Array,
        deposit_addr: String,
    ) -> Result<String, JsError> {
        let dest_addr = dest_addr
            .parse()
            .map_err(|e| Error::Wasm(format!("{:?}", e)))?;

        let commitment = Dest::Address(dest_addr);

        let global = match js_sys::global().dyn_into::<Global>() {
            Ok(global) => global,
            Err(_) => return Err(Error::Wasm("Object class not found".to_string()).into()),
        };
        let mut results = vec![];
        for relayer in relayers.iter() {
            let relayer = match relayer.as_string() {
                Some(relayer) => relayer,
                None => return Err(Error::Wasm("Relayer not found".to_string()).into()),
            };

            let mut opts = RequestInit::new();
            opts.method("POST");
            opts.mode(RequestMode::Cors);
            opts.body(Some(
                &(Uint8Array::from(Encode::encode(&commitment)?.as_slice())).into(),
            ));
            let url = format!(
                "{}/address?sigset_index={}&deposit_addr={}",
                relayer, sigset_index, deposit_addr
            );

            let request = Request::new_with_str_and_init(&url, &opts)
                .map_err(|e| Error::Wasm(format!("{:?}", e)))?;

            let resp_value = JsFuture::from(global.js_fetch(&request))
                .await
                .map_err(|e| Error::Wasm(format!("{:?}", e)))?;

            let res: Response = resp_value
                .dyn_into()
                .map_err(|e| Error::Wasm(format!("{:?}", e)))?;

            let status = res.status();
            if status != 200 {
                return Err(Error::Relayer(format!(
                    "Relayer response returned with error code: {}",
                    status
                ))
                .into());
            }
            let res_buf = res
                .array_buffer()
                .map_err(|e| Error::Wasm(format!("{:?}", e)))?;
            let res = JsFuture::from(res_buf)
                .await
                .map_err(|e| Error::Wasm(format!("{:?}", e)))?;
            let res = js_sys::Uint8Array::new(&res).to_vec();
            results.push(String::from_utf8(res)?);
        }
        Ok(results.join("\n"))
    }

    pub async fn withdraw(
        &self,
        address: String,
        dest_addr: String,
        amount: u64,
    ) -> Result<String, JsError> {
        let mut value = serde_json::Map::new();
        value.insert("amount".to_string(), amount.to_string().into());
        value.insert("dst_address".to_string(), dest_addr.into());

        let address = address
            .parse()
            .map_err(|e| Error::Wasm(format!("{:?}", e)))?;
        self.gen_call_bytes(
            address,
            sdk::Msg {
                type_: "nomic/MsgWithdraw".to_string(),
                value: value.into(),
            },
        )
        .await
    }

    #[allow(non_snake_case)]
    #[wasm_bindgen(js_name=joinRewardAccounts)]
    pub async fn join_reward_accounts(
        &self,
        source_address: String,
        destination_address: String,
    ) -> Result<String, JsError> {
        let address: Address = source_address
            .parse()
            .map_err(|_| Error::Wasm("Invalid source address".to_string()))?;
        let dest_addr: Address = destination_address
            .parse()
            .map_err(|_| Error::Wasm("Invalid destination address".to_string()))?;

        let mut value = serde_json::Map::new();
        value.insert("dest_address".to_string(), dest_addr.to_string().into());

        self.gen_call_bytes(
            address.to_string(),
            sdk::Msg {
                type_: "nomic/MsgJoinRewardAccounts".to_string(),
                value: value.into(),
            },
        )
        .await
    }

    #[allow(non_snake_case)]
    #[wasm_bindgen(js_name=ibcTransferOut)]
    pub async fn ibc_transfer_out(
        &self,
        amount: u64,
        channel_id: String,
        port_id: String,
        denom: String,
        self_address: String,
        receiver_address: String,
        timeout_timestamp: String,
    ) -> Result<String, JsError> {
        let mut value = serde_json::Map::new();
        value.insert("amount".to_string(), amount.into());
        value.insert("denom".to_string(), denom.into());
        value.insert("channel_id".to_string(), channel_id.into());
        value.insert("port_id".to_string(), port_id.into());
        value.insert("receiver".to_string(), receiver_address.into());
        value.insert("sender".to_string(), self_address.clone().into());
        value.insert("timeout_timestamp".to_string(), timeout_timestamp.into());

        let address = self_address
            .parse()
            .map_err(|e| Error::Wasm(format!("{:?}", e)))?;
        self.gen_call_bytes(
            address,
            sdk::Msg {
                type_: "nomic/MsgIbcTransferOut".to_string(),
                value: value.into(),
            },
        )
        .await
    }

    #[allow(non_snake_case)]
    #[wasm_bindgen(js_name=convertEthAddress)]
    pub fn convert_eth_address(&self, str: String) -> Result<String, JsError> {
        if !str.starts_with("0x") {
            return Err(JsError::new("Address must start with 0x"));
        }
        if str.len() != 42 {
            return Err(JsError::new("Address must be 20 bytes"));
        }

        let bytes =
            hex::decode(&str[2..]).map_err(|_| Error::Wasm("Invalid address".to_string()))?;
        let mut arr = [0; Address::LENGTH];
        arr.copy_from_slice(&bytes[..]);
        let addr: Address = arr.into();

        Ok(addr.to_string())
    }

    async fn gen_call_bytes(&self, address: String, msg: sdk::Msg) -> Result<String, JsError> {
        let address = address
            .parse()
            .map_err(|e| Error::Wasm(format!("{:?}", e)))?;

        let nonce = self
            .client
            .query_root(|app| app.inner.inner.borrow().inner.inner.inner.nonce(address))
            .await?;

        let sign_doc = sdk::SignDoc {
            account_number: "0".to_string(),
            chain_id: self.chain_id.to_string(),
            //does this fee have to be a vec
            fee: sdk::Fee {
                amount: vec![sdk::Coin {
                    amount: "0".to_string(),
                    denom: MAIN_NATIVE_TOKEN_DENOM.to_string(),
                }],
                gas: MIN_FEE.to_string(),
            },
            memo: "".to_string(),
            //do these messages have to be a vec
            //might be utility in multiple messages
            msgs: vec![msg],
            sequence: (nonce + 1).to_string(),
        };

        Ok(serde_json::to_string(&sign_doc)?)
    }

    // pub async fn describe(&self) -> nomic::orga::describe::Descriptor {
    //     use nomic::orga::describe::Describe;
    //     nomic::app::App::describe()
    // }
}

#[cfg(test)]
mod tests;
