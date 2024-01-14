/* tslint:disable */
/* eslint-disable */
/**
*/
export function main_js(): void;
/**
*/
export class Coin {
  free(): void;
/**
*/
  amount: bigint;
/**
*/
  denom: number;
}
/**
*/
export class Delegation {
  free(): void;
/**
*/
  address: string;
/**
*/
  liquid: any[];
/**
*/
  staked: bigint;
/**
*/
  unbonding: any[];
}
/**
*/
export class DepositAddress {
  free(): void;
/**
*/
  address: string;
/**
*/
  expiration: bigint;
/**
*/
  sigsetIndex: number;
}
/**
*/
export class JsIter {
  free(): void;
/**
* @returns {JsIterNext}
*/
  next(): JsIterNext;
}
/**
*/
export class JsIterNext {
  free(): void;
/**
*/
  done: boolean;
/**
*/
  readonly value: any;
}
/**
*/
export class OraiBtc {
  free(): void;
/**
* @param {string} url
* @param {string} chain_id
* @param {any} bitcoin_network
*/
  constructor(url: string, chain_id: string, bitcoin_network: any);
/**
* @param {string} addr
* @returns {Promise<bigint>}
*/
  balance(addr: string): Promise<bigint>;
/**
* @param {string} addr
* @returns {Promise<bigint>}
*/
  nomRewardBalance(addr: string): Promise<bigint>;
/**
* @param {string} addr
* @returns {Promise<bigint>}
*/
  nbtcRewardBalance(addr: string): Promise<bigint>;
/**
* @param {string} addr
* @returns {Promise<Array<any>>}
*/
  delegations(addr: string): Promise<Array<any>>;
/**
* @returns {Promise<Array<any>>}
*/
  allValidators(): Promise<Array<any>>;
/**
* @param {string} address
* @returns {Promise<string>}
*/
  claim(address: string): Promise<string>;
/**
* @param {string} address
* @returns {Promise<string>}
*/
  claimIncomingIbcBtc(address: string): Promise<string>;
/**
* @param {string} address
* @param {string} recovery_address
* @returns {Promise<string>}
*/
  setRecoveryAddress(address: string, recovery_address: string): Promise<string>;
/**
* @param {string} address
* @returns {Promise<string>}
*/
  getRecoveryAddress(address: string): Promise<string>;
/**
* @param {string} from_addr
* @param {string} to_addr
* @param {bigint} amount
* @returns {Promise<string>}
*/
  transfer(from_addr: string, to_addr: string, amount: bigint): Promise<string>;
/**
* @param {string} from_addr
* @param {string} to_addr
* @param {bigint} amount
* @returns {Promise<string>}
*/
  delegate(from_addr: string, to_addr: string, amount: bigint): Promise<string>;
/**
* @param {string} address
* @param {string} val_addr
* @param {bigint} amount
* @returns {Promise<string>}
*/
  unbond(address: string, val_addr: string, amount: bigint): Promise<string>;
/**
* @param {string} address
* @param {string} src_addr
* @param {string} dst_addr
* @param {bigint} amount
* @returns {Promise<string>}
*/
  redelegate(address: string, src_addr: string, dst_addr: string, amount: bigint): Promise<string>;
/**
* @param {string} addr
* @returns {Promise<bigint>}
*/
  nonce(addr: string): Promise<bigint>;
/**
* @param {string} receiver
* @param {string | undefined} [channel]
* @param {string | undefined} [sender]
* @param {string | undefined} [memo]
* @param {number | undefined} [timeoutSeconds]
* @returns {Promise<DepositAddress>}
*/
  generateDepositAddress(receiver: string, channel?: string, sender?: string, memo?: string, timeoutSeconds?: number): Promise<DepositAddress>;
/**
* @param {string} addr
* @returns {Promise<bigint>}
*/
  nbtcBalance(addr: string): Promise<bigint>;
/**
* @param {string} addr
* @returns {Promise<bigint>}
*/
  incomingIbcNbtcBalance(addr: string): Promise<bigint>;
/**
* @returns {Promise<bigint>}
*/
  valueLocked(): Promise<bigint>;
/**
* @returns {Promise<string>}
*/
  latestCheckpointHash(): Promise<string>;
/**
* @returns {Promise<number>}
*/
  bitcoinHeight(): Promise<number>;
/**
* @returns {Promise<bigint>}
*/
  capacityLimit(): Promise<bigint>;
/**
* @returns {Promise<boolean>}
*/
  depositsEnabled(): Promise<boolean>;
/**
* @param {string} dest_addr
* @param {number} sigset_index
* @param {Array<any>} relayers
* @param {string} deposit_addr
* @returns {Promise<string>}
*/
  broadcastDepositAddress(dest_addr: string, sigset_index: number, relayers: Array<any>, deposit_addr: string): Promise<string>;
/**
* @param {string} address
* @param {string} dest_addr
* @param {bigint} amount
* @returns {Promise<string>}
*/
  withdraw(address: string, dest_addr: string, amount: bigint): Promise<string>;
/**
* @param {string} source_address
* @param {string} destination_address
* @returns {Promise<string>}
*/
  joinRewardAccounts(source_address: string, destination_address: string): Promise<string>;
/**
* @param {bigint} amount
* @param {string} channel_id
* @param {string} port_id
* @param {string} denom
* @param {string} self_address
* @param {string} receiver_address
* @param {string} timeout_timestamp
* @returns {Promise<string>}
*/
  ibcTransferOut(amount: bigint, channel_id: string, port_id: string, denom: string, self_address: string, receiver_address: string, timeout_timestamp: string): Promise<string>;
/**
* @param {string} str
* @returns {string}
*/
  convertEthAddress(str: string): string;
}
/**
*/
export class RewardDetails {
  free(): void;
/**
*/
  amount: bigint;
/**
*/
  claimable: bigint;
/**
*/
  claimed: bigint;
/**
*/
  locked: bigint;
}
/**
*/
export class UnbondInfo {
  free(): void;
/**
*/
  amount: bigint;
/**
*/
  startSeconds: bigint;
}
/**
*/
export class ValidatorQueryInfo {
  free(): void;
/**
*/
  address: string;
/**
*/
  amountStaked: bigint;
/**
*/
  commission: string;
/**
*/
  inActiveSet: boolean;
/**
*/
  info: string;
/**
*/
  jailed: boolean;
}

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly main_js: () => void;
  readonly __wbg_oraibtc_free: (a: number) => void;
  readonly oraibtc_new: (a: number, b: number, c: number, d: number, e: number) => number;
  readonly oraibtc_balance: (a: number, b: number, c: number) => number;
  readonly oraibtc_nomRewardBalance: (a: number, b: number, c: number) => number;
  readonly oraibtc_nbtcRewardBalance: (a: number, b: number, c: number) => number;
  readonly oraibtc_delegations: (a: number, b: number, c: number) => number;
  readonly oraibtc_allValidators: (a: number) => number;
  readonly oraibtc_claim: (a: number, b: number, c: number) => number;
  readonly oraibtc_claimIncomingIbcBtc: (a: number, b: number, c: number) => number;
  readonly oraibtc_setRecoveryAddress: (a: number, b: number, c: number, d: number, e: number) => number;
  readonly oraibtc_getRecoveryAddress: (a: number, b: number, c: number) => number;
  readonly oraibtc_transfer: (a: number, b: number, c: number, d: number, e: number, f: number) => number;
  readonly oraibtc_delegate: (a: number, b: number, c: number, d: number, e: number, f: number) => number;
  readonly oraibtc_unbond: (a: number, b: number, c: number, d: number, e: number, f: number) => number;
  readonly oraibtc_redelegate: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => number;
  readonly oraibtc_nonce: (a: number, b: number, c: number) => number;
  readonly oraibtc_generateDepositAddress: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number) => number;
  readonly oraibtc_nbtcBalance: (a: number, b: number, c: number) => number;
  readonly oraibtc_incomingIbcNbtcBalance: (a: number, b: number, c: number) => number;
  readonly oraibtc_valueLocked: (a: number) => number;
  readonly oraibtc_latestCheckpointHash: (a: number) => number;
  readonly oraibtc_bitcoinHeight: (a: number) => number;
  readonly oraibtc_capacityLimit: (a: number) => number;
  readonly oraibtc_depositsEnabled: (a: number) => number;
  readonly oraibtc_broadcastDepositAddress: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => number;
  readonly oraibtc_withdraw: (a: number, b: number, c: number, d: number, e: number, f: number) => number;
  readonly oraibtc_joinRewardAccounts: (a: number, b: number, c: number, d: number, e: number) => number;
  readonly oraibtc_ibcTransferOut: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number, n: number) => number;
  readonly oraibtc_convertEthAddress: (a: number, b: number, c: number, d: number) => void;
  readonly __wbg_depositaddress_free: (a: number) => void;
  readonly __wbg_get_depositaddress_sigsetIndex: (a: number) => number;
  readonly __wbg_set_depositaddress_sigsetIndex: (a: number, b: number) => void;
  readonly __wbg_validatorqueryinfo_free: (a: number) => void;
  readonly __wbg_get_validatorqueryinfo_jailed: (a: number) => number;
  readonly __wbg_set_validatorqueryinfo_jailed: (a: number, b: number) => void;
  readonly __wbg_get_validatorqueryinfo_commission: (a: number, b: number) => void;
  readonly __wbg_set_validatorqueryinfo_commission: (a: number, b: number, c: number) => void;
  readonly __wbg_get_validatorqueryinfo_inActiveSet: (a: number) => number;
  readonly __wbg_set_validatorqueryinfo_inActiveSet: (a: number, b: number) => void;
  readonly __wbg_get_validatorqueryinfo_info: (a: number, b: number) => void;
  readonly __wbg_set_validatorqueryinfo_info: (a: number, b: number, c: number) => void;
  readonly __wbg_delegation_free: (a: number) => void;
  readonly __wbg_get_delegation_address: (a: number, b: number) => void;
  readonly __wbg_set_delegation_address: (a: number, b: number, c: number) => void;
  readonly __wbg_get_delegation_liquid: (a: number, b: number) => void;
  readonly __wbg_set_delegation_liquid: (a: number, b: number, c: number) => void;
  readonly __wbg_get_delegation_unbonding: (a: number, b: number) => void;
  readonly __wbg_set_delegation_unbonding: (a: number, b: number, c: number) => void;
  readonly __wbg_coin_free: (a: number) => void;
  readonly __wbg_get_coin_denom: (a: number) => number;
  readonly __wbg_set_coin_denom: (a: number, b: number) => void;
  readonly __wbg_get_coin_amount: (a: number) => number;
  readonly __wbg_set_coin_amount: (a: number, b: number) => void;
  readonly __wbg_rewarddetails_free: (a: number) => void;
  readonly __wbg_get_rewarddetails_claimed: (a: number) => number;
  readonly __wbg_set_rewarddetails_claimed: (a: number, b: number) => void;
  readonly __wbg_get_rewarddetails_claimable: (a: number) => number;
  readonly __wbg_set_rewarddetails_claimable: (a: number, b: number) => void;
  readonly __wbg_get_rewarddetails_amount: (a: number) => number;
  readonly __wbg_set_rewarddetails_amount: (a: number, b: number) => void;
  readonly __wbg_jsiter_free: (a: number) => void;
  readonly jsiter_next: (a: number, b: number) => void;
  readonly __wbg_jsiternext_free: (a: number) => void;
  readonly __wbg_get_jsiternext_done: (a: number) => number;
  readonly __wbg_set_jsiternext_done: (a: number, b: number) => void;
  readonly jsiternext_value: (a: number) => number;
  readonly rustsecp256k1_v0_8_1_context_create: (a: number) => number;
  readonly rustsecp256k1_v0_8_1_context_destroy: (a: number) => void;
  readonly rustsecp256k1_v0_8_1_default_illegal_callback_fn: (a: number, b: number) => void;
  readonly rustsecp256k1_v0_8_1_default_error_callback_fn: (a: number, b: number) => void;
  readonly rustsecp256k1_v0_6_1_context_create: (a: number) => number;
  readonly rustsecp256k1_v0_6_1_context_destroy: (a: number) => void;
  readonly rustsecp256k1_v0_6_1_default_illegal_callback_fn: (a: number, b: number) => void;
  readonly rustsecp256k1_v0_6_1_default_error_callback_fn: (a: number, b: number) => void;
  readonly __wbg_set_validatorqueryinfo_amountStaked: (a: number, b: number) => void;
  readonly __wbg_set_unbondinfo_startSeconds: (a: number, b: number) => void;
  readonly __wbg_set_depositaddress_expiration: (a: number, b: number) => void;
  readonly __wbg_set_delegation_staked: (a: number, b: number) => void;
  readonly __wbg_set_rewarddetails_locked: (a: number, b: number) => void;
  readonly __wbg_set_unbondinfo_amount: (a: number, b: number) => void;
  readonly __wbg_set_validatorqueryinfo_address: (a: number, b: number, c: number) => void;
  readonly __wbg_set_depositaddress_address: (a: number, b: number, c: number) => void;
  readonly __wbg_get_validatorqueryinfo_amountStaked: (a: number) => number;
  readonly __wbg_get_unbondinfo_startSeconds: (a: number) => number;
  readonly __wbg_get_depositaddress_expiration: (a: number) => number;
  readonly __wbg_get_delegation_staked: (a: number) => number;
  readonly __wbg_get_rewarddetails_locked: (a: number) => number;
  readonly __wbg_get_unbondinfo_amount: (a: number) => number;
  readonly __wbg_get_validatorqueryinfo_address: (a: number, b: number) => void;
  readonly __wbg_get_depositaddress_address: (a: number, b: number) => void;
  readonly __wbg_unbondinfo_free: (a: number) => void;
  readonly __wbindgen_malloc: (a: number, b: number) => number;
  readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
  readonly __wbindgen_export_2: WebAssembly.Table;
  readonly wasm_bindgen__convert__closures__invoke1_mut__h4312418dfb22006f: (a: number, b: number, c: number) => void;
  readonly __wbindgen_free: (a: number, b: number, c: number) => void;
  readonly __wbindgen_exn_store: (a: number) => void;
  readonly wasm_bindgen__convert__closures__invoke2_mut__h83aabe358be0c9e6: (a: number, b: number, c: number, d: number) => void;
  readonly __wbindgen_add_to_stack_pointer: (a: number) => number;
  readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;
/**
* Instantiates the given `module`, which can either be bytes or
* a precompiled `WebAssembly.Module`.
*
* @param {SyncInitInput} module
*
* @returns {InitOutput}
*/
export function initSync(module: SyncInitInput): InitOutput;

/**
* If `module_or_path` is {RequestInfo} or {URL}, makes a request and
* for everything else, calls `WebAssembly.instantiate` directly.
*
* @param {InitInput | Promise<InitInput>} module_or_path
*
* @returns {Promise<InitOutput>}
*/
export default function __wbg_init (module_or_path?: InitInput | Promise<InitInput>): Promise<InitOutput>;
