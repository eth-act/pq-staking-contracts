// In-browser EVM running the released contract bytecode (contracts/dist/bytecode.json).
import { createEVM, type EVM } from '@ethereumjs/evm'
import { Common, Hardfork, Mainnet } from '@ethereumjs/common'
import {
  type Address,
  bytesToBigInt,
  createAccount,
  createAddressFromBigInt,
  createAddressFromString,
} from '@ethereumjs/util'
import { type Hex, bytesToHex, concat, hexToBytes, numberToHex } from 'viem'
import bytecode from '../generated/bytecode.json'

export const SYSTEM_ADDRESS: Hex = '0xfffffffffffffffffffffffffffffffffffffffe'

export const SYSTEM_CONTRACTS = [
  'PQValidatorRegistration',
  'PQBuilderRegistration',
  'PQWithdrawal',
  'PQConsolidation',
] as const
export type SystemContract = (typeof SYSTEM_CONTRACTS)[number]
export type ContractName = 'PQStaking' | SystemContract

export const contracts = bytecode.contracts
export const compiler = bytecode.compiler

export interface Log {
  topics: Hex[]
  data: Hex
}

export interface CallResult {
  ok: boolean
  returnValue: Hex
  logs: Log[]
  gasUsed: bigint
}

/** EIP-7002 storage slots 0-3 of a system contract. */
export interface QueueState {
  excess: bigint
  count: bigint
  head: bigint
  tail: bigint
}

const EXCESS_INHIBITOR = 2n ** 256n - 1n

export class Chain {
  private constructor(
    private readonly evm: EVM,
    readonly addresses: Record<ContractName, Hex>,
  ) {}

  /** Value of the CHAINID opcode in this EVM; signed into registration proofs. */
  get chainId(): bigint {
    return this.evm.common.chainId()
  }

  /** Fund `accounts`, then deploy every contract from its creation bytecode. */
  static async create(
    migratedValidatorCount: bigint,
    accounts: { address: Hex; balanceWei: bigint }[],
  ): Promise<Chain> {
    const evm = await createEVM({ common: new Common({ chain: Mainnet, hardfork: Hardfork.Prague }) })
    for (const { address, balanceWei } of accounts) {
      await evm.stateManager.putAccount(createAddressFromString(address), createAccount({ balance: balanceWei }))
    }

    const names: ContractName[] = ['PQStaking', ...SYSTEM_CONTRACTS]
    const addresses = {} as Record<ContractName, Hex>
    for (const [i, name] of names.entries()) {
      // One deployer per contract keeps CREATE addresses distinct without nonce bookkeeping.
      const deployer = createAddressFromBigInt(0xde9100n + BigInt(i))
      await evm.stateManager.putAccount(deployer, createAccount({}))
      const initcode =
        name === 'PQStaking'
          ? concat([contracts[name].bytecode as Hex, numberToHex(migratedValidatorCount, { size: 32 })])
          : (contracts[name].bytecode as Hex)
      const result = await evm.runCall({ caller: deployer, data: hexToBytes(initcode), gasLimit: 30_000_000n })
      if (result.execResult.exceptionError || !result.createdAddress) {
        throw new Error(`deploying ${name} failed: ${result.execResult.exceptionError?.error}`)
      }
      addresses[name] = result.createdAddress.toString() as Hex
    }
    return new Chain(evm, addresses)
  }

  async call(from: Hex, to: Hex, data: Hex, value = 0n): Promise<CallResult> {
    const result = await this.evm.runCall({
      caller: createAddressFromString(from),
      to: createAddressFromString(to),
      data: hexToBytes(data),
      value,
      gasLimit: 30_000_000n,
    })
    const exec = result.execResult
    return {
      ok: exec.exceptionError === undefined,
      returnValue: bytesToHex(exec.returnValue),
      logs: (exec.logs ?? []).map(([, topics, logData]) => ({
        topics: topics.map((t) => bytesToHex(t)),
        data: bytesToHex(logData),
      })),
      gasUsed: exec.executionGasUsed,
    }
  }

  /** End-of-block system call. A failure would invalidate the block, so it throws. */
  async systemCall(name: SystemContract): Promise<Hex> {
    const result = await this.call(SYSTEM_ADDRESS, this.addresses[name], '0x')
    if (!result.ok) throw new Error(`system call to ${name} failed`)
    return result.returnValue
  }

  /** Fee getter (empty calldata, any non-system caller); `undefined` while inhibited. */
  async fee(name: SystemContract): Promise<bigint | undefined> {
    const result = await this.call('0x0000000000000000000000000000000000000000', this.addresses[name], '0x')
    return result.ok ? BigInt(result.returnValue) : undefined
  }

  async queueState(name: SystemContract): Promise<QueueState & { inhibited: boolean }> {
    const address = createAddressFromString(this.addresses[name])
    const [excess, count, head, tail] = await Promise.all(
      [0, 1, 2, 3].map(async (slot) =>
        bytesToBigInt(await this.evm.stateManager.getStorage(address, hexToBytes(numberToHex(slot, { size: 32 })))),
      ),
    )
    return { excess, count, head, tail, inhibited: excess === EXCESS_INHIBITOR }
  }

  async balance(address: Hex): Promise<bigint> {
    return (await this.evm.stateManager.getAccount(createAddressFromString(address)))?.balance ?? 0n
  }

  /** Consensus-layer withdrawals credit execution-layer balances directly (EIP-4895). */
  async credit(address: Hex, wei: bigint): Promise<void> {
    const addr: Address = createAddressFromString(address)
    const account = (await this.evm.stateManager.getAccount(addr)) ?? createAccount({})
    account.balance += wei
    await this.evm.stateManager.putAccount(addr, account)
  }
}
