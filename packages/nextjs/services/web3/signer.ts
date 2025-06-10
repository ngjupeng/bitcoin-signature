import { FeeMarginPercentage, ZERO } from "./constant";
import {
  Abi,
  Account,
  AllowArray,
  BigNumberish,
  CairoCustomEnum,
  CairoOption,
  CairoOptionVariant,
  Call,
  CallData,
  Calldata,
  DeclareSignerDetails,
  DeployAccountContractPayload,
  DeployAccountSignerDetails,
  DeployContractResponse,
  FeeEstimate,
  InvocationsSignerDetails,
  InvokeFunctionResponse,
  RPC,
  Signature,
  SignerInterface,
  TransactionType,
  UniversalDetails,
  V2DeclareSignerDetails,
  V2DeployAccountSignerDetails,
  V2InvocationsSignerDetails,
  V3DeclareSignerDetails,
  V3DeployAccountSignerDetails,
  V3InvocationsSignerDetails,
  ec,
  encode,
  hash,
  num,
  shortString,
  stark,
  transaction,
  typedData,
} from "starknet";

export type ValuesType<
  T extends ReadonlyArray<any> | ArrayLike<any> | Record<any, any>,
> =
  T extends ReadonlyArray<any>
    ? T[number]
    : T extends ArrayLike<any>
      ? T[number]
      : T extends object
        ? T[keyof T]
        : never;

export const EDataAvailabilityMode = {
  L1: "L1",
  L2: "L2",
} as const;

export type EDataAvailabilityMode = ValuesType<typeof EDataAvailabilityMode>;

export const ETransactionVersion = {
  V0: "0x0",
  V1: "0x1",
  V2: "0x2",
  V3: "0x3",
  F0: "0x100000000000000000000000000000000",
  F1: "0x100000000000000000000000000000001",
  F2: "0x100000000000000000000000000000002",
  F3: "0x100000000000000000000000000000003",
} as const;

export type ETransactionVersion = ValuesType<typeof ETransactionVersion>;
export type u64 = string;
export type u128 = string;
export type RESOURCE_BOUNDS = {
  max_amount: u64;
  max_price_per_unit: u128;
};
export type RESOURCE_BOUNDS_MAPPING = {
  l1_gas: RESOURCE_BOUNDS;
  l2_gas: RESOURCE_BOUNDS;
};

export type ResourceBounds = RESOURCE_BOUNDS_MAPPING;

/**
 * This class allows to easily implement custom signers by overriding the `signRaw` method.
 * This is based on Starknet.js implementation of Signer, but it delegates the actual signing to an abstract function
 */
export abstract class RawSigner implements SignerInterface {
  abstract signRaw(messageHash: string): Promise<string[]>;

  public async getPubKey(): Promise<string> {
    throw new Error("This signer allows multiple public keys");
  }

  public async signMessage(
    typedDataArgument: typeof typedData.TypedData,
    accountAddress: string
  ): Promise<Signature> {
    const messageHash = typedData.getMessageHash(
      typedDataArgument,
      accountAddress
    );
    return this.signRaw(messageHash);
  }

  public async signTransaction(
    transactions: Call[],
    details: InvocationsSignerDetails
  ): Promise<Signature> {
    const compiledCalldata = transaction.getExecuteCalldata(
      transactions,
      details.cairoVersion
    );
    let msgHash;

    // TODO: How to do generic union discriminator for all like this
    if (
      Object.values(RPC.ETransactionVersion2).includes(details.version as any)
    ) {
      const det = details as V2InvocationsSignerDetails;
      msgHash = hash.calculateInvokeTransactionHash({
        ...det,
        senderAddress: det.walletAddress,
        compiledCalldata,
        version: det.version,
      });
    } else if (
      Object.values(RPC.ETransactionVersion3).includes(details.version as any)
    ) {
      const det = details as V3InvocationsSignerDetails;
      msgHash = hash.calculateInvokeTransactionHash({
        ...det,
        senderAddress: det.walletAddress,
        compiledCalldata,
        version: det.version,
        nonceDataAvailabilityMode: stark.intDAM(det.nonceDataAvailabilityMode),
        feeDataAvailabilityMode: stark.intDAM(det.feeDataAvailabilityMode),
      });
    } else {
      throw new Error("unsupported signTransaction version");
    }
    return await this.signRaw(msgHash);
  }

  public async signDeployAccountTransaction(
    details: DeployAccountSignerDetails
  ): Promise<Signature> {
    const compiledConstructorCalldata = CallData.compile(
      details.constructorCalldata
    );
    /*     const version = BigInt(details.version).toString(); */
    let msgHash;

    if (
      Object.values(RPC.ETransactionVersion2).includes(details.version as any)
    ) {
      const det = details as V2DeployAccountSignerDetails;
      msgHash = hash.calculateDeployAccountTransactionHash({
        ...det,
        salt: det.addressSalt,
        constructorCalldata: compiledConstructorCalldata,
        version: det.version,
      });
    } else if (
      Object.values(RPC.ETransactionVersion3).includes(details.version as any)
    ) {
      const det = details as V3DeployAccountSignerDetails;
      msgHash = hash.calculateDeployAccountTransactionHash({
        ...det,
        salt: det.addressSalt,
        compiledConstructorCalldata,
        version: det.version,
        nonceDataAvailabilityMode: stark.intDAM(det.nonceDataAvailabilityMode),
        feeDataAvailabilityMode: stark.intDAM(det.feeDataAvailabilityMode),
      });
    } else {
      throw new Error(
        `unsupported signDeployAccountTransaction version: ${details.version}}`
      );
    }

    return await this.signRaw(msgHash);
  }

  public async signDeclareTransaction(
    // contractClass: ContractClass,  // Should be used once class hash is present in ContractClass
    details: DeclareSignerDetails
  ): Promise<Signature> {
    let msgHash;

    if (
      Object.values(RPC.ETransactionVersion2).includes(details.version as any)
    ) {
      const det = details as V2DeclareSignerDetails;
      msgHash = hash.calculateDeclareTransactionHash({
        ...det,
        version: det.version,
      });
    } else if (
      Object.values(RPC.ETransactionVersion3).includes(details.version as any)
    ) {
      const det = details as V3DeclareSignerDetails;
      msgHash = hash.calculateDeclareTransactionHash({
        ...det,
        version: det.version,
        nonceDataAvailabilityMode: stark.intDAM(det.nonceDataAvailabilityMode),
        feeDataAvailabilityMode: stark.intDAM(det.feeDataAvailabilityMode),
      });
    } else {
      throw new Error("unsupported signDeclareTransaction version");
    }

    return await this.signRaw(msgHash);
  }
}

export abstract class RawSignerMultisig implements SignerInterface {
  abstract signRaw(
    messageHash: string
  ): Promise<{ messageBytes: Uint8Array; signature: string }>;

  public async getPubKey(): Promise<string> {
    throw new Error("This signer allows multiple public keys");
  }

  public async signMessage(
    typedDataArgument: typeof typedData.TypedData,
    accountAddress: string
  ): Promise<any> {
    const messageHash = typedData.getMessageHash(
      typedDataArgument,
      accountAddress
    );
    return this.signRaw(messageHash);
  }

  public async signTransaction(
    transactions: Call[],
    details: InvocationsSignerDetails
  ): Promise<any> {
    const compiledCalldata = transaction.getExecuteCalldata(
      transactions,
      details.cairoVersion
    );
    let msgHash;

    // TODO: How to do generic union discriminator for all like this
    if (
      Object.values(RPC.ETransactionVersion2).includes(details.version as any)
    ) {
      const det = details as V2InvocationsSignerDetails;
      msgHash = hash.calculateInvokeTransactionHash({
        ...det,
        senderAddress: det.walletAddress,
        compiledCalldata,
        version: det.version,
      });
    } else if (
      Object.values(RPC.ETransactionVersion3).includes(details.version as any)
    ) {
      const det = details as V3InvocationsSignerDetails;
      msgHash = hash.calculateInvokeTransactionHash({
        ...det,
        senderAddress: det.walletAddress,
        compiledCalldata,
        version: det.version,
        nonceDataAvailabilityMode: stark.intDAM(det.nonceDataAvailabilityMode),
        feeDataAvailabilityMode: stark.intDAM(det.feeDataAvailabilityMode),
      });
    } else {
      throw new Error("unsupported signTransaction version");
    }
    return await this.signRaw(msgHash);
  }

  public async signDeployAccountTransaction(
    details: DeployAccountSignerDetails
  ): Promise<any> {
    const compiledConstructorCalldata = CallData.compile(
      details.constructorCalldata
    );
    /*     const version = BigInt(details.version).toString(); */
    let msgHash;

    if (
      Object.values(RPC.ETransactionVersion2).includes(details.version as any)
    ) {
      const det = details as V2DeployAccountSignerDetails;
      msgHash = hash.calculateDeployAccountTransactionHash({
        ...det,
        salt: det.addressSalt,
        constructorCalldata: compiledConstructorCalldata,
        version: det.version,
      });
    } else if (
      Object.values(RPC.ETransactionVersion3).includes(details.version as any)
    ) {
      const det = details as V3DeployAccountSignerDetails;
      msgHash = hash.calculateDeployAccountTransactionHash({
        ...det,
        salt: det.addressSalt,
        compiledConstructorCalldata,
        version: det.version,
        nonceDataAvailabilityMode: stark.intDAM(det.nonceDataAvailabilityMode),
        feeDataAvailabilityMode: stark.intDAM(det.feeDataAvailabilityMode),
      });
    } else {
      throw new Error(
        `unsupported signDeployAccountTransaction version: ${details.version}}`
      );
    }

    return await this.signRaw(msgHash);
  }

  public async signDeclareTransaction(
    // contractClass: ContractClass,  // Should be used once class hash is present in ContractClass
    details: DeclareSignerDetails
  ): Promise<any> {
    let msgHash;

    if (
      Object.values(RPC.ETransactionVersion2).includes(details.version as any)
    ) {
      const det = details as V2DeclareSignerDetails;
      msgHash = hash.calculateDeclareTransactionHash({
        ...det,
        version: det.version,
      });
    } else if (
      Object.values(RPC.ETransactionVersion3).includes(details.version as any)
    ) {
      const det = details as V3DeclareSignerDetails;
      msgHash = hash.calculateDeclareTransactionHash({
        ...det,
        version: det.version,
        nonceDataAvailabilityMode: stark.intDAM(det.nonceDataAvailabilityMode),
        feeDataAvailabilityMode: stark.intDAM(det.feeDataAvailabilityMode),
      });
    } else {
      throw new Error("unsupported signDeclareTransaction version");
    }

    return await this.signRaw(msgHash);
  }
}

export class MultisigSigner extends RawSigner {
  constructor(public keys: KeyPair[]) {
    super();
  }

  async signRaw(messageHash: string): Promise<string[]> {
    const keys = [];
    for (const key of this.keys) {
      keys.push(await key.signRaw(messageHash));
    }
    return [keys.length.toString(), keys.flat()].flat();
  }
}

export class ArgentSigner extends MultisigSigner {
  constructor(
    public owner: KeyPair = randomStarknetKeyPair(),
    public guardian?: KeyPair
  ) {
    const signers = [owner];
    if (guardian) {
      signers.push(guardian);
    }
    super(signers);
  }
}

export abstract class KeyPair extends RawSigner {
  abstract get signer(): CairoCustomEnum;
  abstract get guid(): bigint;
  abstract get storedValue(): bigint;

  public get compiledSigner(): Calldata {
    return CallData.compile([this.signer]);
  }

  public get signerAsOption() {
    return new CairoOption(CairoOptionVariant.Some, {
      signer: this.signer,
    });
  }
  public get compiledSignerAsOption() {
    return CallData.compile([this.signerAsOption]);
  }
}

export abstract class KeyPairMultisig extends RawSignerMultisig {
  abstract get signer(): CairoCustomEnum;
  abstract get guid(): bigint;
  abstract get storedValue(): bigint;

  public get compiledSigner(): Calldata {
    return CallData.compile([this.signer]);
  }

  public get signerAsOption() {
    return new CairoOption(CairoOptionVariant.Some, {
      signer: this.signer,
    });
  }
  public get compiledSignerAsOption() {
    return CallData.compile([this.signerAsOption]);
  }
}

export class StarknetKeyPair extends KeyPair {
  pk: string;

  constructor(pk?: string | bigint) {
    super();
    this.pk = pk
      ? num.toHex(pk)
      : `0x${encode.buf2hex(ec.starkCurve.utils.randomPrivateKey())}`;
  }

  public get privateKey(): string {
    return this.pk;
  }

  public get publicKey() {
    return BigInt(ec.starkCurve.getStarkKey(this.pk));
  }

  public get guid() {
    return BigInt(
      hash.computePoseidonHash(
        shortString.encodeShortString("Starknet Signer"),
        this.publicKey
      )
    );
  }

  public get storedValue() {
    return this.publicKey;
  }

  public get signer(): CairoCustomEnum {
    return signerTypeToCustomEnum(SignerType.Starknet, {
      signer: this.publicKey,
    });
  }

  public async signRaw(messageHash: string): Promise<string[]> {
    const { r, s } = ec.starkCurve.sign(messageHash, this.pk);
    return starknetSignatureType(this.publicKey, r, s);
  }
}

export class EstimateStarknetKeyPair extends KeyPair {
  readonly pubKey: bigint;

  constructor(pubKey: bigint) {
    super();
    this.pubKey = pubKey;
  }

  public get privateKey(): string {
    throw new Error("EstimateStarknetKeyPair does not have a private key");
  }

  public get publicKey() {
    return this.pubKey;
  }

  public get guid() {
    return BigInt(
      hash.computePoseidonHash(
        shortString.encodeShortString("Starknet Signer"),
        this.publicKey
      )
    );
  }

  public get storedValue() {
    return this.publicKey;
  }

  public get signer(): CairoCustomEnum {
    return signerTypeToCustomEnum(SignerType.Starknet, {
      signer: this.publicKey,
    });
  }

  public async signRaw(messageHash: string): Promise<string[]> {
    const fakeR =
      "0x6cefb49a1f4eb406e8112db9b8cdf247965852ddc5ca4d74b09e42471689495";
    const fakeS =
      "0x25760910405a052b7f08ec533939c54948bc530c662c5d79e8ff416579087f7";
    return starknetSignatureType(this.publicKey, fakeR, fakeS);
  }
}

export function starknetSignatureType(
  signer: bigint | number | string,
  r: bigint | number | string,
  s: bigint | number | string
) {
  return CallData.compile([
    signerTypeToCustomEnum(SignerType.Starknet, { signer, r, s }),
  ]);
}

export function zeroStarknetSignatureType() {
  return signerTypeToCustomEnum(SignerType.Starknet, { signer: 0 });
}

// reflects the signer type in signer_signature.cairo
// needs to be updated for the signer types
// used to convert signertype to guid
export enum SignerType {
  Starknet,
  Secp256k1,
  Secp256r1,
  Eip191,
  Webauthn,
}

export function signerTypeToCustomEnum(
  signerType: SignerType,
  value: any
): CairoCustomEnum {
  const contents = {
    Starknet: undefined,
    Secp256k1: undefined,
    Secp256r1: undefined,
    Eip191: undefined,
    Webauthn: undefined,
  };

  if (signerType === SignerType.Starknet) {
    contents.Starknet = value;
  } else if (signerType === SignerType.Secp256k1) {
    contents.Secp256k1 = value;
  } else if (signerType === SignerType.Secp256r1) {
    contents.Secp256r1 = value;
  } else if (signerType === SignerType.Eip191) {
    contents.Eip191 = value;
  } else if (signerType === SignerType.Webauthn) {
    contents.Webauthn = value;
  } else {
    throw new Error(`Unknown SignerType`);
  }

  return new CairoCustomEnum(contents);
}

export function sortByGuid(keys: KeyPair[]) {
  return keys.sort((n1, n2) => (n1.guid < n2.guid ? -1 : 1));
}

export const randomStarknetKeyPair = () => new StarknetKeyPair();
export const randomStarknetKeyPairs = (length: number) =>
  Array.from({ length }, randomStarknetKeyPair);

export class ArgentAccount extends Account {
  // Increase the gas limit by 30% to avoid failures due to gas estimation being too low with tx v3 and transactions the use escaping
  override async deployAccount(
    payload: DeployAccountContractPayload,
    details?: UniversalDetails
  ): Promise<DeployContractResponse> {
    details ||= {};
    if (!details.skipValidate) {
      details.skipValidate = false;
    }
    return super.deployAccount(payload, details);
  }

  override execute(
    transactions: AllowArray<Call>,
    abis?: Abi[],
    transactionsDetail?: UniversalDetails
  ): Promise<InvokeFunctionResponse>;
  override execute(
    transactions: AllowArray<Call>,
    transactionsDetail?: UniversalDetails
  ): Promise<InvokeFunctionResponse>;
  override async execute(
    transactions: AllowArray<Call>,
    abisOrDetails?: Abi[] | UniversalDetails,
    transactionsDetail?: UniversalDetails
  ): Promise<InvokeFunctionResponse> {
    const details = (transactionsDetail ||
      abisOrDetails ||
      {}) as UniversalDetails;
    details.skipValidate ??= false;

    return super.execute(transactions, abisOrDetails as any, details);
  }
}

export function toBigInt(value: BigNumberish): bigint {
  return BigInt(value);
}

export function isBigInt(value: any): value is bigint {
  return typeof value === "bigint";
}

export function addPercent(number: BigNumberish, percent: number): bigint {
  const bigIntNum = BigInt(number);
  return bigIntNum + (bigIntNum * BigInt(percent)) / 100n;
}

export const isUndefined = (value: unknown): value is undefined => {
  return typeof value === "undefined" || value === undefined;
};

export function removeHexPrefix(hex: string): string {
  return hex.replace(/^0x/i, "");
}

export function addHexPrefix(hex: string): string {
  return `0x${removeHexPrefix(hex)}`;
}

export function toHex(value: BigNumberish): string {
  return addHexPrefix(toBigInt(value).toString(16));
}

export function toTransactionVersion(
  defaultVersion: BigNumberish,
  providedVersion?: BigNumberish
): ETransactionVersion {
  const providedVersion0xs = providedVersion
    ? toHex(providedVersion)
    : undefined;
  const defaultVersion0xs = toHex(defaultVersion);

  if (
    providedVersion &&
    !Object.values(ETransactionVersion).includes(providedVersion0xs as any)
  ) {
    throw Error(
      `providedVersion ${providedVersion} is not ETransactionVersion`
    );
  }
  if (!Object.values(ETransactionVersion).includes(defaultVersion0xs as any)) {
    throw Error(`defaultVersion ${defaultVersion} is not ETransactionVersion`);
  }

  return (
    providedVersion ? providedVersion0xs : defaultVersion0xs
  ) as ETransactionVersion;
}

export function estimateFeeToBounds(
  estimate: FeeEstimate | 0n,
  amountOverhead: number = FeeMarginPercentage.L1_BOUND_MAX_AMOUNT,
  priceOverhead: number = FeeMarginPercentage.L1_BOUND_MAX_PRICE_PER_UNIT
): ResourceBounds {
  if (isBigInt(estimate)) {
    return {
      l2_gas: { max_amount: "0x0", max_price_per_unit: "0x0" },
      l1_gas: { max_amount: "0x0", max_price_per_unit: "0x0" },
    };
  }

  if (isUndefined(estimate.gas_consumed) || isUndefined(estimate.gas_price)) {
    throw Error("estimateFeeToBounds: estimate is undefined");
  }

  const maxUnits =
    estimate.data_gas_consumed !== undefined &&
    estimate.data_gas_price !== undefined // RPC v0.7
      ? toHex(
          addPercent(
            BigInt(estimate.overall_fee) / BigInt(estimate.gas_price),
            amountOverhead
          )
        )
      : toHex(addPercent(estimate.gas_consumed, amountOverhead));
  const maxUnitPrice = toHex(addPercent(estimate.gas_price, priceOverhead));
  return {
    l2_gas: { max_amount: "0x0", max_price_per_unit: "0x0" },
    l1_gas: { max_amount: maxUnits, max_price_per_unit: maxUnitPrice },
  };
}

type V3Details = Required<
  Pick<
    UniversalDetails,
    | "tip"
    | "paymasterData"
    | "accountDeploymentData"
    | "nonceDataAvailabilityMode"
    | "feeDataAvailabilityMode"
    | "resourceBounds"
  >
>;

export function v3Details(details: UniversalDetails): V3Details {
  return {
    tip: details.tip || 0,
    paymasterData: details.paymasterData || [],
    accountDeploymentData: details.accountDeploymentData || [],
    nonceDataAvailabilityMode:
      details.nonceDataAvailabilityMode || EDataAvailabilityMode.L1,
    feeDataAvailabilityMode:
      details.feeDataAvailabilityMode || EDataAvailabilityMode.L1,
    resourceBounds: details.resourceBounds ?? estimateFeeToBounds(ZERO),
  };
}

export class ArgentAccountWithoutExecute extends Account {
  // Increase the gas limit by 30% to avoid failures due to gas estimation being too low with tx v3 and transactions the use escaping
  override async deployAccount(
    payload: DeployAccountContractPayload,
    details?: UniversalDetails
  ): Promise<DeployContractResponse> {
    details ||= {};
    if (!details.skipValidate) {
      details.skipValidate = false;
    }
    return super.deployAccount(payload, details);
  }

  override execute(
    transactions: AllowArray<Call>,
    abis?: Abi[],
    transactionsDetail?: UniversalDetails
  ): Promise<InvokeFunctionResponse>;
  override execute(
    transactions: AllowArray<Call>,
    transactionsDetail?: UniversalDetails
  ): Promise<InvokeFunctionResponse>;
  override async execute(
    transactions: AllowArray<Call>,
    abisOrDetails?: Abi[] | UniversalDetails,
    transactionsDetail?: UniversalDetails
  ): Promise<any> {
    const details = (transactionsDetail ||
      abisOrDetails ||
      {}) as UniversalDetails;
    const calls = Array.isArray(transactions) ? transactions : [transactions];
    const nonce = toBigInt(details.nonce ?? (await this.getNonce()));
    const version = toTransactionVersion(
      this.getPreferredVersion(ETransactionVersion.V1, ETransactionVersion.V3), // TODO: does this depend on cairo version ?
      details.version
    );

    const estimate = await this.getUniversalSuggestedFee(
      version,
      { type: TransactionType.INVOKE, payload: transactions },
      {
        ...details,
        version,
      }
    );

    const chainId = await this.getChainId();

    const signerDetails: InvocationsSignerDetails = {
      ...v3Details(details),
      resourceBounds: estimate.resourceBounds,
      walletAddress: this.address,
      nonce,
      maxFee: estimate.maxFee,
      version,
      chainId,
      cairoVersion: await this.getCairoVersion(),
    };

    const signature = await this.signer.signTransaction(calls, signerDetails);
    return signature;
  }
}
