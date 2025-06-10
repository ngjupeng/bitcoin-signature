import {
  ConnectArgs,
  ConnectorNotConnectedError,
  ConnectorNotFoundError,
  InjectedConnector,
  InjectedConnectorOptions,
  UserRejectedRequestError,
} from "@starknet-react/core";
import { ConnectorData } from "@starknet-react/core/src/connectors/base";
import icon from "./icons/xverse.png";
import {
  getAddress,
  AddressPurpose,
  BitcoinNetworkType,
  BitcoinProvider,
  SignMessageOptions,
  MessageSigningProtocols,
} from "sats-connect";
import {
  Account,
  Call,
  RpcProvider,
  AccountInterface,
  constants,
} from "starknet";

declare global {
  interface Window {
    BitcoinProvider?: BitcoinProvider;
  }
}

const xverseWalletId = "xverse";
const xverseWalletName = "Xverse Wallet";
const xverseWalletIcon = icon.src;

// Utility function for address conversion
function convertToStarknetAddress(bitcoinAddress: string): string {
  const hash = bitcoinAddress.split("").reduce((acc, char) => {
    return ((acc << 5) - acc + char.charCodeAt(0)) | 0;
  }, 0);
  return `0x${Math.abs(hash).toString(16).padStart(40, "0")}`;
}

class BitcoinAccount extends Account {
  private network: BitcoinNetworkType = BitcoinNetworkType.Mainnet;
  private _bitcoinAddress: string;

  constructor(bitcoinAddress: string) {
    super(
      new RpcProvider({
        nodeUrl: "https://bitcoin-rpc.publicnode.com",
      }),
      convertToStarknetAddress(bitcoinAddress),
      constants.StarknetChainId.SN_SEPOLIA
    );
    this._bitcoinAddress = bitcoinAddress;
  }

  get bitcoinAddress(): string {
    return this._bitcoinAddress;
  }

  async execute(calls: Call[]): Promise<any> {
    if (!window.BitcoinProvider) {
      throw new Error("Xverse wallet not installed!");
    }

    // todo: according to how contract verify signature, we need to change the message
    const message = JSON.stringify(calls);
    console.log("BITCOIN SIGNING MESSAGE", message);
    const { signMessage } = await import("sats-connect");
    return new Promise((resolve, reject) => {
      const signMessageOptions: SignMessageOptions = {
        payload: {
          network: {
            type: this.network,
          },
          address: this._bitcoinAddress,
          message,
          protocol: MessageSigningProtocols.ECDSA,
        },

        onFinish: (response) => {
          resolve({
            transaction_hash: response,
          });
        },
        onCancel: () => {
          reject({
            code: 4001,
            message: "User rejected the request.",
          });
        },
      };
      signMessage(signMessageOptions).catch((e) => reject(e));
    });
  }

  async getChainId() {
    return constants.StarknetChainId.SN_SEPOLIA;
  }
}

export class XverseConnector extends InjectedConnector {
  private __wallet?: BitcoinProvider;
  private __options: InjectedConnectorOptions;
  private __network: BitcoinNetworkType = BitcoinNetworkType.Mainnet;
  private __accounts: string[] = [];
  private __currentAccount?: BitcoinAccount;
  private __isConnecting: boolean = false;
  private __isConnected: boolean = false;

  constructor() {
    const options: InjectedConnectorOptions = {
      id: xverseWalletId,
      name: xverseWalletName,
      icon: xverseWalletIcon,
    };
    super({
      options,
    });
    this.__options = options;
  }

  get id() {
    return this.__options.id;
  }

  get name() {
    return xverseWalletName;
  }

  get icon() {
    return xverseWalletIcon;
  }

  available() {
    return typeof window !== "undefined" && !!window.BitcoinProvider;
  }

  getChainId(): string {
    return constants.StarknetChainId.SN_SEPOLIA;
  }

  async chainId(): Promise<bigint> {
    this._ensureWallet();
    const locked = await this._isLocked();

    if (!this.__wallet || locked) {
      throw new ConnectorNotConnectedError();
    }

    try {
      return BigInt(this.getChainId());
    } catch {
      throw new ConnectorNotFoundError();
    }
  }

  async ready(): Promise<boolean> {
    if (this.__isConnected) return true;

    this._ensureWallet();
    if (!this.__wallet) return false;

    try {
      const lastConnectedAccount = localStorage.getItem("lastConnectedAccount");
      if (lastConnectedAccount) {
        this.__currentAccount = new BitcoinAccount(lastConnectedAccount);
        this.__isConnected = true;
        return true;
      }

      const addresses = await this.getAccounts();
      this.__isConnected = addresses.length > 0;
      return this.__isConnected;
    } catch (error) {
      console.error("Ready check failed:", error);
      return false;
    }
  }

  async connect(_args: ConnectArgs = {}): Promise<ConnectorData> {
    if (this.__isConnecting) {
      throw new Error("Connection already in progress");
    }

    if (this.__isConnected) {
      const [account] = this.__accounts;
      const chainId = await this.chainId();
      return { account, chainId };
    }

    try {
      this.__isConnecting = true;
      this._ensureWallet();

      if (!this.__wallet) {
        console.error("Xverse wallet not found");
        throw new ConnectorNotFoundError();
      }

      let accounts: string[];
      try {
        accounts = await this._requestAccounts();
      } catch (error) {
        console.error("Failed to get accounts:", error);
        throw new UserRejectedRequestError();
      }

      if (!accounts || accounts.length === 0) {
        console.error("No accounts returned");
        throw new UserRejectedRequestError();
      }

      this.__accounts = accounts;
      const [account] = accounts;
      const chainId = await this.chainId();

      localStorage.setItem(
        "lastUsedConnector",
        JSON.stringify({ id: this.id })
      );
      localStorage.setItem("lastConnectedTime", Date.now().toString());
      localStorage.setItem(
        "lastConnectedAccount",
        this.__currentAccount?.bitcoinAddress || ""
      );

      this.__isConnected = true;

      this.emit("connect", { account, chainId });
      this.emit("change", { chainId, account });

      return {
        account,
        chainId,
      };
    } finally {
      this.__isConnecting = false;
    }
  }

  async disconnect(): Promise<void> {
    this._ensureWallet();
    if (!this.__wallet) {
      throw new ConnectorNotFoundError();
    }
    this.__accounts = [];
    this.__currentAccount = undefined;
    this.__isConnecting = false;
    this.__isConnected = false;
    localStorage.removeItem("lastUsedConnector");
    localStorage.removeItem("lastConnectedTime");
    localStorage.removeItem("lastConnectedAccount");
    this.emit("disconnect");
  }

  async getAccounts(): Promise<string[]> {
    if (!this.__wallet) {
      throw new Error(`${this.name} is not installed!`);
    }

    if (this.__accounts.length > 0) {
      return this.__accounts;
    }

    const data = localStorage.getItem(
      `btc-connect-xverse-addresses-${this.__network}`
    );
    if (data) {
      const addresses = JSON.parse(data);
      const bitcoinAddresses = addresses.map((item: any) => item.address);
      this.__accounts = bitcoinAddresses.map((addr: string) =>
        convertToStarknetAddress(addr)
      );
      return this.__accounts;
    }
    return [];
  }

  async account(): Promise<AccountInterface> {
    if (!this.__currentAccount) {
      const isReady = await this.ready();
      if (!isReady) {
        throw new ConnectorNotConnectedError();
      }

      if (this.__accounts.length > 0) {
        const [account] = this.__accounts;
        this.__currentAccount = new BitcoinAccount(account);
      } else {
        throw new ConnectorNotConnectedError();
      }
    }

    return this.__currentAccount;
  }

  private _ensureWallet() {
    this.__wallet = window.BitcoinProvider;
  }

  private async _isLocked(): Promise<boolean> {
    const accounts = await this.getAccounts();
    return accounts.length === 0;
  }

  private async _requestAccounts(): Promise<string[]> {
    if (!this.__wallet) {
      throw new Error(`${this.name} is not installed!`);
    }

    const addresses = await new Promise<any[]>((resolve, reject) => {
      const getAddressOptions = {
        payload: {
          purposes: [AddressPurpose.Payment, AddressPurpose.Ordinals],
          message: "Address for receiving Ordinals and payments",
          network: {
            type: this.__network,
          },
        },
        onFinish: (response: any) => {
          resolve(response.addresses);
        },
        onCancel: () => {
          reject({
            code: 4001,
            message: "User rejected the request.",
          });
        },
      };
      getAddress(getAddressOptions).catch((error) => {
        console.error("Error getting addresses:", error);
        reject(error);
      });
    });

    const bitcoinAddresses = addresses.map((item) => item.address);
    localStorage.setItem(
      `btc-connect-xverse-addresses-${this.__network}`,
      JSON.stringify(addresses)
    );

    // set the first address as the current account
    this.__currentAccount = new BitcoinAccount(bitcoinAddresses[0]);

    // todo: find a way to serialize bitcoin address into starknet address
    return ["0x1"];
  }
}
