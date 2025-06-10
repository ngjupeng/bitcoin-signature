"use client";

import toast from "react-hot-toast";
import { universalStrkAddress } from "~~/utils/Constants";
import { Account, CairoUint256, CallData } from "starknet";
import { useAccount } from "@starknet-react/core";
import { useScaffoldWriteContract } from "~~/hooks/scaffold-stark/useScaffoldWriteContract";

import { verify } from "bitcoinjs-message";
import { decodeSignature } from "~~/utils/bitcoin-message";
const secp256k1 = require("secp256k1");

const Home = () => {
  const { account } = useAccount();
  const { sendAsync } = useScaffoldWriteContract({
    contractName: "BitcoinSignature",
    functionName: "verify_message",
    args: ["0xd8da6bf26964af9d7eed9e03e53415d37aa96045", "Hello, world!"],
  });

  const handleSignTransaction = async () => {
    if (!account) {
      toast.error("No account found");
      return;
    }

    const calls = [
      {
        contractAddress: universalStrkAddress,
        calldata: CallData.compile({
          recipient:
            "0x0135353f55784cb5f1c1c7d2ec3f5d4dab42eff301834a9d8588550ae7a33ed4",
          amount: new CairoUint256(100),
        }),
        entrypoint: "transfer",
      },
    ];
    const result = await account.execute(calls);

    // use this to verify signature
    const signature = result.transaction_hash;
    const message = JSON.stringify(calls);
    const address = "bc1qkmtwd3gtm65khw50yaguyvyer0evnvw88pvr5k";

    console.log("BITCOIN SIGNING MESSAGE", message);
    console.log("BITCOIN SIGNATURE", signature);
    console.log("BITCOIN ADDRESS", address);
  };

  const handleVerifySignature = async () => {
    // message: [{"contractAddress":"0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d","calldata":["546323243050573886133918168694107001887540161464523092248027197167743745748","100","0"],"entrypoint":"transfer"}]
    const signature =
      "KBVqML3Lg9Y6z+yXCRYP8IJfR+SCTErvbD/Y3x3+C0OgX1HW6hWv6gxR7INkaLNkUtrhtUbAx0VeE8iSG9P6Iqs=";

    // const result = await sendAsync();
    // console.log("RESULT", result);

    const result = verify(
      `[{"contractAddress":"0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d","calldata":["546323243050573886133918168694107001887540161464523092248027197167743745748","100","0"],"entrypoint":"transfer"}]`,
      "bc1qkmtwd3gtm65khw50yaguyvyer0evnvw88pvr5k",
      "KBVqML3Lg9Y6z+yXCRYP8IJfR+SCTErvbD/Y3x3+C0OgX1HW6hWv6gxR7INkaLNkUtrhtUbAx0VeE8iSG9P6Iqs="
    );
    console.log("RESULT", result);

    const parsed = decodeSignature(Buffer.from(signature, "base64"));
    console.log("PARSED", parsed);

    // when you sign message on bitcoin, you use ethereum prefix, the standard `"\x19Ethereum Signed Message:\n" + len(message).`
    // 2. decode it, get r,s,v
    // 3. use the ethereum signature verification function on cairo
  };
  return (
    <div className="flex items-center flex-col flex-grow pt-10">
      <div>
        <p>Account: {account?.address}</p>
      </div>
      <div className="bg-red-300">
        <button onClick={handleSignTransaction}>Sign Transaction</button>
      </div>
      <div className="bg-red-300">
        <button onClick={handleVerifySignature}>Verify Signature</button>
      </div>
    </div>
  );
};

export default Home;
