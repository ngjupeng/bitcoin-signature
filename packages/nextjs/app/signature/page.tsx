"use client";
import React, { useState } from "react";
import { ec as EC } from "elliptic";

const ec = new EC("secp256k1");

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  return new Uint8Array(hashBuffer);
}

function encodeVarInt(n: number): Uint8Array {
  if (n < 0xfd) return new Uint8Array([n]);
  if (n <= 0xffff) return new Uint8Array([0xfd, n & 0xff, (n >> 8) & 0xff]);
  return new Uint8Array([
    0xfe,
    n & 0xff,
    (n >> 8) & 0xff,
    (n >> 16) & 0xff,
    (n >> 24) & 0xff,
  ]);
}

async function hashMessage(message: string): Promise<Uint8Array> {
  const prefix = "Bitcoin Signed Message:\n";
  const encoder = new TextEncoder();
  const prefixBytes = encoder.encode(prefix);
  const messageBytes = encoder.encode(message);
  console.log("prefixBytes", prefixBytes);

  const varPrefix = encodeVarInt(prefixBytes.length);
  const varMsg = encodeVarInt(messageBytes.length);

  const full = new Uint8Array(
    varPrefix.length + prefixBytes.length + varMsg.length + messageBytes.length
  );
  let offset = 0;
  full.set(varPrefix, offset);
  offset += varPrefix.length;
  full.set(prefixBytes, offset);
  offset += prefixBytes.length;
  full.set(varMsg, offset);
  offset += varMsg.length;
  full.set(messageBytes, offset);

  // Print the exact message being hashed as a string
  const fullString = new TextDecoder().decode(full);
  console.log("Exact message being hashed (first hash):", fullString);
  console.log(
    "Exact message in hex:",
    Array.from(full)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("")
  );

  const firstHash = await sha256(full);
  const firstHashHex = Array.from(firstHash)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  const firstHashDecimal = Array.from(firstHash).join(", ");
  console.log("firstHash (hex):", firstHashHex);
  console.log("firstHash (decimal):", firstHashDecimal);

  // Print the exact message being hashed for second hash
  console.log("Exact message being hashed (second hash):", firstHashHex);

  const finalHash = await sha256(firstHash);
  const finalHashHex = Array.from(finalHash)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  const finalHashDecimal = Array.from(finalHash).join(", ");
  console.log("finalHash (hex):", finalHashHex);
  console.log("finalHash (decimal):", finalHashDecimal);
  return finalHash;
}

interface EcdsaSignatureResult {
  publicKey: string;
  r: string;
  s: string;
  message: string;
  signature: string;
  recoveryId?: number;
  x?: string;
  y?: string;
}

export default function BitcoinSignVerify() {
  const [walletAddress, setWalletAddress] = useState(
    "bc1q8s30a5gn0zs5k0rvvxm9ay607w2gl0fux7jn88"
  );
  const [message, setMessage] = useState(
    "Sign this message to verify your Bitcoin address."
  );
  const [signatureResult, setSignatureResult] =
    useState<EcdsaSignatureResult | null>(null);
  const [hash, setHash] = useState<string | null>(null);
  const [valid, setValid] = useState<boolean | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [signing, setSigning] = useState(false);

  async function signWithUnisat(address: string, message: string) {
    if (!window.unisat) throw new Error("Unisat wallet not found");
    const signature = await window.unisat.signMessage(message);
    const publicKey = await window.unisat.getPublicKey();
    return { signature, publicKey, message };
  }

  function extractSignature(
    signature: string,
    publicKey: string,
    message: string
  ): EcdsaSignatureResult {
    const bytes = Uint8Array.from(atob(signature), (c) => c.charCodeAt(0));
    const recoveryId = bytes[0];
    const rBytes = bytes.slice(1, 33);
    const sBytes = bytes.slice(33, 65);

    const r = BigInt("0x" + Buffer.from(rBytes).toString("hex")).toString();
    const s = BigInt("0x" + Buffer.from(sBytes).toString("hex")).toString();

    const key = ec.keyFromPublic(publicKey, "hex");
    const pubPoint = key.getPublic();
    const x = pubPoint.getX().toString(10);
    const y = pubPoint.getY().toString(10);

    return { r, s, publicKey, message, signature, recoveryId, x, y };
  }

  async function verifySignature(
    pubKeyHex: string,
    message: string,
    r: string,
    s: string
  ): Promise<boolean> {
    const hashBytes = await hashMessage(message);
    const rHex = BigInt(r).toString(16);
    const sHex = BigInt(s).toString(16);
    const key = ec.keyFromPublic(pubKeyHex, "hex");
    return key.verify(hashBytes, { r: rHex, s: sHex });
  }

  async function signAndVerify() {
    try {
      setError(null);
      setSigning(true);
      const result = await signWithUnisat(walletAddress, message);
      const sigData = extractSignature(
        result.signature,
        result.publicKey,
        result.message
      );
      setSignatureResult(sigData);

      const hashBytes = await hashMessage(result.message);
      const hashHex = Array.from(hashBytes)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
      setHash(hashHex);

      const isValid = await verifySignature(
        result.publicKey,
        result.message,
        sigData.r,
        sigData.s
      );
      setValid(isValid);
    } catch (err: any) {
      setError(err.message || "Unexpected error");
    } finally {
      setSigning(false);
    }
  }

  return (
    <div className="min-h-screen bg-black text-white p-6 font-sans">
      <h1 className="text-2xl font-bold mb-4 text-center">
        Bitcoin ECDSA Sign & Verify
      </h1>

      <div className="mb-4">
        <label className="block mb-1">Wallet Address:</label>
        <input
          value={walletAddress}
          onChange={(e) => setWalletAddress(e.target.value)}
          className="w-full p-2 bg-black border border-white text-white rounded"
        />
      </div>

      <div className="mb-4">
        <label className="block mb-1">Message to Sign:</label>
        <textarea
          value={message}
          onChange={(e) => setMessage(e.target.value)}
          className="w-full p-2 bg-black border border-white text-white rounded"
          rows={3}
        />
      </div>

      <button
        onClick={signAndVerify}
        disabled={signing}
        className="w-full p-3 bg-white text-black font-bold rounded hover:bg-gray-300 disabled:opacity-50"
      >
        {signing ? "Signing..." : "Sign & Verify"}
      </button>

      {error && <p className="text-red-400 mt-4">{error}</p>}

      {signatureResult && (
        <div className="mt-6 text-sm space-y-2">
          <p>
            <strong>Message:</strong> {signatureResult.message}
          </p>
          <p>
            <strong>Public Key:</strong> {signatureResult.publicKey}
          </p>
          <p>
            <strong>r:</strong> {signatureResult.r}
          </p>
          <p>
            <strong>s:</strong> {signatureResult.s}
          </p>
          <p>
            <strong>recoveryId:</strong> {signatureResult.recoveryId}
          </p>
          <p>
            <strong>x:</strong> {signatureResult.x}
          </p>
          <p>
            <strong>y:</strong> {signatureResult.y}
          </p>
          <p>
            <strong>Signature (base64):</strong> {signatureResult.signature}
          </p>
          <p>
            <strong>Hash (double SHA-256):</strong> {hash}
          </p>
          <p>
            <strong>Valid Signature:</strong> {valid ? "✅ Yes" : "❌ No"}
          </p>
        </div>
      )}
    </div>
  );
}
