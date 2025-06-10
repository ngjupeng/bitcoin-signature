const SEGWIT_TYPES = {
  P2WPKH: "p2wpkh",
  P2SH_P2WPKH: "p2sh(p2wpkh)",
};

export function decodeSignature(buffer: Buffer) {
  if (buffer.length !== 65) throw new Error("Invalid signature length");

  const flagByte = buffer.readUInt8(0) - 27;
  if (flagByte > 15 || flagByte < 0) {
    throw new Error("Invalid signature parameter");
  }

  return {
    compressed: !!(flagByte & 12),
    segwitType: !(flagByte & 8)
      ? null
      : !(flagByte & 4)
        ? SEGWIT_TYPES.P2SH_P2WPKH
        : SEGWIT_TYPES.P2WPKH,
    recovery: flagByte & 3,
    signature: buffer.slice(1),
  };
}
