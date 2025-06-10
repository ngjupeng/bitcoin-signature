"use client";

import { useEffect } from "react";
import { sepolia } from "@starknet-react/chains";
import { BanknotesIcon } from "@heroicons/react/24/outline";
import { useNetwork, useProvider } from "@starknet-react/core";
import { notification } from "~~/utils/scaffold-stark";
import Image from "next/image";
import GenericModal from "./CustomConnectButton/GenericModal";
import { useTheme } from "next-themes";

/**
 * Faucet modal which displays external websites that lets you send small amounts of L2 Sepolia STRK to an account address on Starknet Sepolia..
 */
export const FaucetSepolia = () => {};
