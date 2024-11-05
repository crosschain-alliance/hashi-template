import axios from "axios";
import { http, createWalletClient, publicActions, parseAbiItem } from "viem";

import { gnosisChiado } from "viem/chains";
import { privateKeyToAccount } from "viem/accounts";
import ABI from "../ABI/MockERC20Prover.json" assert { type: "json" };

// This script illustrates how to read total Supply storage key of MockERC20 contract from Sepolia on Gnosis Chiado MockERC20Prover contract
const main = async () => {
  // Dev: replace the parameters
  const account = privateKeyToAccount(process.env.PRIVATE_KEY);
  const hashiProverRPC = process.env.HASHI_PROVER_RPC_URL;
  const mockERC20 = "0xB3b231614882E8ffa69eB7E37E845060456fF21b"; // sepolia
  const mockERC20Prover = "0x7D5C9C15bc2bD2eDcE54BC8c480A94d02666B514"; // chiado
  const blockNumber = 7016999; // block number that is passed from source chain to target chain using the reporter
  const ancestralBlockNumber = 7016956; // block number that you want to read the storage from
  const sourceChainID = 11155111;
  const storageKey = [
    "0x0000000000000000000000000000000000000000000000000000000000000002", // slot for total Supply on MockERC20 contract
  ];
  // create client for the chain you want to verify on
  const client = createWalletClient({
    account,
    chain: gnosisChiado,
    transport: http(),
  }).extend(publicActions);

  // fetch account/storage proof from Hashi Prover
  console.log("Fetching account & storage proof from Hashi prover...");
  const result = await axios.post(
    `http://${hashiProverRPC}:3000/v1`,
    {
      jsonrpc: "2.0",
      method: "hashi_getAccountAndStorageProof",
      params: {
        address: mockERC20,
        blockNumber,
        ancestralBlockNumber,
        chainId: sourceChainID,
        storageKeys,
      },
      id: 1,
    },
    {
      headers: {
        "Content-Type": "application/json",
      },
    }
  );
  console.log("Obtain proof result", result.data.result.proof);

  const { request } = await client.simulateContract({
    address: mockERC20Prover,
    abi: ABI.abi,
    functionName: "readTotalSupply",
    args: [result.data.result.proof],
  });

  const tx = await client.writeContract(request);

  console.log("Verified tx hash ", tx);
};

main();
