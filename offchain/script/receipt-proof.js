import axios from "axios";
import { http, createWalletClient, publicActions } from "viem";
import { gnosisChiado } from "viem/chains";
import { privateKeyToAccount } from "viem/accounts";
import ABI from "../ABI/MockERC20Prover.json" assert { type: "json" };

// This script illustrates how to verify a Transfer event happened on MockERC20 contract from Sepolia on Gnosis Chiado MockERC20Prover contract
const main = async () => {
  // Dev: replace the parameters
  const account = privateKeyToAccount(process.env.PRIVATE_KEY);
  const hashiProverRPC = process.env.HASHI_PROVER_RPC_URL;
  const mockERC20 = "0xB3b231614882E8ffa69eB7E37E845060456fF21b"; // sepolia
  const mockERC20Prover = "0x7D5C9C15bc2bD2eDcE54BC8c480A94d02666B514"; // chiado
  const txhash =
    "0x25a6a5c138f3b5a434a3a2b5d6bf7bdf97cb700bd7515f801ecfb71f1d965e7b";
  const rlpEncodedTx =
    "0xf89b94b3b231614882e8ffa69eb7e37e845060456ff21bf863a0ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3efa000000000000000000000000067e5855aa4d5786c086b7fc6b4203a5ea50e93f8a00000000000000000000000008a11da83262eaf7c2262a65c585767e5be8dd904a00000000000000000000000000000000000000000000000008ac7230489e80000";
  const logIndex = 397;
  const blockNumber = 7016999;
  const sourceChainId = 11155111;

  // create client for the chain you want to verify on
  const client = createWalletClient({
    account,
    chain: gnosisChiado,
    transport: http(),
  }).extend(publicActions);

  // fetch account/storage proof from Hashi Prover
  console.log("Fetching event proof from Hashi prover...");
  const result = await axios.post(
    `http://${hashiProverRPC}:3000/v1`,
    {
      jsonrpc: "2.0",
      method: "hashi_getReceiptProof",
      params: {
        logIndex,
        blockNumber,
        chainId: sourceChainId,
        transactionHash: txhash,
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
    functionName: "verifyTransferEvent",
    args: [result.data.result.proof, rlpEncodedTx],
  });

  const tx = await client.writeContract(request);

  console.log("Verified tx hash ", tx);
};

main();
