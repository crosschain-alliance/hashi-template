// This setup uses Hardhat Ignition to manage smart contract deployments.
// Learn more about it at https://hardhat.org/ignition

const { buildModule } = require("@nomicfoundation/hardhat-ignition/modules");
require("dotenv").config();

const HASHI_PROVER_ADDRESS = process.env.HASHI_PROVER_ADDRESS;
const MOCK_ERC20_ADDRESS = process.env.MOCK_ERC20_ADDRESS;
const CHAIN_ID = process.env.CHAIN_ID;

module.exports = buildModule("MockERC20ProverModule", (m) => {
  const hashiProver = m.getParameter("hashiProver", HASHI_PROVER_ADDRESS);
  const mockERC20 = m.getParameter("mockERC20", MOCK_ERC20_ADDRESS);
  const chainID = m.getParameter("chainID", CHAIN_ID);
  const mockERC20Prover = m.contract("MockERC20Prover", [
    hashiProver,
    mockERC20,
    chainID,
  ]);

  return { mockERC20Prover };
});
