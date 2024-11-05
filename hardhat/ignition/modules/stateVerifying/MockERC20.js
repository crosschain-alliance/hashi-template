// This setup uses Hardhat Ignition to manage smart contract deployments.
// Learn more about it at https://hardhat.org/ignition

const { buildModule } = require("@nomicfoundation/hardhat-ignition/modules");
require("dotenv").config();

module.exports = buildModule("MockContractModule", (m) => {
  const mockERC20 = m.contract("MockERC20", ["MockERC20", "MER", BigInt(1e25)]);

  return { mockERC20 };
});
