// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Ownable} from "./Ownable.sol";

library Fees {
    function applyFee(uint256 amount, uint256 bps) internal pure returns (uint256) {
        return (amount * bps) / 10_000;
    }
}

contract Vault is Ownable {
    using Fees for uint256;

    error InsufficientBalance();
    error Paused();

    event FeeChanged(uint256 previous, uint256 updated);
    event Deposited(address indexed account, uint256 amount);

    uint256 public feeBps;
    bool public paused;
    mapping(address => uint256) public balances;

    constructor(uint256 initialFee) {
        feeBps = initialFee;
    }

    receive() external payable {
        deposit();
    }

    function deposit() public payable {
        if (paused) revert Paused();
        balances[msg.sender] += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    function withdraw(uint256 amount) external {
        if (balances[msg.sender] < amount) revert InsufficientBalance();
        balances[msg.sender] -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
    }

    function setFee(uint256 newFee) external onlyOwner {
        emit FeeChanged(feeBps, newFee);
        feeBps = newFee;
    }

    function pause() external onlyOwner {
        paused = true;
    }

    function feeOn(uint256 amount) external view returns (uint256) {
        return amount.applyFee(feeBps);
    }
}
