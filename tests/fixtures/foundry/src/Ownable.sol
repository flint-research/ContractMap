// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IOracle {
    function latestAnswer() external view returns (int256);
}

abstract contract Ownable {
    address public owner;

    error NotOwner(address caller);

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner(msg.sender);
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function transferOwnership(address newOwner) public virtual onlyOwner {
        owner = newOwner;
    }
}
