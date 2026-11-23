// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Ownable} from "./Ownable.sol";

contract Roles {
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    mapping(bytes32 => mapping(address => bool)) private _roles;

    modifier onlyRole(bytes32 role) {
        require(_roles[role][msg.sender], "missing role");
        _;
    }

    function grantRole(bytes32 role, address account) external onlyRole(role) {
        _roles[role][account] = true;
    }

    function mint(address to, uint256 amount) external onlyRole(MINTER_ROLE) {
        _mint(to, amount);
    }

    function pause() external onlyRole(PAUSER_ROLE) {}

    function _mint(address, uint256) internal {}
}

contract Upgradable is Ownable {
    address public implementation;
    address public admin;

    function upgradeTo(address next) external onlyOwner {
        implementation = next;
    }

    function destroy() external {
        selfdestruct(payable(owner));
    }
}
