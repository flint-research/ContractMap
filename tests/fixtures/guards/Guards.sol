// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Guards {
    address public owner;
    address public governance;
    mapping(address => bool) public isAdmin;
    function _msgSender() internal view returns (address) { return msg.sender; }
    function getOwner() public view returns (address) { return owner; }
    function viaMsgSender(uint256) external { require(_msgSender() == governance, "!gov"); }
    function viaOwnerCall(uint256) external { require(msg.sender == getOwner(), "!owner"); }
    function viaMapping(uint256) external { require(isAdmin[msg.sender], "!admin"); }
    function viaRevert(uint256) external { if (msg.sender != owner) revert(); }
    function viaAddressCast(uint256) external { require(address(msg.sender) == owner); }
    function setFee(uint256) external {}
    modifier auth() { require(isAdmin[msg.sender]); _; }
    function viaAuthModifier(uint256) external auth {}
    mapping(address => bool) public operators;
    function registerOperator() external { operators[msg.sender] = true; }
    function viaIfRevert(uint256) external { if (!operators[msg.sender]) revert(); }
    address public pendingOwner;
    // `address sender = _msgSender();` then comparing `sender`.
    function viaAlias() external { address sender = _msgSender(); require(sender == pendingOwner); }
    function isAuthorized(address, bytes4) internal pure returns (bool) { return true; }
    // solmate Auth style.
    function viaAuthCall() external { require(isAuthorized(msg.sender, msg.sig)); }
    function hasRole(bytes32, address) internal pure returns (bool) { return true; }
    // Asking about another account is a lookup, not a guard.
    function grantIfMissing(address account) external { if (!hasRole(0, account)) { owner = account; } }
}
