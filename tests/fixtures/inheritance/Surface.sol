// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

abstract contract Owned {
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "!owner");
        _;
    }

    function transferOwnership(address newOwner) public virtual onlyOwner {
        _setOwner(newOwner);
    }

    function _setOwner(address newOwner) internal virtual {
        owner = newOwner;
    }
}

abstract contract Upgradeable {
    address public implementation;

    function upgradeTo(address newImplementation) external {
        _authorizeUpgrade(newImplementation);
        implementation = newImplementation;
    }

    function _authorizeUpgrade(address newImplementation) internal virtual;
}

// The guard lives in the override of the hook.
contract Safe is Owned, Upgradeable {
    function _authorizeUpgrade(address) internal override onlyOwner {}
}

// Same shape, but the override forgot the guard: anyone can upgrade.
contract Unsafe is Owned, Upgradeable {
    function _authorizeUpgrade(address) internal override {}
}

contract Helper is Owned {
    function _onlyOwner() internal view {
        require(msg.sender == owner, "!owner");
    }

    function sweep() external {
        _onlyOwner();
    }

    // Bug: anyone becomes owner.
    function claim(address newOwner) external {
        _setOwner(newOwner);
    }

    // Bug: anyone makes this contract call anything.
    function run(address target, bytes calldata data) external {
        (bool ok,) = target.call{value: 0}(data);
        require(ok);
    }
}

contract TwoStep is Owned {
    address public pendingOwner;

    function _setOwner(address newOwner) internal override {
        pendingOwner = address(0);
        super._setOwner(newOwner);
    }
}
