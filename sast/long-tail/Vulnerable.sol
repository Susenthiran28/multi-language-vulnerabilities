// SPDX-License-Identifier: UNLICENSED
// File:    Vulnerable.sol
// Purpose: SAST fixture (Solidity). delegatecall to an arbitrary target,
//          selfdestruct, tx.origin auth, timestamp dependence, reentrancy.
// Author:  Vigilnz Security Engineering
// Date:    2026-10-16
// Expected rules: solidity-delegatecall, solidity-selfdestruct,
//   solidity-tx-origin, solidity-block-timestamp

pragma solidity ^0.8.0;

contract Vulnerable {
    address public owner;
    mapping(address => uint256) public balances;

    constructor() {
        owner = msg.sender;
    }

    // SWC-115: authorization on tx.origin is phishable
    modifier onlyOwner() {
        require(tx.origin == owner, "not owner");
        _;
    }

    // SWC-112: delegatecall into a caller-supplied target
    function proxyCall(address target, bytes calldata data) external onlyOwner {
        (bool ok, ) = target.delegatecall(data);
        require(ok, "call failed");
    }

    // SWC-107: state updated after the external call
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        balances[msg.sender] -= amount;
    }

    // SWC-116: miner-influenced randomness and expiry
    function isExpired(uint256 deadline) public view returns (bool) {
        return block.timestamp > deadline;
    }

    function lottery() public view returns (uint256) {
        return uint256(keccak256(abi.encodePacked(block.timestamp, block.difficulty))) % 100;
    }

    // SWC-106: unprotected contract teardown
    function kill() external onlyOwner {
        selfdestruct(payable(owner));
    }

    receive() external payable {
        balances[msg.sender] += msg.value;
    }
}
