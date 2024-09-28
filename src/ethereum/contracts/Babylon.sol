//SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Address.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "./Nomic.sol";

contract Babylon is ReentrancyGuard {
    using SafeERC20 for IERC20;

    bytes32 public immutable state_id;
    address public immutable state_tokenContract;
    address public immutable state_nomicContract;

    uint256 public state_delegations = 0;
    mapping(uint256 => address) public state_owners;

    function stake(
        uint256 amount,
        bytes32 finalityProvider,
        uint16 stakingPeriod,
        uint16 unbondingPeriod
    ) external returns (uint256) {
        IERC20(state_tokenContract).safeTransferFrom(
            msg.sender,
            address(this),
            amount
        );

        string memory dest = string.concat(
            '{"type":"stake","owner":"',
            Strings.toHexString(uint256(uint160(msg.sender)), 20),
            '","finality_provider":"',
            Strings.toHexString(uint256(finalityProvider), 32),
            '","staking_period":',
            Strings.toString(stakingPeriod),
            ',"unbonding_period":',
            Strings.toString(unbondingPeriod),
            "}"
        );

        Nomic(state_nomicContract).sendToNomic(
            state_tokenContract,
            dest,
            amount
        );

        uint256 index = state_delegations;
        state_owners[index] = msg.sender;
        state_delegations += 1;
        return index;
    }

    function unstake(uint256 index) external {
        require(index <= state_delegations, "Invalid index");
        require(
            state_owners[index] == msg.sender,
            "Not the owner of the delegation"
        );

        string memory dest = string.concat(
            '{"type":"unstake","index":"',
            Strings.toString(index),
            "}"
        );

        Nomic(state_nomicContract).sendToNomic(state_tokenContract, dest, 0);
    }

    constructor(bytes32 _id, address _tokenContract, address _nomicContract) {
        state_id = _id;
        state_tokenContract = _tokenContract;
        state_nomicContract = _nomicContract;

        IERC20(_tokenContract).approve(_nomicContract, type(uint256).max);
    }
}
