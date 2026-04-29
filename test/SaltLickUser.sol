// SPDX-License-Identifier: LicenseRef-Uniteum
pragma solidity ^0.8.30;

import {SaltLick} from "../src/SaltLick.sol";
import {Test, console} from "forge-std/Test.sol";

contract SaltLickUser is Test {
    string public name;

    constructor(string memory name_) {
        name = name_;
        console.log("%s born %s", name, address(this));
    }

    receive() external payable {
        console.log("%s receive %s", name, msg.value);
    }

    function make(
        SaltLick proto,
        address deployer,
        bytes32 codeHash,
        uint160 mask,
        uint160 target,
        bytes32 salt,
        uint256 reward
    ) public returns (SaltLick clone) {
        console.log("%s make %s wei", name, reward);
        clone = proto.make{value: reward}(deployer, codeHash, mask, target, salt);
    }

    function claim(SaltLick clone, bytes32 salt) public returns (address vanity) {
        console.log("%s claim", name);
        vanity = clone.claim(salt);
    }

    function cancel(SaltLick clone) public {
        console.log("%s cancel", name);
        clone.cancel();
    }
}
