// SPDX-License-Identifier: LicenseRef-Uniteum
pragma solidity ^0.8.30;

import {SaltBounty} from "../src/SaltBounty.sol";
import {Test, console} from "forge-std/Test.sol";

contract SaltBountyUser is Test {
    string public name;

    constructor(string memory name_) {
        name = name_;
        console.log("%s born %s", name, address(this));
    }

    receive() external payable {
        console.log("%s receive %s", name, msg.value);
    }

    function make(
        SaltBounty proto,
        address deployer,
        bytes32 codeHash,
        uint160 mask,
        uint160 target,
        bytes32 salt,
        uint256 payout
    ) public returns (SaltBounty clone) {
        console.log("%s make %s wei", name, payout);
        clone = proto.make{value: payout}(deployer, codeHash, mask, target, salt);
    }

    function claim(SaltBounty clone, bytes32 salt) public returns (address vanity) {
        console.log("%s claim", name);
        vanity = clone.claim(salt);
    }

    function cancel(SaltBounty clone) public {
        console.log("%s cancel", name);
        clone.cancel();
    }
}
