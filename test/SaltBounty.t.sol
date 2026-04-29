// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {SaltBounty} from "../src/SaltBounty.sol";
import {SaltBountyUser} from "./SaltBountyUser.sol";
import {BaseTest} from "crucible/test/Base.t.sol";

/**
 * @notice Tests for {SaltBounty.claim}. Salts are pre-mined off-chain by
 *         saltminer so each test is deterministic and runs in milliseconds
 *         instead of doing live keccak search inside Foundry.
 *
 *         Fixture parameters common to all tests:
 *           deployer = 0x4e59…4956C  (Arachnid CREATE2 deployer)
 *           initCodeHash = keccak256("")
 *           claimant = 0xE396…26da   (encoded into salt's high 20 bytes
 *                                     for fixtures B and C)
 */
contract SaltBountyTest is BaseTest {
    address constant DEPLOYER = 0x4e59b44847b379578588920cA78FbF26c0B4956C;
    bytes32 constant INIT_CODE_HASH = 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470;
    address constant CLAIMANT = 0xE396da99091B535B65384914B178b9264c7426da;
    uint256 constant BOUNTY = 1 ether;

    SaltBounty public proto;
    SaltBountyUser public owen; // proto owner — collects the 10% fee
    SaltBountyUser public alex; // poster — funds the bounty
    SaltBountyUser public beck; // claimant — submits the salt

    function setUp() public override {
        super.setUp();
        owen = new SaltBountyUser("owen");
        alex = new SaltBountyUser("alex");
        beck = new SaltBountyUser("beck");
        proto = new SaltBounty(address(owen));
        vm.deal(address(alex), 10 ether);
    }

    /**
     * @notice Fixture A — `salt` high 20 bytes are zero, so `claim`
     *         falls back to paying `msg.sender` (beck).
     */
    function test_Claim_FallbackToSender() public {
        uint160 mask = 0xff;
        uint160 target = 0;
        bytes32 salt = bytes32(uint256(0x15));
        address expectedVanity = 0xcB33dBA50bb85F96eBD683a40b118825A6B85200;

        SaltBounty clone = alex.make(proto, DEPLOYER, INIT_CODE_HASH, mask, target, bytes32(0), BOUNTY);

        uint256 beckBefore = address(beck).balance;
        uint256 owenBefore = address(owen).balance;

        address vanity = beck.claim(clone, salt);

        assertEq(vanity, expectedVanity, "vanity address");
        assertEq(address(beck).balance - beckBefore, BOUNTY * 9 / 10, "beck payout");
        assertEq(address(owen).balance - owenBefore, BOUNTY / 10, "owen fee");
        assertEq(address(clone).balance, 0, "clone drained");
        assertEq(clone.winningSalt(), salt, "winningSalt recorded");
    }

    /**
     * @notice Fixture B — salt encodes CLAIMANT in its high 20 bytes,
     *         so the payout is paid there regardless of who calls
     *         {claim}. beck submits, but CLAIMANT gets paid.
     */
    function test_Claim_PaysBakedClaimant() public {
        uint160 mask = 0xff;
        uint160 target = 0;
        bytes32 salt = 0xE396da99091B535B65384914B178b9264c7426da000000000000000000000b5e;
        address expectedVanity = 0xF7674Af795Bdf7fB7f15559da59a2190d24f3E00;

        SaltBounty clone = alex.make(proto, DEPLOYER, INIT_CODE_HASH, mask, target, bytes32(0), BOUNTY);

        uint256 claimantBefore = CLAIMANT.balance;
        uint256 beckBefore = address(beck).balance;
        uint256 owenBefore = address(owen).balance;

        address vanity = beck.claim(clone, salt);

        assertEq(vanity, expectedVanity, "vanity address");
        assertEq(CLAIMANT.balance - claimantBefore, BOUNTY * 9 / 10, "baked claimant payout");
        assertEq(address(beck).balance, beckBefore, "beck unpaid");
        assertEq(address(owen).balance - owenBefore, BOUNTY / 10, "owen fee");
    }

    /**
     * @notice Fixture C — non-trivial mask (last 16 bits zero). Same
     *         claimant-encoding pattern as B; this fixture is also the
     *         source for the {InvalidSalt} perturbation test below.
     */
    function test_Claim_HarderMask() public {
        uint160 mask = 0xffff;
        uint160 target = 0;
        bytes32 salt = 0xE396da99091B535B65384914B178b9264c7426da000000000000000000001324;
        address expectedVanity = 0x1568e1B729B83948B920034611C5cdF310A90000;

        SaltBounty clone = alex.make(proto, DEPLOYER, INIT_CODE_HASH, mask, target, bytes32(0), BOUNTY);

        uint256 claimantBefore = CLAIMANT.balance;
        address vanity = beck.claim(clone, salt);

        assertEq(vanity, expectedVanity, "vanity address");
        assertEq(uint160(vanity) & mask, target & mask, "masked bits zero");
        assertEq(CLAIMANT.balance - claimantBefore, BOUNTY * 9 / 10, "baked claimant payout");
    }

    /**
     * @notice Fixture D — vanity has four leading and four trailing `1`
     *         nibbles. Mask covers the high and low 16 bits of the
     *         address; target encodes `0x1111` in both. Mined against
     *         the Arachnid CREATE2 deployer in ~32s on an Intel iGPU.
     */
    function test_Claim_LeadingAndTrailingOnes() public {
        uint160 mask = uint160(0x1111000000000000000000000000000000001111);
        uint160 target = uint160(0x1111111111111111111111111111111111111111);
        bytes32 salt = 0xE396da99091B535B65384914B178b9264c7426da0000000000000000822af95a;
        address expectedVanity = 0x1111BDaf47b4EcB87BE478743093a3639dA11111;

        SaltBounty clone = alex.make(proto, DEPLOYER, INIT_CODE_HASH, mask, target, bytes32(0), BOUNTY);

        uint256 claimantBefore = CLAIMANT.balance;
        address vanity = beck.claim(clone, salt);

        assertEq(vanity, expectedVanity, "vanity address");
        assertEq(uint160(vanity) >> 144, 0x1111, "leading 1111");
        assertEq(uint160(vanity) & 0xffff, 0x1111, "trailing 1111");
        assertEq(CLAIMANT.balance - claimantBefore, BOUNTY * 9 / 10, "baked claimant payout");
    }

    /**
     * @notice Perturb fixture C's salt by 1 — the resulting vanity no
     *         longer satisfies (mask, target), so {claim} reverts with
     *         {InvalidSalt}.
     */
    function test_Claim_RevertsOnInvalidSalt() public {
        uint160 mask = 0xffff;
        uint160 target = 0;
        bytes32 validSalt = 0xE396da99091B535B65384914B178b9264c7426da000000000000000000001324;
        bytes32 badSalt = bytes32(uint256(validSalt) + 1);

        SaltBounty clone = alex.make(proto, DEPLOYER, INIT_CODE_HASH, mask, target, bytes32(0), BOUNTY);

        vm.expectRevert(abi.encodeWithSelector(SaltBounty.InvalidSalt.selector, badSalt));
        beck.claim(clone, badSalt);
    }

    /**
     * @notice After a successful claim the clone's `winningSalt` is set;
     *         a second {claim} reverts with {AlreadyWon} regardless of
     *         whether the resubmitted salt is valid.
     */
    function test_Claim_RevertsOnAlreadyWon() public {
        uint160 mask = 0xff;
        uint160 target = 0;
        bytes32 salt = bytes32(uint256(0x15));

        SaltBounty clone = alex.make(proto, DEPLOYER, INIT_CODE_HASH, mask, target, bytes32(0), BOUNTY);
        beck.claim(clone, salt);

        vm.expectRevert(SaltBounty.AlreadyWon.selector);
        beck.claim(clone, salt);
    }
}
