// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Clones} from "clones/Clones.sol";
import {Ownable} from "ownable/Ownable.sol";

/**
 * @title SaltLick
 * @notice On-chain escrow that pays an ETH bounty to whoever finds a
 *         CREATE2 salt producing a vanity address for a given bytecode.
 * @dev SaltLick is Bitsy: a single prototype is deployed once and acts as
 *      a permissionless EIP-1167 minimal-proxy factory. Each bounty is a
 *      deterministic clone that owns its own ETH reward and stores its
 *      own (codeHash, mask, target). The poster of a bounty is the owner
 *      of its clone.
 *
 *      The poster supplies the `deployer` whose CREATE2 deployment will
 *      produce the vanity address — the contract that will actually
 *      execute the CREATE2 (a dedicated factory, an existing deployer
 *      contract, or any contract the poster controls). Claimants mine
 *      salts against that deployer.
 *      The reward is paid to the address encoded in the salt's high 20
 *      bytes; if those bytes are zero, payment falls back to
 *      `msg.sender`. Claimants should bake their payout address into the
 *      salt — this mirrors the guard Uniswap used for the v4 PoolManager
 *      deployment bounty: a mempool watcher gains nothing from copying a
 *      salt whose reward is locked to the original miner. A salt that
 *      omits this encoding can be front-run by anyone who sees the
 *      pending submission.
 *
 *      The clone stores only `codeHash`, so posters do not have to publish
 *      their bytecode on-chain ahead of deployment.
 *
 *      On {claim}, the clone pays 90% of its balance to the claimant and
 *      10% (the vig) to the prototype's owner.
 */
contract SaltLick is Ownable {
    /**
     * @notice The prototype instance used as the EIP-1167 implementation.
     */
    SaltLick public immutable proto;

    /**
     * @notice Winning salt recorded by the first successful {claim};
     *         non-zero once the bounty has been claimed.
     */
    bytes32 public winningSalt;

    /**
     * @notice Address whose CREATE2 deployments produce the vanity
     *         address this bounty pays for.
     */
    address public deployer;

    /**
     * @notice keccak256 of the contract creation bytecode the claimant
     *         must deploy at the vanity address.
     */
    bytes32 public codeHash;

    /**
     * @notice Bitmask selecting which bits of the candidate address are
     *         constrained by {target}.
     */
    uint160 public mask;

    /**
     * @notice Required values for the bits selected by {mask}; a salt
     *         qualifies when `(uint160(vanity) & mask) == (target & mask)`.
     */
    uint160 public target;

    /**
     * @notice Deploy the SaltLick prototype. This single deployment becomes
     *         the EIP-1167 implementation for every bounty clone, and its
     *         owner collects the 10% vig on each successful {claim}.
     * @param owner_ Owner of the prototype. The prototype owns no bounty
     *               itself; clones reset ownership to their poster in
     *               {zzInit}.
     */
    constructor(address owner_) Ownable(owner_) {
        proto = this;
    }

    /**
     * @notice Accept ETH top-ups to a bounty clone and emit {TopUp}.
     */
    receive() external payable {
        emit TopUp(this, msg.sender, msg.value);
    }

    /**
     * @notice Predict the deterministic clone address for a bounty.
     * @param poster Address that will own the bounty clone.
     * @param deployer_ Address that will deploy the bytecode via CREATE2;
     *                  determines the vanity address the claimant mines for.
     * @param codeHash_ keccak256 of the contract creation bytecode.
     * @param mask_ Bitmask selecting which address bits are constrained.
     * @param target_ Required values for the masked bits.
     * @param salt User-supplied disambiguator allowing the same poster to
     *             post multiple bounties with otherwise identical params.
     * @return exists True if the clone is already deployed.
     * @return home The deterministic clone address.
     * @return create2Salt The CREATE2 salt used to derive `home`.
     */
    function made(address poster, address deployer_, bytes32 codeHash_, uint160 mask_, uint160 target_, bytes32 salt)
        public
        view
        returns (bool exists, address home, bytes32 create2Salt)
    {
        create2Salt = keccak256(abi.encode(poster, deployer_, codeHash_, mask_, target_)) ^ salt;
        home = Clones.predictDeterministicAddress(address(proto), create2Salt, address(proto));
        exists = home.code.length > 0;
    }

    /**
     * @notice Post a new bounty (or top up an existing one) by deploying or
     *         funding a clone keyed by
     *         `(msg.sender, deployer, codeHash, mask, target, salt)`.
     * @dev Callable on either the prototype or a clone. Calls on a clone
     *      forward to `proto.make` with the original `msg.value` so every
     *      bounty resolves through the same factory.
     * @param deployer_ Address that will deploy the bytecode via CREATE2;
     *                  the vanity address is `keccak256(0xff, deployer_,
     *                  salt, codeHash)[12:]`.
     * @param codeHash_ keccak256 of the contract creation bytecode the
     *                  claimant mines salts against.
     * @param mask_ Bitmask selecting which address bits are constrained.
     * @param target_ Required values for the masked bits; a salt qualifies
     *                when `(uint160(vanity) & mask) == (target & mask)`.
     * @param salt User-supplied disambiguator (see {made}).
     * @return clone The bounty clone, newly deployed or already existing.
     */
    function make(address deployer_, bytes32 codeHash_, uint160 mask_, uint160 target_, bytes32 salt)
        external
        payable
        returns (SaltLick clone)
    {
        if (address(this) != address(proto)) {
            clone = proto.make{value: msg.value}(deployer_, codeHash_, mask_, target_, salt);
        } else {
            (bool exists, address home, bytes32 create2Salt) =
                made(msg.sender, deployer_, codeHash_, mask_, target_, salt);
            clone = SaltLick(payable(home));
            if (exists) {
                _pay(home, msg.value);
                emit TopUp(clone, msg.sender, msg.value);
            } else {
                home = Clones.cloneDeterministic(address(proto), create2Salt, msg.value);
                SaltLick(payable(home)).zzInit(msg.sender, deployer_, codeHash_, mask_, target_);
                emit Make(clone, msg.sender, msg.value, deployer_, codeHash_, mask_, target_);
            }
        }
    }

    /**
     * @notice Initializer called by proto on a freshly deployed clone.
     * @dev Reverts with {Unauthorized} if invoked by anyone else.
     * @param poster Account that posted the bounty; becomes the clone's
     *               owner.
     * @param deployer_ See {deployer}.
     * @param codeHash_ See {codeHash}.
     * @param mask_ See {mask}.
     * @param target_ See {target}.
     */
    function zzInit(address poster, address deployer_, bytes32 codeHash_, uint160 mask_, uint160 target_) public {
        if (msg.sender != address(proto)) revert Unauthorized();
        _transferOwnership(poster);
        deployer = deployer_;
        codeHash = codeHash_;
        mask = mask_;
        target = target_;
    }

    /**
     * @dev Send `amount` wei to `to`, bubbling the recipient's revert
     *      data verbatim if the call fails.
     */
    function _pay(address to, uint256 amount) internal {
        (bool ok, bytes memory ret) = to.call{value: amount}("");
        if (!ok) {
            // Solidity has no `revert(bytes)`; bubble the recipient's revert data verbatim.
            assembly ("memory-safe") {
                revert(add(ret, 0x20), mload(ret))
            }
        }
    }

    /**
     * @notice Cancel the bounty and refund the remaining balance to the
     *         poster.
     * @dev Restricted to the clone's owner (the original poster). Does not
     *      destroy the clone — a subsequent {make} with the same key tops
     *      up the same address.
     */
    function cancel() public onlyOwner {
        uint256 refund = address(this).balance;
        _pay(owner(), refund);
        emit Cancel(refund);
    }

    /**
     * @notice Claim the bounty by submitting a salt whose predicted CREATE2
     *         address qualifies under the bounty's mask/target. The clone
     *         splits its ETH balance: 90% (the reward) to the address
     *         encoded in the salt's high 20 bytes — falling back to
     *         `msg.sender` if those bytes are zero — and 10% (the vig) to
     *         the prototype's owner. Reverts with {AlreadyWon} if the
     *         bounty has already been claimed, or {InvalidSalt} if `salt`
     *         does not produce a qualifying address.
     * @dev Setting `winningSalt` before the external payouts is the
     *      reentrancy guard: a re-entrant {claim} hits the {AlreadyWon}
     *      check.
     * @param salt CREATE2 salt. Encode the intended payout address in the
     *             high 20 bytes to lock the reward to that address; salts
     *             without this encoding can be front-run by anyone who sees
     *             the pending submission.
     * @return vanity The qualifying CREATE2 address derived from `salt` and
     *                the bounty's committed codeHash.
     */
    function claim(bytes32 salt) external returns (address vanity) {
        if (winningSalt != bytes32(0)) revert AlreadyWon();
        winningSalt = salt;

        vanity = create2Address(deployer, salt, codeHash);
        if ((uint160(vanity) & mask) != (target & mask)) revert InvalidSalt(salt);

        uint256 payout = address(this).balance;
        uint256 vig = payout / 10;
        uint256 reward = payout - vig;
        address claimant = address(uint160(uint256(salt) >> 96));
        if (claimant == address(0)) claimant = msg.sender;
        _pay(claimant, reward);
        _pay(proto.owner(), vig);

        emit Claim(msg.sender, vanity, reward);
    }

    /**
     * @notice Compute the CREATE2 deployment address for a given deployer,
     *         salt, and creation-code hash.
     * @param deployer_ Address whose CREATE2 deployment is being predicted.
     * @param salt CREATE2 salt supplied to that deployment.
     * @param hash keccak256 of the contract creation bytecode.
     * @return The address at which `deployer_` would deploy this bytecode
     *         under `salt` via CREATE2.
     */
    function create2Address(address deployer_, bytes32 salt, bytes32 hash) public pure returns (address) {
        return address(uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), deployer_, salt, hash)))));
    }

    /**
     * @notice Emitted by {make} when a new bounty clone is deployed and
     *         funded.
     */
    event Make(
        SaltLick indexed clone,
        address indexed poster,
        uint256 reward,
        address deployer,
        bytes32 codeHash,
        uint160 mask,
        uint160 target
    );

    /**
     * @notice Emitted when ETH is added to a bounty clone, either by
     *         {make} on an existing bounty or via {receive}.
     */
    event TopUp(SaltLick indexed clone, address indexed from, uint256 amount);

    /**
     * @notice Emitted when the poster cancels a bounty and withdraws the
     *         remaining reward.
     */
    event Cancel(uint256 refund);

    /**
     * @notice Emitted when a winning salt is accepted and the reward is
     *         paid out. `claimant` is the submitter (`msg.sender`); the
     *         actual recipient is the salt's high-20 encoding, falling
     *         back to `claimant` if those bytes are zero. `reward` is the
     *         post-vig amount (90% of the clone's balance at claim time).
     */
    event Claim(address indexed claimant, address vanity, uint256 reward);

    /**
     * @notice Thrown by {claim} when the bounty has already been claimed.
     */
    error AlreadyWon();

    /**
     * @notice Thrown by {claim} when `salt` does not produce an address
     *         satisfying `(uint160(vanity) & mask) == (target & mask)`.
     */
    error InvalidSalt(bytes32 salt);

    /**
     * @notice Thrown by {zzInit} when the caller is not the prototype.
     */
    error Unauthorized();
}
