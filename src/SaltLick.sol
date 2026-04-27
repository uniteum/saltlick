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
 *      produce the vanity address — typically the contract that will
 *      actually deploy the bytecode (a factory, the poster's own EOA, or
 *      any other address). Claimants mine salts against that deployer.
 *      The salt's first 20 bytes must equal `msg.sender` to prevent a
 *      mempool watcher from copying a pending salt and front-running the
 *      claim, mirroring the guard Uniswap used for the v4 PoolManager
 *      deployment bounty.
 *
 *      The clone stores only `codeHash`, so posters do not have to publish
 *      their bytecode on-chain ahead of deployment.
 */
contract SaltLick is Ownable {
    /// @notice The prototype instance used as the EIP-1167 implementation.
    SaltLick public immutable PROTO;

    bytes32 public winningSalt;
    address public deployer;
    bytes32 public codeHash;
    uint160 public mask;
    uint160 public target;

    constructor(address owner_) Ownable(owner_) {
        PROTO = this;
    }

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
        home = Clones.predictDeterministicAddress(address(PROTO), create2Salt, address(PROTO));
        exists = home.code.length > 0;
    }

    /**
     * @notice Post a new bounty (or top up an existing one) by deploying or
     *         funding a clone keyed by
     *         `(msg.sender, deployer, codeHash, mask, target, salt)`.
     * @param deployer_ Address that will deploy the bytecode via CREATE2;
     *                  the vanity address is `keccak256(0xff, deployer_,
     *                  salt, codeHash)[12:]`.
     * @param codeHash_ keccak256 of the contract creation bytecode the
     *                  claimant mines salts against.
     * @param mask_ Bitmask selecting which address bits are constrained.
     * @param target_ Required values for the masked bits; a salt qualifies
     *                when `(uint160(vanity) & mask) == target`.
     * @param salt User-supplied disambiguator (see {made}).
     * @return clone The bounty clone, newly deployed or already existing.
     */
    function make(address deployer_, bytes32 codeHash_, uint160 mask_, uint160 target_, bytes32 salt)
        external
        payable
        returns (SaltLick clone)
    {
        if (msg.value == 0) revert NoReward();
        if (address(this) != address(PROTO)) {
            clone = PROTO.make{value: msg.value}(deployer_, codeHash_, mask_, target_, salt);
        } else {
            (bool exists, address home, bytes32 create2Salt) =
                made(msg.sender, deployer_, codeHash_, mask_, target_, salt);
            clone = SaltLick(payable(home));
            if (exists) {
                (bool ok,) = home.call{value: msg.value}("");
                ok;
                emit TopUp(clone, msg.sender, msg.value);
            } else {
                home = Clones.cloneDeterministic(address(PROTO), create2Salt, msg.value);
                SaltLick(payable(home)).zzInit(msg.sender, deployer_, codeHash_, mask_, target_);
                emit Make(clone, msg.sender, msg.value, deployer_, mask_, target_, codeHash_);
            }
        }
    }

    /**
     * @notice Initializer called by PROTO on a freshly deployed clone.
     * @dev Reverts with {Unauthorized} otherwise.
     */
    function zzInit(address poster, address deployer_, bytes32 codeHash_, uint160 mask_, uint160 target_) public {
        if (msg.sender != address(PROTO)) revert Unauthorized();
        _transferOwnership(poster);
        deployer = deployer_;
        codeHash = codeHash_;
        mask = mask_;
        target = target_;
    }

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
     * @notice Cancel the bounty and refund the reward to the poster.
     */
    function cancel() public onlyOwner {
        uint256 refund = address(this).balance;
        _pay(owner(), refund);
        emit Cancel(refund);
    }

    /**
     * @notice Claim the bounty by submitting a salt whose predicted CREATE2
     *         address qualifies under the bounty's mask/target. The first
     *         20 bytes of `salt` must equal `msg.sender`. The clone forwards
     *         its full ETH balance to the caller.
     * @param salt CREATE2 salt; high 20 bytes must equal `msg.sender`.
     * @return vanity The qualifying CREATE2 address derived from `salt` and
     *                the bounty's committed codeHash.
     */
    function claim(bytes32 salt) external returns (address vanity) {
        if (winningSalt != bytes32(0)) revert AlreadyWon();
        winningSalt = salt;

        vanity = _create2Address(deployer, salt, codeHash);
        if ((uint160(vanity) & mask) != (target & mask)) revert InvalidAddress();

        uint256 reward = address(this).balance;
        address claimant = address(uint160(uint256(salt) >> 96));
        if (claimant == address(0)) claimant = msg.sender;
        _pay(claimant, address(this).balance);

        emit Claim(msg.sender, vanity, reward);
    }

    function _create2Address(address deployer_, bytes32 salt, bytes32 hash) internal pure returns (address) {
        return address(uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), deployer_, salt, hash)))));
    }

    event Make(
        SaltLick indexed clone,
        address indexed poster,
        uint256 reward,
        address deployer,
        uint160 mask,
        uint160 target,
        bytes32 codeHash
    );
    event TopUp(SaltLick indexed clone, address indexed from, uint256 amount);
    event Cancel(uint256 refund);
    event Claim(address indexed claimant, address vanity, uint256 reward);

    error NoReward();
    error AlreadyWon();
    error InvalidSalt();
    error InvalidAddress();
    error TransferFailed();
    error Unauthorized();
}
