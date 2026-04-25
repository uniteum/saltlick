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
 *      A bounty's CREATE2 deployment uses the clone's address as the
 *      deployer, so a claimant mines salts against that clone's address.
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

    bytes32 public codeHash;
    uint160 public mask;
    uint160 public target;

    event Make(
        SaltLick indexed clone, address indexed poster, uint256 reward, uint160 mask, uint160 target, bytes32 codeHash
    );
    event TopUp(SaltLick indexed clone, address indexed from, uint256 amount);
    event Cancel(uint256 refund);
    event Claim(address indexed claimant, address deployed, uint256 reward);

    error NoReward();
    error NotPosted();
    error InvalidSalt();
    error InvalidInitCode();
    error InvalidAddress();
    error TransferFailed();
    error DeployFailed();
    error Unauthorized();

    constructor(address owner_) Ownable(owner_) {
        PROTO = this;
    }

    receive() external payable {
        if (this == PROTO) revert();
    }

    /**
     * @notice Predict the deterministic clone address for a bounty.
     * @param poster Address that will own the bounty clone.
     * @param codeHash_ keccak256 of the contract creation bytecode.
     * @param mask_ Bitmask selecting which address bits are constrained.
     * @param target_ Required values for the masked bits.
     * @param salt User-supplied disambiguator allowing the same poster to
     *             post multiple bounties with otherwise identical params.
     * @return exists True if the clone is already deployed.
     * @return home The deterministic clone address.
     * @return create2Salt The CREATE2 salt used to derive `home`.
     */
    function made(address poster, bytes32 codeHash_, uint160 mask_, uint160 target_, bytes32 salt)
        public
        view
        returns (bool exists, address home, bytes32 create2Salt)
    {
        create2Salt = keccak256(abi.encode(poster, codeHash_, mask_, target_)) ^ salt;
        home = Clones.predictDeterministicAddress(address(PROTO), create2Salt, address(PROTO));
        exists = home.code.length > 0;
    }

    /**
     * @notice Post a new bounty (or top up an existing one) by deploying or
     *         funding a clone keyed by `(msg.sender, codeHash, mask, target, salt)`.
     * @param codeHash_ keccak256 of the contract creation bytecode the
     *                  claimant must later supply.
     * @param mask_ Bitmask selecting which address bits are constrained.
     * @param target_ Required values for the masked bits; a salt qualifies
     *                when `(uint160(deployed) & mask) == target`.
     * @param salt User-supplied disambiguator (see {made}).
     * @return clone The bounty clone, newly deployed or already existing.
     */
    function make(bytes32 codeHash_, uint160 mask_, uint160 target_, bytes32 salt)
        external
        payable
        returns (SaltLick clone)
    {
        if (msg.value == 0) revert NoReward();
        if (this != PROTO) {
            clone = PROTO.make{value: msg.value}(codeHash_, mask_, target_, salt);
        } else {
            (bool exists, address home, bytes32 create2Salt) = made(msg.sender, codeHash_, mask_, target_, salt);
            clone = SaltLick(payable(home));
            if (exists) {
                (bool ok,) = home.call{value: msg.value}("");
                if (!ok) revert TransferFailed();
                emit TopUp(clone, msg.sender, msg.value);
            } else {
                home = Clones.cloneDeterministic(address(PROTO), create2Salt, msg.value);
                SaltLick(payable(home)).zzInit(msg.sender, codeHash_, mask_, target_);
                emit Make(clone, msg.sender, msg.value, mask_, target_, codeHash_);
            }
        }
    }

    /**
     * @notice Initializer called by PROTO on a freshly deployed clone.
     * @dev Reverts with {Unauthorized} otherwise.
     */
    function zzInit(address poster, bytes32 codeHash_, uint160 mask_, uint160 target_) public {
        if (msg.sender != address(PROTO)) revert Unauthorized();
        _transferOwnership(poster);
        codeHash = codeHash_;
        mask = mask_;
        target = target_;
    }

    /**
     * @notice Cancel the bounty and refund the reward to the poster.
     */
    function cancel() external onlyOwner {
        if (codeHash == bytes32(0)) revert NotPosted();
        uint256 refund = address(this).balance;
        delete codeHash;
        delete mask;
        delete target;
        (bool ok,) = owner().call{value: refund}("");
        if (!ok) revert TransferFailed();
        emit Cancel(refund);
    }

    /**
     * @notice Claim the bounty by submitting a salt and the initcode whose
     *         CREATE2 address qualifies. The first 20 bytes of `salt` must
     *         equal `msg.sender`, and `keccak256(initCode)` must equal the
     *         bounty's committed codeHash. The clone deploys the contract
     *         and forwards its full ETH balance to the caller.
     * @param salt CREATE2 salt; high 20 bytes must equal `msg.sender`.
     * @param initCode Contract creation bytecode (constructor args appended).
     * @return deployed Address of the newly deployed contract.
     */
    function claim(bytes32 salt, bytes calldata initCode) external returns (address deployed) {
        bytes32 ch = codeHash;
        if (ch == bytes32(0)) revert NotPosted();

        address claimant;
        assembly {
            claimant := shr(96, salt)
        }
        if (claimant != msg.sender) revert InvalidSalt();

        bytes32 hash;
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            calldatacopy(ptr, initCode.offset, initCode.length)
            hash := keccak256(ptr, initCode.length)
        }
        if (hash != ch) revert InvalidInitCode();

        deployed = _create2Address(salt, hash);
        if ((uint160(deployed) & mask) != target) revert InvalidAddress();

        delete codeHash;
        delete mask;
        delete target;

        address actual;
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            calldatacopy(ptr, initCode.offset, initCode.length)
            actual := create2(0, ptr, initCode.length, salt)
        }
        if (actual != deployed) revert DeployFailed();

        uint256 paid = address(this).balance;
        (bool ok,) = msg.sender.call{value: paid}("");
        if (!ok) revert TransferFailed();

        emit Claim(msg.sender, deployed, paid);
    }

    /**
     * @notice Current ETH reward held by this clone.
     */
    function reward() external view returns (uint256) {
        return address(this).balance;
    }

    function _create2Address(bytes32 salt, bytes32 hash) internal view returns (address) {
        return address(uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), address(this), salt, hash)))));
    }
}
