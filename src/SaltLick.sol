// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/**
 * @title SaltLick
 * @notice On-chain escrow that pays an ETH bounty to whoever finds a
 *         CREATE2 salt producing a vanity address for a given bytecode.
 * @dev A poster locks ETH against an initcode hash and an address
 *      mask/target pair. A claimant submits a salt together with the
 *      initcode, and SaltLick checks the hash matches the commitment,
 *      verifies the resulting CREATE2 address satisfies
 *      `(address & mask) == target`, performs the deployment, and
 *      forwards the reward to the claimant.
 *
 *      The bounty stores only the codeHash, so posters do not have to
 *      publish their bytecode on-chain ahead of deployment and do not
 *      pay to store kilobytes of initcode.
 *
 *      The salt's first 20 bytes must equal `msg.sender`. An attacker who
 *      copies a pending salt from the mempool cannot reuse it: their
 *      `msg.sender` would not match the embedded address and the call
 *      reverts with `InvalidSalt`. This mirrors the front-running guard
 *      Uniswap used for the v4 PoolManager deployment bounty.
 */
contract SaltLick {
    struct Bounty {
        address poster;
        uint256 reward;
        uint160 mask;
        uint160 target;
        bytes32 codeHash;
    }

    uint256 public nextId;
    mapping(uint256 => Bounty) private _bounties;

    event Posted(
        uint256 indexed id, address indexed poster, uint256 reward, uint160 mask, uint160 target, bytes32 codeHash
    );
    event ToppedUp(uint256 indexed id, address indexed from, uint256 amount);
    event Cancelled(uint256 indexed id, uint256 refund);
    event Claimed(uint256 indexed id, address indexed claimant, address deployed, uint256 reward);

    error NoReward();
    error UnknownBounty();
    error NotPoster();
    error InvalidSalt();
    error InvalidInitCode();
    error InvalidAddress();
    error TransferFailed();
    error DeployFailed();

    /**
     * @notice Post a new bounty, locking `msg.value` ETH against the given
     *         initcode hash and address criteria.
     * @param codeHash keccak256 of the contract creation bytecode the
     *                 claimant must later supply.
     * @param mask Bitmask selecting which address bits are constrained.
     * @param target Required values for the masked bits; a salt qualifies
     *               when `(uint160(deployed) & mask) == target`.
     * @return id Identifier of the new bounty.
     */
    function post(bytes32 codeHash, uint160 mask, uint160 target) external payable returns (uint256 id) {
        if (msg.value == 0) revert NoReward();

        id = nextId++;
        Bounty storage b = _bounties[id];
        b.poster = msg.sender;
        b.reward = msg.value;
        b.mask = mask;
        b.target = target;
        b.codeHash = codeHash;

        emit Posted(id, msg.sender, msg.value, mask, target, codeHash);
    }

    /**
     * @notice Add `msg.value` ETH to an existing bounty's reward.
     * @param id Bounty identifier.
     */
    function topUp(uint256 id) external payable {
        if (msg.value == 0) revert NoReward();
        Bounty storage b = _bounties[id];
        if (b.poster == address(0)) revert UnknownBounty();
        b.reward += msg.value;
        emit ToppedUp(id, msg.sender, msg.value);
    }

    /**
     * @notice Cancel a bounty and refund its reward to the poster.
     * @param id Bounty identifier.
     */
    function cancel(uint256 id) external {
        Bounty memory b = _bounties[id];
        if (b.poster == address(0)) revert UnknownBounty();
        if (b.poster != msg.sender) revert NotPoster();

        delete _bounties[id];

        (bool ok,) = b.poster.call{value: b.reward}("");
        if (!ok) revert TransferFailed();

        emit Cancelled(id, b.reward);
    }

    /**
     * @notice Claim a bounty by submitting a salt and the initcode whose
     *         CREATE2 address qualifies. The first 20 bytes of `salt`
     *         must equal `msg.sender`, and `keccak256(initCode)` must
     *         equal the bounty's committed codeHash. SaltLick deploys
     *         the contract and forwards the reward to the caller.
     * @param id Bounty identifier.
     * @param salt CREATE2 salt; high 20 bytes must equal `msg.sender`.
     * @param initCode Contract creation bytecode (constructor args appended).
     * @return deployed Address of the newly deployed contract.
     */
    function claim(uint256 id, bytes32 salt, bytes calldata initCode) external returns (address deployed) {
        address claimant;
        assembly {
            claimant := shr(96, salt)
        }
        if (claimant != msg.sender) revert InvalidSalt();

        Bounty memory b = _bounties[id];
        if (b.poster == address(0)) revert UnknownBounty();

        bytes32 codeHash;
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            calldatacopy(ptr, initCode.offset, initCode.length)
            codeHash := keccak256(ptr, initCode.length)
        }
        if (codeHash != b.codeHash) revert InvalidInitCode();

        deployed = _create2Address(salt, codeHash);
        if ((uint160(deployed) & b.mask) != b.target) revert InvalidAddress();

        delete _bounties[id];

        address actual;
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            calldatacopy(ptr, initCode.offset, initCode.length)
            actual := create2(0, ptr, initCode.length, salt)
        }
        if (actual != deployed) revert DeployFailed();

        (bool ok,) = msg.sender.call{value: b.reward}("");
        if (!ok) revert TransferFailed();

        emit Claimed(id, msg.sender, deployed, b.reward);
    }

    /**
     * @notice Read a bounty's full state.
     * @param id Bounty identifier.
     * @return Bounty record; `poster == address(0)` if absent.
     */
    function bounty(uint256 id) external view returns (Bounty memory) {
        return _bounties[id];
    }

    function _create2Address(bytes32 salt, bytes32 codeHash) internal view returns (address) {
        return address(uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), address(this), salt, codeHash)))));
    }
}
