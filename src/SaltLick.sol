// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/**
 * @title SaltLick
 * @notice On-chain escrow that pays an ETH bounty to whoever finds a
 *         CREATE2 salt producing a vanity address for a given bytecode.
 * @dev A poster locks ETH against a contract's initcode and an address
 *      mask/target pair. A claimant submits a salt whose CREATE2 address
 *      satisfies `(address & mask) == target`. SaltLick performs the
 *      CREATE2 deployment and forwards the reward to the claimant.
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
        bytes initCode;
    }

    uint256 public nextId;
    mapping(uint256 => Bounty) private _bounties;

    event Posted(
        uint256 indexed id, address indexed poster, uint256 reward, uint160 mask, uint160 target, bytes initCode
    );
    event ToppedUp(uint256 indexed id, address indexed from, uint256 amount);
    event Cancelled(uint256 indexed id, uint256 refund);
    event Claimed(uint256 indexed id, address indexed claimant, address deployed, uint256 reward);

    error EmptyInitCode();
    error NoReward();
    error UnknownBounty();
    error NotPoster();
    error InvalidSalt();
    error InvalidAddress();
    error TransferFailed();
    error DeployFailed();

    /**
     * @notice Post a new bounty, locking `msg.value` ETH against the given
     *         initcode and address criteria.
     * @param initCode Contract creation bytecode (constructor args appended).
     * @param mask Bitmask selecting which address bits are constrained.
     * @param target Required values for the masked bits; a salt qualifies
     *               when `(uint160(deployed) & mask) == target`.
     * @return id Identifier of the new bounty.
     */
    function post(bytes calldata initCode, uint160 mask, uint160 target) external payable returns (uint256 id) {
        if (initCode.length == 0) revert EmptyInitCode();
        if (msg.value == 0) revert NoReward();

        id = nextId++;
        Bounty storage b = _bounties[id];
        b.poster = msg.sender;
        b.reward = msg.value;
        b.mask = mask;
        b.target = target;
        b.initCode = initCode;

        emit Posted(id, msg.sender, msg.value, mask, target, initCode);
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
     * @notice Claim a bounty by submitting a salt that produces a qualifying
     *         CREATE2 address. The first 20 bytes of `salt` must equal
     *         `msg.sender`. SaltLick deploys the contract and forwards the
     *         reward to the caller.
     * @param id Bounty identifier.
     * @param salt CREATE2 salt; high 20 bytes must equal `msg.sender`.
     * @return deployed Address of the newly deployed contract.
     */
    function claim(uint256 id, bytes32 salt) external returns (address deployed) {
        address claimant;
        assembly {
            claimant := shr(96, salt)
        }
        if (claimant != msg.sender) revert InvalidSalt();

        Bounty memory b = _bounties[id];
        if (b.poster == address(0)) revert UnknownBounty();

        bytes memory initCode = b.initCode;
        bytes32 codeHash;
        assembly ("memory-safe") {
            codeHash := keccak256(add(initCode, 0x20), mload(initCode))
        }
        deployed = _create2Address(salt, codeHash);
        if ((uint160(deployed) & b.mask) != b.target) revert InvalidAddress();

        delete _bounties[id];

        address actual;
        assembly ("memory-safe") {
            actual := create2(0, add(initCode, 0x20), mload(initCode), salt)
        }
        if (actual != deployed) revert DeployFailed();

        (bool ok,) = msg.sender.call{value: b.reward}("");
        if (!ok) revert TransferFailed();

        emit Claimed(id, msg.sender, deployed, b.reward);
    }

    /**
     * @notice Read a bounty's full state, including its initcode.
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
