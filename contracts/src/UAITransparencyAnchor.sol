// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {Roles} from "./Roles.sol";

/// @title Merkle checkpoint anchoring and epoch tracking.
/// @notice Anchoring is a durability layer, not an admission gate (§12.4): the
///         log stays usable when this chain is unreachable. What anchoring adds
///         is that a log operator cannot quietly rewrite history afterwards,
///         because the roots are already somewhere they do not control.
contract UAITransparencyAnchor is Roles {
    struct Checkpoint {
        bytes32 root;
        uint64 size;
        uint64 anchoredAt;
        uint32 witnessCount;
    }

    /// @dev Checkpoints are append-only and strictly growing. A log that shrank
    ///      would be a log that dropped entries, which is the one thing a
    ///      transparency log must make impossible to do quietly.
    mapping(uint64 => Checkpoint) private _checkpoints;
    uint64 public latestSize;
    uint64 public epoch;
    mapping(uint64 => bytes32) public epochRoot;
    mapping(uint64 => bytes32) public publicAnchorTx;

    event CheckpointAnchored(bytes32 indexed root, uint64 size, uint32 witnessCount);
    event EpochClosed(uint64 indexed epoch, bytes32 root);
    event PublicAnchorPublished(uint64 indexed epoch, bytes32 root, bytes32 externalTxId);

    error NotGrowing(uint64 have, uint64 got);
    error EmptyRoot();
    error UnderWitnessed(uint32 have, uint32 needed);
    error UnknownEpoch(uint64 epoch);
    error AlreadyPublished(uint64 epoch);

    /// @dev The minimum co-signature count. Stored rather than constant so the
    ///      witness requirement can be raised as the witness set grows.
    uint32 public minWitnesses;

    constructor(address admin, uint32 minWitnesses_) Roles(admin) {
        minWitnesses = minWitnesses_;
    }

    function setMinWitnesses(uint32 n) external onlyRole(ROLE_ADMIN) {
        minWitnesses = n;
    }

    /// @notice Anchor a witnessed checkpoint.
    /// @dev Witness signatures are verified off-chain by the ledger writer and
    ///      their COUNT is recorded here. Verifying dozens of signatures on
    ///      chain would cost more than the property is worth, and the
    ///      signatures themselves are in the log where anybody can check them;
    ///      what this contract adds is that the count and the root cannot be
    ///      changed after the fact.
    function anchor(bytes32 root, uint64 size, uint32 witnessCount) external onlyRole(ROLE_WRITER) {
        if (root == bytes32(0)) revert EmptyRoot();
        if (size <= latestSize) revert NotGrowing(latestSize, size);
        if (witnessCount < minWitnesses) revert UnderWitnessed(witnessCount, minWitnesses);
        _checkpoints[size] =
        // forge-lint: disable-next-line(unsafe-typecast)
            Checkpoint({root: root, size: size, anchoredAt: uint64(block.timestamp), witnessCount: witnessCount});
        latestSize = size;
        emit CheckpointAnchored(root, size, witnessCount);
    }

    /// @notice Close the current epoch with an aggregate root.
    function closeEpoch(bytes32 root) external onlyRole(ROLE_WRITER) {
        if (root == bytes32(0)) revert EmptyRoot();
        epochRoot[epoch] = root;
        emit EpochClosed(epoch, root);
        epoch++;
    }

    /// @notice Record that an epoch root reached a public chain.
    /// @dev externalTxId is opaque: what matters is that it is recorded and
    ///      cannot be changed, not that this chain can interpret it.
    function recordPublicAnchor(uint64 epoch_, bytes32 externalTxId) external onlyRole(ROLE_WRITER) {
        bytes32 root = epochRoot[epoch_];
        if (root == bytes32(0)) revert UnknownEpoch(epoch_);
        if (publicAnchorTx[epoch_] != bytes32(0)) revert AlreadyPublished(epoch_);
        publicAnchorTx[epoch_] = externalTxId;
        emit PublicAnchorPublished(epoch_, root, externalTxId);
    }

    function checkpoint(uint64 size) external view returns (Checkpoint memory) {
        return _checkpoints[size];
    }
}
