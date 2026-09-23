// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {Roles} from "./Roles.sol";
import {UAIGovernance} from "./UAIGovernance.sol";

/// @title Vote recording and signature verification.
/// @notice A vote is stored as a signature proof, never as anything a reader
///         could mine for who voted what beyond the delegate identifier the
///         governance process already publishes.
contract UAIVoting is Roles {
    UAIGovernance public immutable governance;

    struct Vote {
        bytes32 delegateId;
        bool value;
        bytes32 r;
        bytes32 s;
        uint8 v;
    }

    /// @dev caseId -> delegateId -> recorded
    mapping(bytes32 => mapping(bytes32 => bool)) public hasVoted;
    mapping(bytes32 => uint256) public yesCount;

    event VoteCast(bytes32 indexed caseId, bytes32 indexed delegateId, bool value);
    event VoteSuperseded(bytes32 indexed caseId, bytes32 indexed delegateId);
    event QuorumReached(bytes32 indexed caseId, uint256 yes);

    error UnknownDelegate(bytes32 delegateId);
    error AlreadyVoted(bytes32 caseId, bytes32 delegateId);
    error BadSignature(bytes32 delegateId);
    error NotVoting(bytes32 caseId);

    constructor(address admin, UAIGovernance governance_) Roles(admin) {
        governance = governance_;
    }

    /// @notice The bytes a delegate signs.
    /// @dev The domain binds the chain id and this contract's address, so a
    ///      signature collected on a test chain, or for a different deployment
    ///      of this protocol, cannot be replayed here. Without that binding the
    ///      cheapest attack on a quorum is to gather votes somewhere harmless.
    function voteDigest(bytes32 caseId, bytes32 agentId, bytes32 governanceProof, bytes32 delegateId, bool value)
        public
        view
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                keccak256("UAI-v1:vote"),
                block.chainid,
                address(this),
                caseId,
                agentId,
                governanceProof,
                delegateId,
                value
            )
        );
    }

    function castVote(bytes32 caseId, bytes32 agentId, bytes32 governanceProof, Vote calldata vote)
        external
        onlyRole(ROLE_WRITER)
    {
        if (governance.proposalState(caseId) != UAIGovernance.State.VOTING) revert NotVoting(caseId);
        if (!governance.isRegisteredDelegate(vote.delegateId)) revert UnknownDelegate(vote.delegateId);
        if (hasVoted[caseId][vote.delegateId]) revert AlreadyVoted(caseId, vote.delegateId);
        if (!verify(caseId, agentId, governanceProof, vote)) revert BadSignature(vote.delegateId);

        hasVoted[caseId][vote.delegateId] = true;
        if (vote.value) {
            yesCount[caseId]++;
            emit QuorumReached(caseId, yesCount[caseId]);
        }
        emit VoteCast(caseId, vote.delegateId, vote.value);
    }

    /// @notice Verify one vote signature against the delegate's registered key.
    function verify(bytes32 caseId, bytes32 agentId, bytes32 governanceProof, Vote calldata vote)
        public
        view
        returns (bool)
    {
        UAIGovernance.Delegate memory d = governance.delegate(vote.delegateId);
        if (!d.active || d.key == address(0)) return false;
        // Reject the upper half of the curve order. Without this check every
        // signature has a second, equally valid form, and "one delegate, one
        // vote" could be defeated by submitting both spellings.
        if (uint256(vote.s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            return false;
        }
        if (vote.v != 27 && vote.v != 28) return false;
        bytes32 digest = voteDigest(caseId, agentId, governanceProof, vote.delegateId, vote.value);
        address signer = ecrecover(digest, vote.v, vote.r, vote.s);
        return signer != address(0) && signer == d.key;
    }
}
