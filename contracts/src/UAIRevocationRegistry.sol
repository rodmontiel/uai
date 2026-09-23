// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {Roles} from "./Roles.sol";
import {UAIGovernance} from "./UAIGovernance.sol";
import {UAIPolicyRegistry} from "./UAIPolicyRegistry.sol";
import {UAIVoting} from "./UAIVoting.sol";
import {UAIIdentityRegistry} from "./UAIIdentityRegistry.sol";

/// @title Authorized revocation execution.
/// @notice This contract is the reason the ledger exists.
///
/// An administrator can submit a revocation; an administrator cannot decide
/// one. Every consequential parameter is checked here against delegate
/// signatures and a threshold read from the policy registry, so a compromise of
/// the application layer -- or of the admin account itself -- cannot produce a
/// revocation that this contract will accept. That is INV-005 and INV-010
/// expressed as code rather than as a promise in a document.
contract UAIRevocationRegistry is Roles {
    UAIGovernance public immutable governance;
    UAIPolicyRegistry public immutable policy;
    UAIVoting public immutable voting;
    UAIIdentityRegistry public immutable identity;

    mapping(bytes32 => bool) public revoked;
    mapping(bytes32 => bytes32) public revocationProof;

    event RevocationAuthorized(bytes32 indexed caseId, bytes32 indexed agentId);
    event AgentRevoked(bytes32 indexed agentId, bytes32 governanceProof);

    error AlreadyRevoked(bytes32 agentId);
    error NotAuthorized_(bytes32 caseId);
    error UnknownDelegate(bytes32 delegateId);
    error DuplicateDelegate(bytes32 delegateId);
    error BadVote(bytes32 delegateId);
    error ThresholdNotMet(uint256 yes, uint256 needed);
    error NotEnoughCountries(uint256 got, uint256 needed);
    error CaseAgentMismatch(bytes32 caseAgent, bytes32 agentId);
    error EmptyProof();

    constructor(
        address admin,
        UAIGovernance governance_,
        UAIPolicyRegistry policy_,
        UAIVoting voting_,
        UAIIdentityRegistry identity_
    ) Roles(admin) {
        governance = governance_;
        policy = policy_;
        voting = voting_;
        identity = identity_;
    }

    /// @notice Execute a revocation that governance has already authorized.
    /// @dev The caller holds ROLE_EXECUTOR, which is the right to SUBMIT this
    ///      transaction and nothing else. Every check below runs regardless of
    ///      who submitted it.
    function executeRevocation(
        bytes32 caseId,
        bytes32 agentId,
        bytes32 governanceProof,
        UAIVoting.Vote[] calldata votes
    ) external onlyRole(ROLE_EXECUTOR) {
        if (revoked[agentId]) revert AlreadyRevoked(agentId);
        if (governanceProof == bytes32(0)) revert EmptyProof();
        if (governance.proposalState(caseId) != UAIGovernance.State.AUTHORIZED) {
            revert NotAuthorized_(caseId);
        }
        // The case must be about this agent. Without this, an authorization for
        // one agent could be spent revoking another.
        bytes32 caseAgent = governance.proposal(caseId).agentId;
        if (caseAgent != agentId) revert CaseAgentMismatch(caseAgent, agentId);

        (uint256 yes, uint256 countryCount) = _tally(caseId, agentId, governanceProof, votes);
        uint256 threshold = policy.revocationThreshold();
        uint256 countriesNeeded = policy.minCountries();

        if (yes < threshold) revert ThresholdNotMet(yes, threshold);
        // A quorum drawn from one jurisdiction is not an international decision.
        // Requiring several countries is what stops a single government, or a
        // single operator with several delegates, from revoking on its own.
        if (countryCount < countriesNeeded) revert NotEnoughCountries(countryCount, countriesNeeded);

        // Checks, effects, then interactions. The state change and the events
        // land before the call into the identity registry, so a reentrant call
        // finds this revocation already recorded and cannot reorder or
        // fabricate the logs that off-chain consumers index.
        revoked[agentId] = true;
        revocationProof[agentId] = governanceProof;
        emit RevocationAuthorized(caseId, agentId);
        emit AgentRevoked(agentId, governanceProof);

        identity.setStatus(agentId, UAIIdentityRegistry.Status.REVOKED);
    }

    /// @dev Counts YES votes and the distinct countries behind them.
    ///
    /// Extracted from executeRevocation because the two jobs are different:
    /// this one decides what the votes say, the caller decides whether that is
    /// enough. Keeping them apart also keeps the live values on each side small
    /// enough to reason about -- and, as it happens, small enough to compile.
    function _tally(bytes32 caseId, bytes32 agentId, bytes32 governanceProof, UAIVoting.Vote[] calldata votes)
        private
        view
        returns (uint256 yes, uint256 countryCount)
    {
        bytes32[] memory seen = new bytes32[](votes.length);
        bytes32[] memory countries = new bytes32[](votes.length);

        // Reverting inside the loop, and calling out of it, are both deliberate.
        // One unverifiable vote invalidates the whole revocation: counting the
        // rest and proceeding would let an attacker pad a tally with garbage and
        // still reach a threshold. The loop is bounded by the votes submitted,
        // which is bounded by the delegate set.
        // forge-lint: disable-start(require-revert-in-loop,calls-loop)
        for (uint256 i = 0; i < votes.length; i++) {
            bytes32 delegateId = votes[i].delegateId;
            if (!governance.isRegisteredDelegate(delegateId)) revert UnknownDelegate(delegateId);
            for (uint256 j = 0; j < i; j++) {
                if (seen[j] == delegateId) revert DuplicateDelegate(delegateId);
            }
            seen[i] = delegateId;
            if (!voting.verify(caseId, agentId, governanceProof, votes[i])) revert BadVote(delegateId);
            if (!votes[i].value) continue;

            yes++;
            bytes32 country = governance.delegate(delegateId).country;
            bool known = false;
            for (uint256 k = 0; k < countryCount; k++) {
                if (countries[k] == country) {
                    known = true;
                    break;
                }
            }
            if (!known) {
                countries[countryCount] = country;
                countryCount++;
            }
        }
        // forge-lint: disable-end(require-revert-in-loop,calls-loop)
    }
}
