// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {Roles} from "./Roles.sol";

/// @title Identity, credential and passport commitments.
/// @notice Only commitments are stored, never content (§17.2.1). A salted
///         commitment is what makes that safe: an unsalted hash of a short,
///         guessable value is recoverable by dictionary attack and would be
///         personal data in practice, not in theory.
contract UAIIdentityRegistry is Roles {
    enum Status {
        UNKNOWN,
        REGISTERED,
        VERIFIED,
        ACTIVE,
        UNBOUND,
        QUARANTINED,
        REVOCATION_AUTHORIZED,
        REVOKED
    }

    struct Identity {
        bytes32 identityCommitment;
        bytes32 genesisEventHash;
        uint64 registeredAt;
        Status status;
    }

    mapping(bytes32 => Identity) private _identities;
    mapping(bytes32 => bytes32) public credentialIssuer; // credentialHash -> agentId
    mapping(bytes32 => bytes32) public passportAgent; // passportHash  -> agentId
    mapping(bytes32 => bool) public passportRevoked;

    event AgentRegistered(bytes32 indexed agentId, bytes32 identityCommitment, bytes32 genesisEventHash);
    event IdentityUpdated(bytes32 indexed agentId, Status status);
    event CredentialRecorded(bytes32 indexed agentId, bytes32 credentialHash);
    event PassportRecorded(bytes32 indexed agentId, bytes32 passportHash);
    event PassportRevoked(bytes32 indexed agentId, bytes32 passportHash);

    error AlreadyRegistered(bytes32 agentId);
    error UnknownAgent(bytes32 agentId);
    error Terminal(bytes32 agentId);
    error EmptyCommitment();

    constructor(address admin) Roles(admin) {}

    function registerAgent(bytes32 agentId, bytes32 identityCommitment, bytes32 genesisEventHash)
        external
        onlyRole(ROLE_WRITER)
    {
        if (_identities[agentId].identityCommitment != bytes32(0)) revert AlreadyRegistered(agentId);
        // A zero commitment is not a commitment. Accepting one would create an
        // identity that nothing can ever be opened against.
        if (identityCommitment == bytes32(0) || genesisEventHash == bytes32(0)) revert EmptyCommitment();
        _identities[agentId] = Identity({
            identityCommitment: identityCommitment,
            genesisEventHash: genesisEventHash,
            // forge-lint: disable-next-line(unsafe-typecast)
            registeredAt: uint64(block.timestamp),
            status: Status.REGISTERED
        });
        emit AgentRegistered(agentId, identityCommitment, genesisEventHash);
    }

    /// @notice Move an identity to a new status.
    /// @dev REVOKED is terminal and irreversible by protocol (§6.10 rule 4).
    ///      Enforcing it here rather than only in the service means no
    ///      application-layer compromise can walk a revoked identity back.
    function setStatus(bytes32 agentId, Status status) external onlyRole(ROLE_WRITER) {
        Identity storage id = _identities[agentId];
        if (id.identityCommitment == bytes32(0)) revert UnknownAgent(agentId);
        if (id.status == Status.REVOKED) revert Terminal(agentId);
        id.status = status;
        emit IdentityUpdated(agentId, status);
    }

    function recordCredential(bytes32 agentId, bytes32 credentialHash) external onlyRole(ROLE_WRITER) {
        if (_identities[agentId].identityCommitment == bytes32(0)) revert UnknownAgent(agentId);
        credentialIssuer[credentialHash] = agentId;
        emit CredentialRecorded(agentId, credentialHash);
    }

    function recordPassport(bytes32 agentId, bytes32 passportHash) external onlyRole(ROLE_WRITER) {
        if (_identities[agentId].identityCommitment == bytes32(0)) revert UnknownAgent(agentId);
        passportAgent[passportHash] = agentId;
        emit PassportRecorded(agentId, passportHash);
    }

    function revokePassport(bytes32 passportHash) external onlyRole(ROLE_WRITER) {
        bytes32 agentId = passportAgent[passportHash];
        if (agentId == bytes32(0)) revert UnknownAgent(agentId);
        passportRevoked[passportHash] = true;
        emit PassportRevoked(agentId, passportHash);
    }

    function identity(bytes32 agentId) external view returns (Identity memory) {
        return _identities[agentId];
    }

    function isRevoked(bytes32 agentId) external view returns (bool) {
        return _identities[agentId].status == Status.REVOKED;
    }
}
