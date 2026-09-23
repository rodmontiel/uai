// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {Roles} from "./Roles.sol";

/// @title Quarantine orders, releases and owner restrictions.
/// @notice Quarantine is preventive and reversible. Every order carries an
///         expiry, and the contract refuses one without it: a preventive
///         measure with no end date is a sanction nobody decided (P13).
contract UAIQuarantineRegistry is Roles {
    struct Order {
        bytes32 caseId;
        uint64 orderedAt;
        uint64 expiresAt;
        bool active;
    }

    mapping(bytes32 => Order) private _orders; // agentId -> order
    mapping(bytes32 => bool) public ownerRestricted;

    event AgentQuarantined(bytes32 indexed agentId, bytes32 caseId, uint64 expiresAt);
    event AgentUnquarantined(bytes32 indexed agentId, bytes32 caseId);
    event OwnerRestricted(bytes32 indexed ownerId, bytes32 caseId);
    event OwnerRestrictionLifted(bytes32 indexed ownerId, bytes32 caseId);

    error NoExpiry();
    error ExpiryInPast(uint64 expiresAt);
    error NotQuarantined(bytes32 agentId);
    error AlreadyQuarantined(bytes32 agentId);

    constructor(address admin) Roles(admin) {}

    function quarantine(bytes32 agentId, bytes32 caseId, uint64 expiresAt) external onlyRole(ROLE_WRITER) {
        if (_orders[agentId].active) revert AlreadyQuarantined(agentId);
        if (expiresAt == 0) revert NoExpiry();
        // A validator can nudge block.timestamp by seconds. Quarantine windows
        // are days, so the drift is irrelevant here; what matters is that an
        // expiry in the past is refused at all.
        // forge-lint: disable-next-line(block-timestamp)
        if (expiresAt <= block.timestamp) revert ExpiryInPast(expiresAt);
        // forge-lint: disable-next-line(unsafe-typecast)
        uint64 now_ = uint64(block.timestamp); // overflows in the year 584942417355
        _orders[agentId] = Order({caseId: caseId, orderedAt: now_, expiresAt: expiresAt, active: true});
        emit AgentQuarantined(agentId, caseId, expiresAt);
    }

    /// @notice Release a quarantine.
    /// @dev Anyone holding ROLE_WRITER may release, and release needs no case
    ///      to have advanced: lifting a preventive measure must never be harder
    ///      than imposing it, or quarantine becomes punishment by inertia.
    function release(bytes32 agentId) external onlyRole(ROLE_WRITER) {
        Order storage o = _orders[agentId];
        if (!o.active) revert NotQuarantined(agentId);
        o.active = false;
        emit AgentUnquarantined(agentId, o.caseId);
    }

    /// @notice Whether an agent is under quarantine right now.
    /// @dev Expiry is evaluated on read, so an order that nobody got round to
    ///      releasing stops constraining the agent the moment it lapses.
    function isQuarantined(bytes32 agentId) external view returns (bool) {
        Order memory o = _orders[agentId];
        // forge-lint: disable-next-line(block-timestamp)
        return o.active && o.expiresAt > block.timestamp;
    }

    function order(bytes32 agentId) external view returns (Order memory) {
        return _orders[agentId];
    }

    function restrictOwner(bytes32 ownerId, bytes32 caseId) external onlyRole(ROLE_WRITER) {
        ownerRestricted[ownerId] = true;
        emit OwnerRestricted(ownerId, caseId);
    }

    function liftOwnerRestriction(bytes32 ownerId, bytes32 caseId) external onlyRole(ROLE_WRITER) {
        ownerRestricted[ownerId] = false;
        emit OwnerRestrictionLifted(ownerId, caseId);
    }
}
