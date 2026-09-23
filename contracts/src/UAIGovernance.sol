// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {Roles} from "./Roles.sol";

/// @title Cases, proposals and the delegate set.
contract UAIGovernance is Roles {
    enum State {
        NONE,
        OPEN,
        VOTING,
        AUTHORIZED,
        REJECTED,
        CLOSED
    }

    struct Proposal {
        bytes32 caseId;
        bytes32 agentId;
        State state;
        uint64 openedAt;
    }

    struct Delegate {
        address key;
        bytes32 country;
        bool active;
    }

    mapping(bytes32 => Proposal) private _proposals;
    mapping(bytes32 => Delegate) private _delegates;

    event CaseOpened(bytes32 indexed caseId, bytes32 indexed agentId);
    event ProposalCreated(bytes32 indexed caseId, bytes32 indexed agentId);
    event ProposalStateChanged(bytes32 indexed caseId, State state);
    event DelegateRegistered(bytes32 indexed delegateId, bytes32 country);
    event DelegateDeactivated(bytes32 indexed delegateId);

    error UnknownProposal(bytes32 caseId);
    error AlreadyExists(bytes32 caseId);
    error BadTransition(State from, State to);
    error UnknownDelegate(bytes32 delegateId);

    constructor(address admin) Roles(admin) {}

    function openCase(bytes32 caseId, bytes32 agentId) external onlyRole(ROLE_WRITER) {
        if (_proposals[caseId].state != State.NONE) revert AlreadyExists(caseId);
        // forge-lint: disable-next-line(unsafe-typecast)
        uint64 now_ = uint64(block.timestamp);
        _proposals[caseId] = Proposal({caseId: caseId, agentId: agentId, state: State.OPEN, openedAt: now_});
        emit CaseOpened(caseId, agentId);
        emit ProposalCreated(caseId, agentId);
    }

    /// @dev The machine is enforced here, not asserted by the caller. AUTHORIZED
    ///      is reachable only from VOTING, so a proposal cannot be walked
    ///      straight from OPEN to authorized without anybody voting.
    function setState(bytes32 caseId, State to) external onlyRole(ROLE_WRITER) {
        Proposal storage p = _proposals[caseId];
        if (p.state == State.NONE) revert UnknownProposal(caseId);
        bool ok = (p.state == State.OPEN && to == State.VOTING)
            || (p.state == State.VOTING && (to == State.AUTHORIZED || to == State.REJECTED))
            || (p.state == State.AUTHORIZED && to == State.CLOSED)
            || (p.state == State.REJECTED && to == State.CLOSED);
        if (!ok) revert BadTransition(p.state, to);
        p.state = to;
        emit ProposalStateChanged(caseId, to);
    }

    function registerDelegate(bytes32 delegateId, address key, bytes32 country) external onlyRole(ROLE_ADMIN) {
        _delegates[delegateId] = Delegate({key: key, country: country, active: true});
        emit DelegateRegistered(delegateId, country);
    }

    function deactivateDelegate(bytes32 delegateId) external onlyRole(ROLE_ADMIN) {
        if (_delegates[delegateId].key == address(0)) revert UnknownDelegate(delegateId);
        _delegates[delegateId].active = false;
        emit DelegateDeactivated(delegateId);
    }

    function proposalState(bytes32 caseId) external view returns (State) {
        return _proposals[caseId].state;
    }

    function proposal(bytes32 caseId) external view returns (Proposal memory) {
        return _proposals[caseId];
    }

    function isRegisteredDelegate(bytes32 delegateId) external view returns (bool) {
        return _delegates[delegateId].active;
    }

    function delegate(bytes32 delegateId) external view returns (Delegate memory) {
        return _delegates[delegateId];
    }
}
