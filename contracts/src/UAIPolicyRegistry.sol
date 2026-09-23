// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {Roles} from "./Roles.sol";

/// @title Registry of GASC policy bundles and the thresholds they carry.
/// @notice Every other contract reads its thresholds from here rather than
///         holding a constant. A quorum compiled into a revocation contract
///         could only be changed by redeploying it, which would put a
///         governance parameter beyond the reach of governance.
contract UAIPolicyRegistry is Roles {
    struct Policy {
        bytes32 bundleHash;
        bytes32 previousHash;
        uint64 effectiveDate;
        uint32 revocationThreshold;
        uint32 minCountries;
        bool active;
    }

    /// @dev Keyed by policy version hash, never by a version string.
    mapping(bytes32 => Policy) private _policies;
    bytes32 public activeVersion;

    event PolicyRegistered(bytes32 indexed versionId, bytes32 bundleHash, bytes32 previousHash);
    event PolicyActivated(bytes32 indexed versionId, bytes32 bundleHash);

    error AlreadyRegistered(bytes32 versionId);
    error UnknownPolicy(bytes32 versionId);
    error ChainBroken(bytes32 expected, bytes32 got);
    error NotYetEffective(uint64 effectiveDate);
    error ThresholdUnsatisfiable();

    constructor(address admin) Roles(admin) {}

    /// @notice Register a bundle. The version chain is enforced on-chain, so a
    ///         bundle cannot be quietly replaced by an older, more permissive
    ///         one: policy history is as tamper-evident as action history.
    function registerPolicy(
        bytes32 versionId,
        bytes32 bundleHash,
        bytes32 previousHash,
        uint64 effectiveDate,
        uint32 quorum,
        uint32 countries
    ) external onlyRole(ROLE_ADMIN) {
        if (_policies[versionId].bundleHash != bytes32(0)) revert AlreadyRegistered(versionId);
        // Neither may be zero. A quorum of zero would let a revocation pass
        // with no votes, and one country is not an international decision.
        if (quorum == 0 || countries == 0) revert ThresholdUnsatisfiable();
        if (activeVersion != bytes32(0)) {
            bytes32 expected = _policies[activeVersion].bundleHash;
            if (previousHash != expected) revert ChainBroken(expected, previousHash);
        }
        _policies[versionId] = Policy({
            bundleHash: bundleHash,
            previousHash: previousHash,
            effectiveDate: effectiveDate,
            revocationThreshold: quorum,
            minCountries: countries,
            active: false
        });
        emit PolicyRegistered(versionId, bundleHash, previousHash);
    }

    /// @notice Activate a registered bundle once its effective date has passed.
    function activatePolicy(bytes32 versionId) external onlyRole(ROLE_ADMIN) {
        Policy storage p = _policies[versionId];
        if (p.bundleHash == bytes32(0)) revert UnknownPolicy(versionId);
        // Effective dates are days apart; second-level validator drift cannot
        // activate a policy meaningfully early.
        // forge-lint: disable-next-line(block-timestamp)
        if (block.timestamp < p.effectiveDate) revert NotYetEffective(p.effectiveDate);
        p.active = true;
        activeVersion = versionId;
        emit PolicyActivated(versionId, p.bundleHash);
    }

    function policy(bytes32 versionId) external view returns (Policy memory) {
        return _policies[versionId];
    }

    /// @notice The revocation quorum in force. Reverts when no policy is
    ///         active: a threshold of zero would let a revocation pass with no
    ///         votes at all, so "no policy" must fail rather than default.
    function revocationThreshold() external view returns (uint32) {
        if (activeVersion == bytes32(0)) revert UnknownPolicy(bytes32(0));
        return _policies[activeVersion].revocationThreshold;
    }

    function minCountries() external view returns (uint32) {
        if (activeVersion == bytes32(0)) revert UnknownPolicy(bytes32(0));
        return _policies[activeVersion].minCountries;
    }
}
