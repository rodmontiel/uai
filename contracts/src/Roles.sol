// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

/// @title Minimal role-based access control for the UAI contracts.
/// @notice Deliberately written here rather than vendored from a library.
///         The surface is three functions; vendoring a general-purpose access
///         control framework would bring in far more code than is used, and on
///         contracts that gate revocation the amount of code a reviewer has to
///         read is itself a security property.
abstract contract Roles {
    /// @dev Roles are bytes32 constants, never strings: a string parameter is
    ///      exactly the shape INV-007 forbids on this chain.
    bytes32 public constant ROLE_ADMIN = keccak256("UAI_ADMIN");
    bytes32 public constant ROLE_EXECUTOR = keccak256("UAI_EXECUTOR");
    bytes32 public constant ROLE_WRITER = keccak256("UAI_WRITER");

    mapping(bytes32 => mapping(address => bool)) private _roles;

    event RoleGranted(bytes32 indexed role, address indexed account, address indexed by);
    event RoleRevoked(bytes32 indexed role, address indexed account, address indexed by);

    error NotAuthorized(bytes32 role, address account);
    error LastAdmin();

    uint256 private _adminCount;

    constructor(address admin) {
        _roles[ROLE_ADMIN][admin] = true;
        _adminCount = 1;
        emit RoleGranted(ROLE_ADMIN, admin, msg.sender);
    }

    modifier onlyRole(bytes32 role) {
        if (!_roles[role][msg.sender]) revert NotAuthorized(role, msg.sender);
        _;
    }

    function hasRole(bytes32 role, address account) public view returns (bool) {
        return _roles[role][account];
    }

    function grantRole(bytes32 role, address account) external onlyRole(ROLE_ADMIN) {
        if (_roles[role][account]) return;
        _roles[role][account] = true;
        if (role == ROLE_ADMIN) _adminCount++;
        emit RoleGranted(role, account, msg.sender);
    }

    function revokeRole(bytes32 role, address account) external onlyRole(ROLE_ADMIN) {
        if (!_roles[role][account]) return;
        // Removing the last admin would leave the contract with no one able to
        // grant roles again -- a bricked registry that still holds history.
        if (role == ROLE_ADMIN && _adminCount == 1) revert LastAdmin();
        _roles[role][account] = false;
        if (role == ROLE_ADMIN) _adminCount--;
        emit RoleRevoked(role, account, msg.sender);
    }
}
