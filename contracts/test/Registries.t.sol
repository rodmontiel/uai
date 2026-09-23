// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {Roles} from "../src/Roles.sol";
import {UAIIdentityRegistry} from "../src/UAIIdentityRegistry.sol";
import {UAIPolicyRegistry} from "../src/UAIPolicyRegistry.sol";
import {UAIQuarantineRegistry} from "../src/UAIQuarantineRegistry.sol";
import {UAITransparencyAnchor} from "../src/UAITransparencyAnchor.sol";

contract RegistriesTest is Test {
    address admin = address(0xA11CE);
    address writer = address(0x3333);

    UAIIdentityRegistry ids;
    UAIPolicyRegistry pol;
    UAIQuarantineRegistry quar;
    UAITransparencyAnchor anchor;

    bytes32 constant AGENT = keccak256("agent");
    bytes32 constant CASE = keccak256("case");

    function setUp() public {
        vm.startPrank(admin);
        ids = new UAIIdentityRegistry(admin);
        pol = new UAIPolicyRegistry(admin);
        quar = new UAIQuarantineRegistry(admin);
        anchor = new UAITransparencyAnchor(admin, 2);
        ids.grantRole(ids.ROLE_WRITER(), writer);
        quar.grantRole(quar.ROLE_WRITER(), writer);
        anchor.grantRole(anchor.ROLE_WRITER(), writer);
        vm.stopPrank();
    }

    // ── identity ────────────────────────────────────────────────────────────

    /// @notice REVOKED is terminal by protocol (§6.10 rule 4). Enforcing it in
    ///         the contract means no application-layer compromise can walk a
    ///         revoked identity back into service.
    function test_RevokedIsTerminal() public {
        vm.startPrank(writer);
        ids.registerAgent(AGENT, keccak256("c"), keccak256("g"));
        ids.setStatus(AGENT, UAIIdentityRegistry.Status.REVOKED);
        vm.expectRevert(abi.encodeWithSelector(UAIIdentityRegistry.Terminal.selector, AGENT));
        ids.setStatus(AGENT, UAIIdentityRegistry.Status.ACTIVE);
        vm.stopPrank();
    }

    /// @notice A zero commitment is not a commitment: it would create an
    ///         identity nothing can ever be opened against.
    function test_RejectsEmptyCommitment() public {
        vm.startPrank(writer);
        vm.expectRevert(UAIIdentityRegistry.EmptyCommitment.selector);
        ids.registerAgent(AGENT, bytes32(0), keccak256("g"));
        vm.expectRevert(UAIIdentityRegistry.EmptyCommitment.selector);
        ids.registerAgent(AGENT, keccak256("c"), bytes32(0));
        vm.stopPrank();
    }

    function test_RegistrationIsOnceOnly() public {
        vm.startPrank(writer);
        ids.registerAgent(AGENT, keccak256("c"), keccak256("g"));
        vm.expectRevert(abi.encodeWithSelector(UAIIdentityRegistry.AlreadyRegistered.selector, AGENT));
        ids.registerAgent(AGENT, keccak256("c2"), keccak256("g2"));
        vm.stopPrank();
    }

    // ── policy ──────────────────────────────────────────────────────────────

    /// @notice Policy history is as tamper-evident as action history: a bundle
    ///         cannot be swapped for one that does not follow the active chain.
    function test_PolicyChainIsEnforced() public {
        bytes32 v1 = keccak256("v1");
        bytes32 v2 = keccak256("v2");
        vm.startPrank(admin);
        pol.registerPolicy(v1, keccak256("b1"), bytes32(0), uint64(block.timestamp), 3, 3);
        pol.activatePolicy(v1);
        vm.expectRevert(
            abi.encodeWithSelector(UAIPolicyRegistry.ChainBroken.selector, keccak256("b1"), keccak256("wrong"))
        );
        pol.registerPolicy(v2, keccak256("b2"), keccak256("wrong"), uint64(block.timestamp), 3, 3);
        vm.stopPrank();
    }

    /// @notice No active policy means no threshold, and no threshold must mean
    ///         a revert rather than zero: a quorum of zero passes with no votes.
    function test_ThresholdRevertsWithoutAnActivePolicy() public {
        vm.expectRevert(abi.encodeWithSelector(UAIPolicyRegistry.UnknownPolicy.selector, bytes32(0)));
        pol.revocationThreshold();
    }

    function test_RejectsUnsatisfiableThreshold() public {
        vm.startPrank(admin);
        vm.expectRevert(UAIPolicyRegistry.ThresholdUnsatisfiable.selector);
        pol.registerPolicy(keccak256("v"), keccak256("b"), bytes32(0), uint64(block.timestamp), 0, 3);
        vm.expectRevert(UAIPolicyRegistry.ThresholdUnsatisfiable.selector);
        pol.registerPolicy(keccak256("v"), keccak256("b"), bytes32(0), uint64(block.timestamp), 3, 0);
        vm.stopPrank();
    }

    function test_PolicyCannotActivateEarly() public {
        bytes32 v = keccak256("future");
        uint64 later = uint64(block.timestamp + 1 days);
        vm.startPrank(admin);
        pol.registerPolicy(v, keccak256("b"), bytes32(0), later, 3, 3);
        vm.expectRevert(abi.encodeWithSelector(UAIPolicyRegistry.NotYetEffective.selector, later));
        pol.activatePolicy(v);
        vm.stopPrank();
    }

    // ── quarantine ──────────────────────────────────────────────────────────

    /// @notice A preventive measure with no end date is a sanction nobody
    ///         decided (P13).
    function test_QuarantineRequiresAnExpiry() public {
        vm.startPrank(writer);
        vm.expectRevert(UAIQuarantineRegistry.NoExpiry.selector);
        quar.quarantine(AGENT, CASE, 0);
        uint64 past = uint64(block.timestamp);
        vm.expectRevert(abi.encodeWithSelector(UAIQuarantineRegistry.ExpiryInPast.selector, past));
        quar.quarantine(AGENT, CASE, past);
        vm.stopPrank();
    }

    /// @notice Expiry is evaluated on read, so an order nobody released stops
    ///         constraining the agent the moment it lapses.
    function test_QuarantineLapsesOnItsOwn() public {
        vm.prank(writer);
        quar.quarantine(AGENT, CASE, uint64(block.timestamp + 1 days));
        assertTrue(quar.isQuarantined(AGENT), "must be quarantined while the order stands");
        vm.warp(block.timestamp + 2 days);
        assertFalse(quar.isQuarantined(AGENT), "an expired order must stop constraining the agent");
    }

    // ── transparency anchor ─────────────────────────────────────────────────

    /// @notice A log that shrank would be a log that dropped entries, which is
    ///         the one thing a transparency log must not be able to do quietly.
    function test_CheckpointsOnlyGrow() public {
        vm.startPrank(writer);
        anchor.anchor(keccak256("r1"), 100, 3);
        vm.expectRevert(abi.encodeWithSelector(UAITransparencyAnchor.NotGrowing.selector, uint64(100), uint64(99)));
        anchor.anchor(keccak256("r2"), 99, 3);
        vm.expectRevert(abi.encodeWithSelector(UAITransparencyAnchor.NotGrowing.selector, uint64(100), uint64(100)));
        anchor.anchor(keccak256("r3"), 100, 3);
        vm.stopPrank();
    }

    /// @notice An under-witnessed checkpoint is refused. Anchoring one would
    ///         put a root beyond reach that no independent party vouched for,
    ///         which is worse than not anchoring it at all.
    function test_RefusesUnderWitnessedCheckpoints() public {
        vm.prank(writer);
        vm.expectRevert(abi.encodeWithSelector(UAITransparencyAnchor.UnderWitnessed.selector, uint32(1), uint32(2)));
        anchor.anchor(keccak256("r"), 10, 1);
    }

    function test_PublicAnchorIsRecordedOnce() public {
        vm.startPrank(writer);
        anchor.closeEpoch(keccak256("epoch-root"));
        anchor.recordPublicAnchor(0, keccak256("tx"));
        vm.expectRevert(abi.encodeWithSelector(UAITransparencyAnchor.AlreadyPublished.selector, uint64(0)));
        anchor.recordPublicAnchor(0, keccak256("tx2"));
        vm.stopPrank();
    }

    function test_PublicAnchorNeedsAClosedEpoch() public {
        vm.prank(writer);
        vm.expectRevert(abi.encodeWithSelector(UAITransparencyAnchor.UnknownEpoch.selector, uint64(7)));
        anchor.recordPublicAnchor(7, keccak256("tx"));
    }

    // ── roles ───────────────────────────────────────────────────────────────

    /// @notice Removing the last admin would leave a registry that still holds
    ///         history but that nobody can ever administer again.
    function test_CannotRemoveTheLastAdmin() public {
        // Hoisted: ids.ROLE_ADMIN() is an external call, and a cheatcode
        // applies to the next external call — an inline getter eats it.
        bytes32 role = ids.ROLE_ADMIN();
        vm.expectRevert(Roles.LastAdmin.selector);
        vm.prank(admin);
        ids.revokeRole(role, admin);
    }

    function test_WriterCannotGrantRoles() public {
        bytes32 role = ids.ROLE_ADMIN();
        vm.prank(writer);
        vm.expectRevert(abi.encodeWithSelector(Roles.NotAuthorized.selector, role, writer));
        ids.grantRole(role, writer);
    }

    /// @notice Fuzz: whatever account is tried, only the roles it holds work.
    function testFuzz_OnlyWritersMayRegister(address who) public {
        vm.assume(who != writer && who != address(0));
        bytes32 role = ids.ROLE_WRITER();
        vm.prank(who);
        vm.expectRevert(abi.encodeWithSelector(Roles.NotAuthorized.selector, role, who));
        ids.registerAgent(AGENT, keccak256("c"), keccak256("g"));
    }
}
