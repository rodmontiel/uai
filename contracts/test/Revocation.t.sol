// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {UAIGovernance} from "../src/UAIGovernance.sol";
import {UAIIdentityRegistry} from "../src/UAIIdentityRegistry.sol";
import {UAIPolicyRegistry} from "../src/UAIPolicyRegistry.sol";
import {UAIRevocationRegistry} from "../src/UAIRevocationRegistry.sol";
import {UAIVoting} from "../src/UAIVoting.sol";
import {Roles} from "../src/Roles.sol";

/// @notice The Phase 7 acceptance criterion, as tests: AgentRevoked requires a
///         valid governance proof on-chain.
contract RevocationTest is Test {
    UAIGovernance gov;
    UAIPolicyRegistry pol;
    UAIVoting vote;
    UAIIdentityRegistry ids;
    UAIRevocationRegistry rev;

    address admin = address(0xA11CE);
    address executor = address(0xE0E0);

    bytes32 constant CASE_ID = keccak256("case-1");
    bytes32 constant AGENT_ID = keccak256("uai:agent:01JY8R9ZAF392N7QX2T81JH6KM");
    bytes32 constant PROOF = keccak256("governance-proof");
    bytes32 constant VERSION = keccak256("GASC-2027.4");

    /// @dev Five delegates across five countries, so a 3-of-N quorum spanning
    ///      3 countries is reachable and so is every way of failing it.
    uint256[5] keys = [uint256(1), 2, 3, 4, 5];
    bytes32[5] delegateIds;
    bytes32[5] countries = [bytes32("DE"), bytes32("JP"), bytes32("AR"), bytes32("CA"), bytes32("DE")];

    function setUp() public {
        vm.startPrank(admin);
        gov = new UAIGovernance(admin);
        pol = new UAIPolicyRegistry(admin);
        vote = new UAIVoting(admin, gov);
        ids = new UAIIdentityRegistry(admin);
        rev = new UAIRevocationRegistry(admin, gov, pol, vote, ids);

        gov.grantRole(gov.ROLE_WRITER(), admin);
        ids.grantRole(ids.ROLE_WRITER(), admin);
        ids.grantRole(ids.ROLE_WRITER(), address(rev));
        rev.grantRole(rev.ROLE_EXECUTOR(), executor);

        pol.registerPolicy(VERSION, keccak256("bundle"), bytes32(0), uint64(block.timestamp), 3, 3);
        pol.activatePolicy(VERSION);

        for (uint256 i = 0; i < 5; i++) {
            delegateIds[i] = keccak256(abi.encodePacked("delegate", i));
            gov.registerDelegate(delegateIds[i], vm.addr(keys[i]), countries[i]);
        }

        ids.registerAgent(AGENT_ID, keccak256("identity-commitment"), keccak256("genesis"));
        gov.openCase(CASE_ID, AGENT_ID);
        vm.stopPrank();
    }

    function _authorize() internal {
        vm.startPrank(admin);
        gov.setState(CASE_ID, UAIGovernance.State.VOTING);
        gov.setState(CASE_ID, UAIGovernance.State.AUTHORIZED);
        vm.stopPrank();
    }

    function _vote(uint256 idx, bool value) internal view returns (UAIVoting.Vote memory) {
        bytes32 digest = vote.voteDigest(CASE_ID, AGENT_ID, PROOF, delegateIds[idx], value);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(keys[idx], digest);
        return UAIVoting.Vote({delegateId: delegateIds[idx], value: value, r: r, s: s, v: v});
    }

    /// @dev Three YES from DE, JP and AR: meets both the quorum and the
    ///      three-country requirement.
    ///
    /// Callers must build the votes BEFORE arming vm.prank or vm.expectRevert.
    /// Those cheatcodes apply to the next EXTERNAL call, and constructing a vote
    /// makes one (voteDigest) -- so an inline _quorum() in the call expression
    /// consumes the cheatcode and the test silently checks nothing.
    function _quorum() internal view returns (UAIVoting.Vote[] memory votes) {
        votes = new UAIVoting.Vote[](3);
        votes[0] = _vote(0, true);
        votes[1] = _vote(1, true);
        votes[2] = _vote(2, true);
    }

    function test_RevokesWithAValidGovernanceProof() public {
        _authorize();
        UAIVoting.Vote[] memory votes = _quorum();
        vm.expectEmit(true, false, false, true);
        emit UAIRevocationRegistry.AgentRevoked(AGENT_ID, PROOF);
        vm.prank(executor);
        rev.executeRevocation(CASE_ID, AGENT_ID, PROOF, votes);

        assertTrue(rev.revoked(AGENT_ID), "agent must be revoked");
        assertEq(rev.revocationProof(AGENT_ID), PROOF, "the proof must be recorded");
        assertTrue(ids.isRevoked(AGENT_ID), "the identity registry must agree");
    }

    /// @notice The heart of it: an administrator may SUBMIT a revocation, never
    ///         decide one. Everything below is a way of trying to decide.
    ///
    ///         This block is INV-010 -- "permanent revocation requires valid
    ///         human decision evidence" -- at the layer §20.3 calls primary.
    ///         The application also recomputes the decision, but that check
    ///         runs on a server an attacker who got this far already owns.
    ///         Here the votes are verified by the code that writes the event.
    function test_RevertsWithoutAuthorization() public {
        UAIVoting.Vote[] memory votes = _quorum();
        vm.expectRevert(abi.encodeWithSelector(UAIRevocationRegistry.NotAuthorized_.selector, CASE_ID));
        vm.prank(executor);
        rev.executeRevocation(CASE_ID, AGENT_ID, PROOF, votes);
    }

    function test_RevertsBelowThreshold() public {
        _authorize();
        UAIVoting.Vote[] memory votes = new UAIVoting.Vote[](2);
        votes[0] = _vote(0, true);
        votes[1] = _vote(1, true);
                vm.expectRevert(abi.encodeWithSelector(UAIRevocationRegistry.ThresholdNotMet.selector, 2, 3));
        vm.prank(executor);
        rev.executeRevocation(CASE_ID, AGENT_ID, PROOF, votes);
    }

    /// @notice A quorum drawn from one jurisdiction is not an international
    ///         decision. Delegates 0 and 4 are both DE.
    function test_RevertsWithoutEnoughCountries() public {
        _authorize();
        UAIVoting.Vote[] memory votes = new UAIVoting.Vote[](3);
        votes[0] = _vote(0, true); // DE
        votes[1] = _vote(4, true); // DE
        votes[2] = _vote(1, true); // JP
                vm.expectRevert(abi.encodeWithSelector(UAIRevocationRegistry.NotEnoughCountries.selector, 2, 3));
        vm.prank(executor);
        rev.executeRevocation(CASE_ID, AGENT_ID, PROOF, votes);
    }

    function test_RevertsOnDuplicateDelegate() public {
        _authorize();
        UAIVoting.Vote[] memory votes = new UAIVoting.Vote[](3);
        votes[0] = _vote(0, true);
        votes[1] = _vote(1, true);
        votes[2] = _vote(0, true);
                vm.expectRevert(abi.encodeWithSelector(UAIRevocationRegistry.DuplicateDelegate.selector, delegateIds[0]));
        vm.prank(executor);
        rev.executeRevocation(CASE_ID, AGENT_ID, PROOF, votes);
    }

    /// @notice A signature by somebody who is not the registered delegate.
    /// @notice INV-004 on-chain: a vote is a delegate's signature over the vote
    ///         digest, so substituting one means producing that signature.
    ///         Nobody with write access to the database -- or to this call --
    ///         can do that, which is what makes votes unmodifiable rather than
    ///         merely protected.
    function test_RevertsOnForgedVote() public {
        _authorize();
        UAIVoting.Vote[] memory votes = _quorum();
        bytes32 digest = vote.voteDigest(CASE_ID, AGENT_ID, PROOF, delegateIds[2], true);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(uint256(0xBAD), digest);
        votes[2] = UAIVoting.Vote({delegateId: delegateIds[2], value: true, r: r, s: s, v: v});
                vm.expectRevert(abi.encodeWithSelector(UAIRevocationRegistry.BadVote.selector, delegateIds[2]));
        vm.prank(executor);
        rev.executeRevocation(CASE_ID, AGENT_ID, PROOF, votes);
    }

    /// @notice A vote signed for a DIFFERENT case cannot be moved to this one.
    function test_RevertsOnVoteFromAnotherCase() public {
        _authorize();
        UAIVoting.Vote[] memory votes = _quorum();
        bytes32 other = vote.voteDigest(keccak256("case-2"), AGENT_ID, PROOF, delegateIds[2], true);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(keys[2], other);
        votes[2] = UAIVoting.Vote({delegateId: delegateIds[2], value: true, r: r, s: s, v: v});
                vm.expectRevert(abi.encodeWithSelector(UAIRevocationRegistry.BadVote.selector, delegateIds[2]));
        vm.prank(executor);
        rev.executeRevocation(CASE_ID, AGENT_ID, PROOF, votes);
    }

    /// @notice An authorization for one agent cannot be spent on another.
    function test_RevertsOnCaseAgentMismatch() public {
        _authorize();
        bytes32 other = keccak256("uai:agent:other");
        vm.prank(admin);
        ids.registerAgent(other, keccak256("c2"), keccak256("g2"));
        UAIVoting.Vote[] memory votes = _quorum();
        vm.expectRevert(abi.encodeWithSelector(UAIRevocationRegistry.CaseAgentMismatch.selector, AGENT_ID, other));
        vm.prank(executor);
        rev.executeRevocation(CASE_ID, other, PROOF, votes);
    }

    function test_RevertsOnEmptyProof() public {
        _authorize();
        UAIVoting.Vote[] memory votes = _quorum();
        vm.expectRevert(UAIRevocationRegistry.EmptyProof.selector);
        vm.prank(executor);
        rev.executeRevocation(CASE_ID, AGENT_ID, bytes32(0), votes);
    }

    function test_RevertsForNonExecutor() public {
        _authorize();
        UAIVoting.Vote[] memory votes = _quorum();
        bytes32 role = rev.ROLE_EXECUTOR();
        vm.expectRevert(abi.encodeWithSelector(Roles.NotAuthorized.selector, role, address(0xDEAD)));
        vm.prank(address(0xDEAD));
        rev.executeRevocation(CASE_ID, AGENT_ID, PROOF, votes);
    }

    function test_RevertsWhenAlreadyRevoked() public {
        _authorize();
        UAIVoting.Vote[] memory votes = _quorum();
        vm.startPrank(executor);
        rev.executeRevocation(CASE_ID, AGENT_ID, PROOF, votes);
        vm.expectRevert(abi.encodeWithSelector(UAIRevocationRegistry.AlreadyRevoked.selector, AGENT_ID));
        rev.executeRevocation(CASE_ID, AGENT_ID, PROOF, votes);
        vm.stopPrank();
    }

    /// @notice The threshold is read from the policy registry, not compiled in.
    ///         Raising it by governance changes what this contract accepts
    ///         without redeploying it — which is the whole reason it is not a
    ///         constant.
    function test_ThresholdComesFromThePolicyRegistry() public {
        _authorize();
        bytes32 v2 = keccak256("GASC-2027.5");
        vm.startPrank(admin);
        pol.registerPolicy(v2, keccak256("bundle-2"), keccak256("bundle"), uint64(block.timestamp), 4, 3);
        pol.activatePolicy(v2);
        vm.stopPrank();

        UAIVoting.Vote[] memory votes = _quorum();
        vm.expectRevert(abi.encodeWithSelector(UAIRevocationRegistry.ThresholdNotMet.selector, 3, 4));
        vm.prank(executor);
        rev.executeRevocation(CASE_ID, AGENT_ID, PROOF, votes);
    }

    /// @notice Signature malleability: every ECDSA signature has a second,
    ///         equally valid form with s in the upper half of the curve order.
    ///         Accepting both would let one delegate be counted twice under two
    ///         spellings of the same vote.
    function test_RejectsMalleableSignature() public view {
        UAIVoting.Vote memory v = _vote(0, true);
        uint256 n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
        UAIVoting.Vote memory flipped = UAIVoting.Vote({
            delegateId: v.delegateId,
            value: v.value,
            r: v.r,
            s: bytes32(n - uint256(v.s)),
            v: v.v == 27 ? 28 : 27
        });
        assertTrue(vote.verify(CASE_ID, AGENT_ID, PROOF, v), "the canonical form must verify");
        assertFalse(vote.verify(CASE_ID, AGENT_ID, PROOF, flipped), "the malleable form must not");
    }

    /// @notice Fuzz: no set of votes below the threshold ever revokes.
    function testFuzz_NeverRevokesBelowThreshold(uint8 count) public {
        count = uint8(bound(count, 0, 2));
        _authorize();
        UAIVoting.Vote[] memory votes = new UAIVoting.Vote[](count);
        for (uint256 i = 0; i < count; i++) {
            votes[i] = _vote(i, true);
        }
                vm.expectRevert();
        vm.prank(executor);
        rev.executeRevocation(CASE_ID, AGENT_ID, PROOF, votes);
        assertFalse(rev.revoked(AGENT_ID), "no sub-threshold vote set may revoke");
    }

    /// @notice Fuzz: NO votes never count toward the quorum, however many.
    function testFuzz_NoVotesDoNotRevoke(uint8 seed) public {
        _authorize();
        UAIVoting.Vote[] memory votes = new UAIVoting.Vote[](5);
        for (uint256 i = 0; i < 5; i++) {
            votes[i] = _vote(i, false);
        }
        seed; // the shape is fixed; the fuzzer exercises repeated invocation
                vm.expectRevert(abi.encodeWithSelector(UAIRevocationRegistry.ThresholdNotMet.selector, 0, 3));
        vm.prank(executor);
        rev.executeRevocation(CASE_ID, AGENT_ID, PROOF, votes);
    }
}
