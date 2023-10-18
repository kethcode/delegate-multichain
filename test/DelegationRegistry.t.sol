// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";
import {DelegationRegistry} from "src/DelegationRegistry.sol";
import {IDelegationRegistry} from "src/IDelegationRegistry.sol";

import {LZEndpointMock} from "@layerzero-contracts/lzApp/mocks/LZEndpointMock.sol";

contract DelegationRegistryTest is Test {
    DelegationRegistry reg;
    DelegationRegistry reg_remote;

    LZEndpointMock public lzEndpointMock;

    address DEPLOYER = makeAddr("deployer");
    address USER1 = makeAddr("user1");

    uint256 constant ETH_EVMID = 1;
    uint256 constant OPTIMISM_EVMID = 10;
    uint256 constant BSC_EVMID = 56;
    uint256 constant POLYGON_EVMID = 137;
    uint256 constant ARBITRUM_EVMID = 42161;

    uint16 constant CHAINID_MOCK = 1128;

    uint256 constant CONTRACT_STARTING_BALANCE = 1 ether;
    uint256 constant USER_STARTING_BALANCE = 10 ether;

    function setUp() public {
        vm.startPrank(DEPLOYER);
        // deploy mock endpoint
        lzEndpointMock = new LZEndpointMock(CHAINID_MOCK);

        // deploy registries
        reg = new DelegationRegistry(address(lzEndpointMock));
        reg_remote = new DelegationRegistry(address(lzEndpointMock));

        vm.deal(DEPLOYER, USER_STARTING_BALANCE);
        vm.deal(USER1, USER_STARTING_BALANCE);

        vm.deal(address(lzEndpointMock), CONTRACT_STARTING_BALANCE);
        vm.deal(address(reg), CONTRACT_STARTING_BALANCE);
        vm.deal(address(reg_remote), CONTRACT_STARTING_BALANCE);

        // set up addresses that are allowed to send LZ calls to these contracts
        reg.setTrustedRemoteAddress(CHAINID_MOCK, abi.encodePacked(uint160(address(reg_remote))));

        reg_remote.setTrustedRemoteAddress(CHAINID_MOCK, abi.encodePacked(uint160(address(reg))));

        // Set up mock routing
        lzEndpointMock.setDestLzEndpoint(address(reg), address(lzEndpointMock));
        lzEndpointMock.setDestLzEndpoint(address(reg_remote), address(lzEndpointMock));

        // configure multichain propogation for both registries (to mock LZ Chain)
        reg.manageLZChains(ETH_EVMID, CHAINID_MOCK);
        reg_remote.manageLZChains(OPTIMISM_EVMID, CHAINID_MOCK);

        // get default_fee for current chain configuration
        uint256 default_fee = reg.estimateFee();

        vm.stopPrank();
    }

    function getInitHash() public pure returns (bytes32) {
        bytes memory bytecode = type(DelegationRegistry).creationCode;
        return keccak256(abi.encodePacked(bytecode));
    }

    function testInitHash() public {
        bytes32 initHash = getInitHash();
        emit log_bytes32(initHash);
    }

    function testEstimateFee() public view {
        uint256 fee = reg.estimateFee();
        console2.log(fee);
        assert(fee > 21000);
    }

    function testApproveAndRevokeForAll(address vault, address delegate) public {
        vm.deal(vault, USER_STARTING_BALANCE);

        // Approve
        vm.startPrank(vault);
        uint256 fee = (reg.estimateFee() * 11) / 10;
        reg.delegateForAll{value: fee}(delegate, true);

        // assert delegations have been set
        assertTrue(reg.checkDelegateForAll(delegate, vault));
        assertTrue(reg.checkDelegateForContract(delegate, vault, address(0x0)));
        assertTrue(reg.checkDelegateForToken(delegate, vault, address(0x0), 0));

        // assert delegations have been propogated to remote registry
        assertTrue(reg_remote.checkDelegateForAll(delegate, vault));
        assertTrue(reg_remote.checkDelegateForContract(delegate, vault, address(0x0)));
        assertTrue(reg_remote.checkDelegateForToken(delegate, vault, address(0x0), 0));

        // Revoke
        reg.delegateForAll{value: fee}(delegate, false);

        // assert delegations have been revoked
        assertFalse(reg.checkDelegateForAll(delegate, vault));

        // assert delegation revokation has been propogated
        assertFalse(reg_remote.checkDelegateForAll(delegate, vault));
    }

    function testApproveAndRevokeForContract(address vault, address delegate, address contract_) public {
        // Approve
        vm.startPrank(vault);
        reg.delegateForContract(delegate, contract_, true);
        assertTrue(reg.checkDelegateForContract(delegate, vault, contract_));
        assertTrue(reg.checkDelegateForToken(delegate, vault, contract_, 0));
        // Revoke
        reg.delegateForContract(delegate, contract_, false);
        assertFalse(reg.checkDelegateForContract(delegate, vault, contract_));
    }

    function testApproveAndRevokeForToken(address vault, address delegate, address contract_, uint256 tokenId) public {
        // Approve
        vm.startPrank(vault);
        reg.delegateForToken(delegate, contract_, tokenId, true);
        assertTrue(reg.checkDelegateForToken(delegate, vault, contract_, tokenId));
        // Revoke
        reg.delegateForToken(delegate, contract_, tokenId, false);
        assertFalse(reg.checkDelegateForToken(delegate, vault, contract_, tokenId));
    }

    function testMultipleDelegationForAll(address vault, address delegate0, address delegate1) public {
        vm.assume(delegate0 != delegate1);
        vm.startPrank(vault);
        reg.delegateForAll(delegate0, true);
        reg.delegateForAll(delegate1, true);
        // Read
        address[] memory delegates = reg.getDelegatesForAll(vault);
        assertEq(delegates.length, 2);
        assertEq(delegates[0], delegate0);
        assertEq(delegates[1], delegate1);
        // Remove
        reg.delegateForAll(delegate0, false);
        delegates = reg.getDelegatesForAll(vault);
        assertEq(delegates.length, 1);
    }

    function testRevokeDelegates(address vault0, address vault1, address delegate, address contract_, uint256 tokenId)
        public
    {
        vm.assume(delegate != vault0);
        vm.assume(vault0 != vault1);
        vm.startPrank(vault0);
        reg.delegateForAll(delegate, true);
        reg.delegateForContract(delegate, contract_, true);
        reg.delegateForToken(delegate, contract_, tokenId, true);
        vm.stopPrank();
        vm.startPrank(vault1);
        reg.delegateForAll(delegate, true);
        reg.delegateForContract(delegate, contract_, true);
        reg.delegateForToken(delegate, contract_, tokenId, true);
        vm.stopPrank();
        // Revoke delegates for vault0
        vm.startPrank(vault0);
        reg.revokeAllDelegates();
        vm.stopPrank();
        // Read
        address[] memory vault0DelegatesForAll = reg.getDelegatesForAll(vault0);
        assertEq(vault0DelegatesForAll.length, 0);
        address[] memory vault1DelegatesForAll = reg.getDelegatesForAll(vault1);
        assertEq(vault1DelegatesForAll.length, 1);
        address[] memory vault0DelegatesForContract = reg.getDelegatesForContract(vault0, contract_);
        assertEq(vault0DelegatesForContract.length, 0);
        address[] memory vault1DelegatesForContract = reg.getDelegatesForContract(vault1, contract_);
        assertEq(vault1DelegatesForContract.length, 1);
        address[] memory vault0DelegatesForToken = reg.getDelegatesForToken(vault0, contract_, tokenId);
        assertEq(vault0DelegatesForToken.length, 0);
        address[] memory vault1DelegatesForToken = reg.getDelegatesForToken(vault1, contract_, tokenId);
        assertEq(vault1DelegatesForToken.length, 1);

        assertFalse(reg.checkDelegateForAll(delegate, vault0));
        assertTrue(reg.checkDelegateForAll(delegate, vault1));
        assertFalse(reg.checkDelegateForContract(delegate, vault0, contract_));
        assertTrue(reg.checkDelegateForContract(delegate, vault1, contract_));
        assertFalse(reg.checkDelegateForToken(delegate, vault0, contract_, tokenId));
        assertTrue(reg.checkDelegateForToken(delegate, vault1, contract_, tokenId));
    }

    function testRevokeDelegate(address vault, address delegate0, address delegate1, address contract_, uint256 tokenId)
        public
    {
        vm.assume(vault != delegate0);
        vm.assume(delegate0 != delegate1);
        vm.startPrank(vault);
        reg.delegateForAll(delegate0, true);
        reg.delegateForContract(delegate0, contract_, true);
        reg.delegateForToken(delegate0, contract_, tokenId, true);
        reg.delegateForAll(delegate1, true);
        reg.delegateForContract(delegate1, contract_, true);
        reg.delegateForToken(delegate1, contract_, tokenId, true);

        // Revoke delegate0
        reg.revokeDelegate(delegate0);
        vm.stopPrank();
        // Read
        address[] memory vaultDelegatesForAll = reg.getDelegatesForAll(vault);
        assertEq(vaultDelegatesForAll.length, 1);
        assertEq(vaultDelegatesForAll[0], delegate1);
        address[] memory vaultDelegatesForContract = reg.getDelegatesForContract(vault, contract_);
        assertEq(vaultDelegatesForContract.length, 1);
        assertEq(vaultDelegatesForContract[0], delegate1);
        address[] memory vaultDelegatesForToken = reg.getDelegatesForToken(vault, contract_, tokenId);
        assertEq(vaultDelegatesForToken.length, 1);
        assertEq(vaultDelegatesForToken[0], delegate1);

        assertFalse(reg.checkDelegateForAll(delegate0, vault));
        assertTrue(reg.checkDelegateForAll(delegate1, vault));
        assertFalse(reg.checkDelegateForContract(delegate0, vault, contract_));
        assertTrue(reg.checkDelegateForContract(delegate1, vault, contract_));
        assertFalse(reg.checkDelegateForToken(delegate0, vault, contract_, tokenId));
        assertTrue(reg.checkDelegateForToken(delegate1, vault, contract_, tokenId));
    }

    function testRevokeSelf(address vault, address delegate0, address delegate1, address contract_, uint256 tokenId)
        public
    {
        vm.assume(vault != delegate0);
        vm.assume(delegate0 != delegate1);
        vm.startPrank(vault);
        reg.delegateForAll(delegate0, true);
        reg.delegateForContract(delegate0, contract_, true);
        reg.delegateForToken(delegate0, contract_, tokenId, true);
        reg.delegateForAll(delegate1, true);
        reg.delegateForContract(delegate1, contract_, true);
        reg.delegateForToken(delegate1, contract_, tokenId, true);

        // delegate 0 revoke self from being a delegate for vault
        changePrank(delegate0);
        reg.revokeSelf(vault);
        vm.stopPrank();
        // Read
        address[] memory vaultDelegatesForAll = reg.getDelegatesForAll(vault);
        assertEq(vaultDelegatesForAll.length, 1);
        assertEq(vaultDelegatesForAll[0], delegate1);
        address[] memory vaultDelegatesForContract = reg.getDelegatesForContract(vault, contract_);
        assertEq(vaultDelegatesForContract.length, 1);
        assertEq(vaultDelegatesForContract[0], delegate1);
        address[] memory vaultDelegatesForToken = reg.getDelegatesForToken(vault, contract_, tokenId);
        assertEq(vaultDelegatesForToken.length, 1);
        assertEq(vaultDelegatesForToken[0], delegate1);

        assertFalse(reg.checkDelegateForAll(delegate0, vault));
        assertTrue(reg.checkDelegateForAll(delegate1, vault));
        assertFalse(reg.checkDelegateForContract(delegate0, vault, contract_));
        assertTrue(reg.checkDelegateForContract(delegate1, vault, contract_));
        assertFalse(reg.checkDelegateForToken(delegate0, vault, contract_, tokenId));
        assertTrue(reg.checkDelegateForToken(delegate1, vault, contract_, tokenId));
    }

    function testDelegateEnumeration(
        address vault0,
        address vault1,
        address delegate0,
        address delegate1,
        address contract0,
        address contract1,
        uint256 tokenId0,
        uint256 tokenId1
    ) public {
        vm.assume(vault0 != vault1);
        vm.assume(vault0 != delegate0);
        vm.assume(vault0 != delegate1);
        vm.assume(vault1 != delegate0);
        vm.assume(vault1 != delegate1);
        vm.assume(delegate0 != delegate1);
        vm.assume(contract0 != contract1);
        vm.assume(tokenId0 != tokenId1);
        vm.startPrank(vault0);
        reg.delegateForAll(delegate0, true);
        reg.delegateForContract(delegate0, contract0, true);
        reg.delegateForToken(delegate0, contract1, tokenId1, true);
        reg.delegateForAll(delegate1, true);
        reg.delegateForContract(delegate1, contract0, true);
        reg.delegateForToken(delegate1, contract1, tokenId1, true);
        vm.stopPrank();

        vm.startPrank(vault1);
        reg.delegateForAll(delegate0, true);
        reg.delegateForContract(delegate0, contract1, true);
        reg.delegateForToken(delegate0, contract0, tokenId0, true);

        // Read
        IDelegationRegistry.DelegationInfo[] memory info;
        info = reg.getDelegationsByDelegate(delegate0);
        assertEq(info.length, 6);

        // Revoke
        reg.delegateForAll(delegate0, false);
        info = reg.getDelegationsByDelegate(delegate0);
        assertEq(info.length, 5);
        reg.delegateForContract(delegate0, contract1, false);
        info = reg.getDelegationsByDelegate(delegate0);
        assertEq(info.length, 4);
        reg.delegateForToken(delegate0, contract0, tokenId0, false);
        info = reg.getDelegationsByDelegate(delegate0);
        assertEq(info.length, 3);

        // Grant again
        reg.delegateForAll(delegate0, true);
        reg.delegateForContract(delegate0, contract1, true);
        reg.delegateForToken(delegate0, contract0, tokenId0, true);

        // vault1 revoke delegate0
        vm.stopPrank();
        vm.startPrank(vault0);
        reg.revokeDelegate(delegate0);
        vm.stopPrank();

        // Remaining delegations should all be related to vault1
        info = reg.getDelegationsByDelegate(delegate0);
        assertEq(info.length, 3);
        assertEq(info[0].vault, vault1);
        assertEq(info[1].vault, vault1);
        assertEq(info[2].vault, vault1);
        info = reg.getDelegationsByDelegate(delegate1);
        assertEq(info.length, 3);
        assertEq(info[0].vault, vault0);
        assertEq(info[1].vault, vault0);
        assertEq(info[2].vault, vault0);

        // vault1 revokes all delegates
        vm.startPrank(vault1);
        reg.revokeAllDelegates();
        vm.stopPrank();

        // delegate0 has no more delegations, delegate1 remains
        info = reg.getDelegationsByDelegate(delegate0);
        assertEq(info.length, 0);
        info = reg.getDelegationsByDelegate(delegate1);
        assertEq(info.length, 3);
        assertEq(info[0].vault, vault0);
        assertEq(info[1].vault, vault0);
        assertEq(info[2].vault, vault0);
    }

    function testContractLevelEnumerations(
        address vault,
        address delegate0,
        address delegate1,
        address contract0,
        address contract1,
        uint256 tokenId
    ) public {
        vm.assume(vault != delegate0);
        vm.assume(vault != delegate1);
        vm.assume(delegate0 != delegate1);
        vm.assume(contract0 != contract1);
        vm.startPrank(vault);
        reg.delegateForAll(delegate0, true);
        reg.delegateForContract(delegate0, contract0, true);
        reg.delegateForToken(delegate0, contract1, tokenId, true);
        reg.delegateForAll(delegate1, true);
        reg.delegateForContract(delegate1, contract0, true);

        // Read
        IDelegationRegistry.ContractDelegation[] memory contractDelegations;
        contractDelegations = reg.getContractLevelDelegations(vault);
        assertEq(contractDelegations.length, 2);
        assertEq(contractDelegations[0].contract_, contract0);
        assertEq(contractDelegations[1].contract_, contract0);
        assertEq(contractDelegations[0].delegate, delegate0);
        assertEq(contractDelegations[1].delegate, delegate1);

        // Delegate for another contract
        reg.delegateForContract(delegate0, contract1, true);

        // Read
        contractDelegations = reg.getContractLevelDelegations(vault);
        assertEq(contractDelegations.length, 3);
        assertEq(contractDelegations[0].contract_, contract0);
        assertEq(contractDelegations[1].contract_, contract0);
        assertEq(contractDelegations[2].contract_, contract1);
        assertEq(contractDelegations[0].delegate, delegate0);
        assertEq(contractDelegations[1].delegate, delegate1);
        assertEq(contractDelegations[2].delegate, delegate0);

        // Revoke single contract
        reg.delegateForContract(delegate0, contract0, false);

        // Read
        contractDelegations = reg.getContractLevelDelegations(vault);
        assertEq(contractDelegations.length, 2);
        assertEq(contractDelegations[0].contract_, contract1);
        assertEq(contractDelegations[1].contract_, contract0);
        assertEq(contractDelegations[0].delegate, delegate0);
        assertEq(contractDelegations[1].delegate, delegate1);

        // Revoke Delegate
        reg.revokeDelegate(delegate1);

        // Read
        contractDelegations = reg.getContractLevelDelegations(vault);
        assertEq(contractDelegations.length, 1);
        assertEq(contractDelegations[0].contract_, contract1);
        assertEq(contractDelegations[0].delegate, delegate0);

        // Add back delegate
        reg.delegateForContract(delegate1, contract1, true);

        // Read
        contractDelegations = reg.getContractLevelDelegations(vault);
        assertEq(contractDelegations.length, 2);
        assertEq(contractDelegations[0].contract_, contract1);
        assertEq(contractDelegations[1].contract_, contract1);
        assertEq(contractDelegations[0].delegate, delegate0);
        assertEq(contractDelegations[1].delegate, delegate1);

        // Revoke all
        reg.revokeAllDelegates();

        // Read
        contractDelegations = reg.getContractLevelDelegations(vault);
        assertEq(contractDelegations.length, 0);
    }

    function testTokenLevelEnumerations(
        address vault,
        address delegate0,
        address delegate1,
        address contract0,
        address contract1,
        uint256 tokenId0,
        uint256 tokenId1
    ) public {
        vm.assume(vault != delegate0);
        vm.assume(vault != delegate1);
        vm.assume(delegate0 != delegate1);
        vm.assume(contract0 != contract1);
        vm.assume(tokenId0 != tokenId1);
        vm.startPrank(vault);
        reg.delegateForAll(delegate0, true);
        reg.delegateForContract(delegate0, contract0, true);
        reg.delegateForToken(delegate0, contract0, tokenId0, true);
        reg.delegateForAll(delegate1, true);
        reg.delegateForToken(delegate1, contract0, tokenId0, true);

        // Read
        IDelegationRegistry.TokenDelegation[] memory tokenDelegations;
        tokenDelegations = reg.getTokenLevelDelegations(vault);
        assertEq(tokenDelegations.length, 2);
        assertEq(tokenDelegations[0].contract_, contract0);
        assertEq(tokenDelegations[1].contract_, contract0);
        assertEq(tokenDelegations[0].tokenId, tokenId0);
        assertEq(tokenDelegations[1].tokenId, tokenId0);
        assertEq(tokenDelegations[0].delegate, delegate0);
        assertEq(tokenDelegations[1].delegate, delegate1);

        // Delegate for another token
        reg.delegateForToken(delegate0, contract0, tokenId1, true);

        // Read
        tokenDelegations = reg.getTokenLevelDelegations(vault);
        assertEq(tokenDelegations.length, 3);
        assertEq(tokenDelegations[0].contract_, contract0);
        assertEq(tokenDelegations[1].contract_, contract0);
        assertEq(tokenDelegations[2].contract_, contract0);
        assertEq(tokenDelegations[0].tokenId, tokenId0);
        assertEq(tokenDelegations[1].tokenId, tokenId0);
        assertEq(tokenDelegations[2].tokenId, tokenId1);
        assertEq(tokenDelegations[0].delegate, delegate0);
        assertEq(tokenDelegations[1].delegate, delegate1);
        assertEq(tokenDelegations[2].delegate, delegate0);

        // Revoke token
        reg.delegateForToken(delegate0, contract0, tokenId0, false);

        // Read
        tokenDelegations = reg.getTokenLevelDelegations(vault);
        assertEq(tokenDelegations.length, 2);
        assertEq(tokenDelegations[0].contract_, contract0);
        assertEq(tokenDelegations[1].contract_, contract0);
        assertEq(tokenDelegations[0].tokenId, tokenId1);
        assertEq(tokenDelegations[1].tokenId, tokenId0);
        assertEq(tokenDelegations[0].delegate, delegate0);
        assertEq(tokenDelegations[1].delegate, delegate1);

        // Add token on different contract
        reg.delegateForToken(delegate0, contract1, tokenId0, true);

        // Read
        tokenDelegations = reg.getTokenLevelDelegations(vault);
        assertEq(tokenDelegations.length, 3);
        assertEq(tokenDelegations[0].contract_, contract0);
        assertEq(tokenDelegations[1].contract_, contract0);
        assertEq(tokenDelegations[2].contract_, contract1);
        assertEq(tokenDelegations[0].tokenId, tokenId1);
        assertEq(tokenDelegations[1].tokenId, tokenId0);
        assertEq(tokenDelegations[2].tokenId, tokenId0);
        assertEq(tokenDelegations[0].delegate, delegate0);
        assertEq(tokenDelegations[1].delegate, delegate1);
        assertEq(tokenDelegations[2].delegate, delegate0);

        // Revoke Delegate
        reg.revokeDelegate(delegate1);

        // Read
        tokenDelegations = reg.getTokenLevelDelegations(vault);
        assertEq(tokenDelegations.length, 2);
        assertEq(tokenDelegations[0].contract_, contract0);
        assertEq(tokenDelegations[1].contract_, contract1);
        assertEq(tokenDelegations[0].tokenId, tokenId1);
        assertEq(tokenDelegations[1].tokenId, tokenId0);
        assertEq(tokenDelegations[0].delegate, delegate0);
        assertEq(tokenDelegations[1].delegate, delegate0);

        // Add back delegate, then revoke all
        reg.delegateForToken(delegate1, contract0, tokenId0, true);
        reg.revokeAllDelegates();

        // Read
        tokenDelegations = reg.getTokenLevelDelegations(vault);
        assertEq(tokenDelegations.length, 0);
    }
}
