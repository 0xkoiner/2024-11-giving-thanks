// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test, console} from "forge-std/Test.sol";
import "../src/GivingThanks.sol";
import "../src/CharityRegistry.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "@openzeppelin/contracts/utils/Base64.sol";

contract GivingThanksTest is Test {
    GivingThanks public charityContract;
    CharityRegistry public registryContract;
    address public admin;
    address public charity;
    address public donor;

    function setUp() public {
        // Initialize addresses
        admin = makeAddr("admin");
        charity = makeAddr("charity");
        donor = makeAddr("donor");

        // Deploy the CharityRegistry contract as admin
        vm.prank(admin);
        registryContract = new CharityRegistry();

        // Deploy the GivingThanks contract with the registry address
        vm.prank(admin);
        charityContract = new GivingThanks(address(registryContract));

        // Register and verify the charity
        vm.prank(admin);
        registryContract.registerCharity(charity);

        vm.prank(admin);
        registryContract.verifyCharity(charity);
    }

    function testDonate() public {
        uint256 donationAmount = 1 ether;

        // Check initial token counter
        uint256 initialTokenCounter = charityContract.tokenCounter();

        // Fund the donor
        vm.deal(donor, 10 ether);

        // Donor donates to the charity
        vm.prank(donor);
        charityContract.donate{value: donationAmount}(charity);

        // Check that the NFT was minted
        uint256 newTokenCounter = charityContract.tokenCounter();
        assertEq(newTokenCounter, initialTokenCounter + 1);

        // Verify ownership of the NFT
        address ownerOfToken = charityContract.ownerOf(initialTokenCounter);
        assertEq(ownerOfToken, donor);

        // Verify that the donation was sent to the charity
        uint256 charityBalance = charity.balance;
        assertEq(charityBalance, donationAmount);
    }

    function testCannotDonateToUnverifiedCharity() public {
        address unverifiedCharity = address(0x4);

        // Unverified charity registers but is not verified
        vm.prank(unverifiedCharity);
        registryContract.registerCharity(unverifiedCharity);

        // Fund the donor
        vm.deal(donor, 10 ether);

        // Donor tries to donate to unverified charity
        vm.prank(donor);
        vm.expectRevert();
        charityContract.donate{value: 1 ether}(unverifiedCharity);
    }

    function testFuzzDonate(uint96 donationAmount) public {
        // Limit the donation amount to a reasonable range
        donationAmount = uint96(bound(donationAmount, 1 wei, 10 ether));

        // Fund the donor
        vm.deal(donor, 20 ether);

        // Record initial balances
        uint256 initialTokenCounter = charityContract.tokenCounter();
        uint256 initialCharityBalance = charity.balance;

        // Donor donates to the charity
        vm.prank(donor);
        charityContract.donate{value: donationAmount}(charity);

        // Verify that the NFT was minted
        uint256 newTokenCounter = charityContract.tokenCounter();
        assertEq(newTokenCounter, initialTokenCounter + 1);

        // Verify ownership of the NFT
        address ownerOfToken = charityContract.ownerOf(initialTokenCounter);
        assertEq(ownerOfToken, donor);

        // Verify that the donation was sent to the charity
        uint256 charityBalance = charity.balance;
        assertEq(charityBalance, initialCharityBalance + donationAmount);
    }

    /*////////////////////////////////////////////////////////
                @Audit Tests CharityRegistry.sol              
    //////////////////////////////////////////////////////////*/

    /*////////////////////////////////////////////////////////
              Test changeAdmin Only Admin
   //////////////////////////////////////////////////////////*/

    function testCharityRegistryChangeAdminWithAdmin() public {
        address newAdmin = makeAddr("newAdmin");

        vm.startPrank(admin);
        registryContract.changeAdmin(newAdmin);
        vm.stopPrank();
        address updatedAdmin = registryContract.admin();

        assertEq(newAdmin, updatedAdmin);
    }

    /*////////////////////////////////////////////////////////
            Test changeAdmin Only Admin Revert
    //////////////////////////////////////////////////////////*/

    function testCharityRegistryChangeAdminWithAdminRevert() public {
        address newAdmin = makeAddr("newAdmin");

        vm.startPrank(donor);
        vm.expectRevert("Only admin can change admin");
        registryContract.changeAdmin(newAdmin);
        vm.stopPrank();
    }

    /*////////////////////////////////////////////////////////
             Test verifyCharity Only Admin              
    //////////////////////////////////////////////////////////*/

    function testCharityVerifyCharityAdminWithAdmin() public {
        address newCharity = makeAddr("newCharity");
        vm.startPrank(newCharity);
        registryContract.registerCharity(newCharity);
        vm.stopPrank();

        vm.startPrank(admin);
        registryContract.verifyCharity(newCharity);
        vm.stopPrank();
        assert(registryContract.isVerified(newCharity));
    }

    /*////////////////////////////////////////////////////////
            Test verifyCharity Only Admin Revert
    //////////////////////////////////////////////////////////*/

    function testCharityVerifyCharityAdminWithAdminRevert() public {
        address newCharity = makeAddr("newCharity");
        vm.startPrank(newCharity);
        registryContract.registerCharity(newCharity);
        vm.stopPrank();

        vm.startPrank(donor);
        vm.expectRevert("Only admin can verify");
        registryContract.verifyCharity(newCharity);
        vm.stopPrank();
    }

    /*////////////////////////////////////////////////////////
      Test verifyCharity Only Admin Revert registeredCharities
    //////////////////////////////////////////////////////////*/

    function testCharityVerifyCharityAdminWithAdminRevertNotRegisteredCharities()
        public
    {
        address newCharity = makeAddr("newCharity");

        vm.startPrank(admin);
        vm.expectRevert("Charity not registered");
        registryContract.verifyCharity(newCharity);
        vm.stopPrank();
    }

    /*////////////////////////////////////////////////////////
                @Audit Tests GivingThanks.sol           
    //////////////////////////////////////////////////////////*/

    /*//////////////////////////////////////////////////////////
        Test updateRegistry Not Protected by Admin !!!!!!!!       
    ////////////////////////////////////////////////////////////*/

    function testGivingThanksUpdateRegistryNotProtected() public {
        address oldRegistryAddress = address(charityContract.registry());

        address attackerAddress = makeAddr("attackerAddress");
        vm.startPrank(attackerAddress);
        charityContract.updateRegistry(attackerAddress);
        vm.stopPrank();

        address updatedRegistryAddress = address(charityContract.registry());

        assertNotEq(oldRegistryAddress, updatedRegistryAddress);
    }

    /*//////////////////////////////////////////////////////////
             Test _createTokenURI Correct Values           
    ////////////////////////////////////////////////////////////*/

    function testGivingThanksCreateTokenURIReturnCorrectValues() public {
        uint256 donationAmount = 1 ether;
        uint256 initialTokenCounter = charityContract.tokenCounter();

        vm.deal(donor, 10 ether);
        vm.prank(donor);

        charityContract.donate{value: donationAmount}(charity);

        uint256 newTokenCounter = charityContract.tokenCounter();
        assertEq(newTokenCounter, initialTokenCounter + 1);

        address ownerOfToken = charityContract.ownerOf(initialTokenCounter);
        assertEq(ownerOfToken, donor);

        uint256 charityBalance = charity.balance;
        assertEq(charityBalance, donationAmount);

        console.log(block.timestamp);
        console.log(donor);
        string memory resFromFunction = charityContract._createTokenURI(
            donor,
            block.timestamp,
            1 ether
        );

        console.log(resFromFunction);

        string memory checkURI = charityContract.tokenURI(0);
        console.log(checkURI);

        assertEq(checkURI, resFromFunction);
    }
}
