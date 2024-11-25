// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract CharityRegistry {
    address public admin;
    mapping(address => bool) public verifiedCharities;
    mapping(address => bool) public registeredCharities;

    constructor() {
        admin = msg.sender;
    }

    function registerCharity(address charity) public {
        registeredCharities[charity] = true;
    }

    function verifyCharity(address charity) public {
        require(msg.sender == admin, "Only admin can verify");
        require(registeredCharities[charity], "Charity not registered");
        verifiedCharities[charity] = true;
    }

    function isVerified(address charity) public view returns (bool) {
        return verifiedCharities[charity];
    }

    function changeAdmin(address newAdmin) public {
        require(msg.sender == admin, "Only admin can change admin");
        admin = newAdmin;
    }
}
