Summary

- [reentrancy-vulnerabilities-2](#reentrancy-vulnerabilities-2) (1 results) (High)
- [allows-old-versions](#allows-old-versions) (1 results) (Informational)
- [should-be-immutable](#should-be-immutable) (1 results) (Low)
- [zero-address-validation](#zero-address-validation) (1 results) (Informational)

## allows-old-versions

Impact: Informational
Confidence: Low

- [ ] ID-0
      [Pragma version^0.8.0 (src/CharityRegistry.sol#2) allows old versions]
      solc-0.8.20 is not recommended for deployment
      `Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#incorrect-versions-of-solidity`

## should-be-immutable

Impact: Low
Confidence: Low/Gas

- [ ] ID-1
      Parameter GivingThanks.updateRegistry(address).\_registry (src/GivingThanks.sol#67) is not in mixedCase
      `Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#conformance-to-solidity-naming-conventions`

src/protocol/GivingThanks.sol#L13

## zero-address-validation

Impact: Informational
Confidence: High

- [ ] ID-2
      CharityRegistry.changeAdmin(address).newAdmin (src/CharityRegistry.sol#27) lacks a zero-check on :

  - admin = newAdmin (src/CharityRegistry.sol#29)

  `Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#missing-zero-address-validation`

src/CharityRegistry.sol#29

## reentrancy-vulnerabilities-2

Impact: High
Confidence: Medium

- [ ] ID-3
      INFO:Detectors:
      Reentrancy in GivingThanks.donate(address) (src/GivingThanks.sol#21-37):
      External calls: - (sent) = charity.call{value: msg.value}() (src/GivingThanks.sol#23)
      State variables written after the call(s): - \_mint(msg.sender,tokenCounter) (src/GivingThanks.sol#26) - \_balances[from] -= 1 (lib/openzeppelin-contracts/contracts/token/ERC721/ERC721.sol#256) - \_balances[to] += 1 (lib/openzeppelin-contracts/contracts/token/ERC721/ERC721.sol#262) - \_mint(msg.sender,tokenCounter) (src/GivingThanks.sol#26) - \_owners[tokenId] = to (lib/openzeppelin-contracts/contracts/token/ERC721/ERC721.sol#266) - \_mint(msg.sender,tokenCounter) (src/GivingThanks.sol#26) - \_tokenApprovals[tokenId] = to (lib/openzeppelin-contracts/contracts/token/ERC721/ERC721.sol#424) - \_setTokenURI(tokenCounter,uri) (src/GivingThanks.sol#34) - \_tokenURIs[tokenId] = \_tokenURI (lib/openzeppelin-contracts/contracts/token/ERC721/extensions/ERC721URIStorage.sol#58) - tokenCounter += 1 (src/GivingThanks.sol#36)
      `Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#reentrancy-vulnerabilities-2`

      INFO:Detectors:
      Reentrancy in GivingThanks.donate(address) (src/GivingThanks.sol#21-37):
      External calls: - (sent) = charity.call{value: msg.value}() (src/GivingThanks.sol#23)
      Event emitted after the call(s): - Approval(owner,to,tokenId) (lib/openzeppelin-contracts/contracts/token/ERC721/ERC721.sol#420) - \_mint(msg.sender,tokenCounter) (src/GivingThanks.sol#26) - MetadataUpdate(tokenId) (lib/openzeppelin-contracts/contracts/token/ERC721/extensions/ERC721URIStorage.sol#59) - \_setTokenURI(tokenCounter,uri) (src/GivingThanks.sol#34) - Transfer(from,to,tokenId) (lib/openzeppelin-contracts/contracts/token/ERC721/ERC721.sol#268) - \_mint(msg.sender,tokenCounter) (src/GivingThanks.sol#26)
      `Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#reentrancy-vulnerabilities-3`

src/GivingThanks.sol#21-37
