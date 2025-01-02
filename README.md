First Flight #28: GivingThanks
Starts: November 07, 2024 Noon UTC

Ends: November 14, 2024 Noon UTC

nSLOC: 67

About the Project
About the Project

GivingThanks is a decentralized platform that embodies the spirit of Thanksgiving by enabling donors to contribute Ether to registered and verified charitable causes. Charities can register themselves, and upon verification by the trusted admin, they become eligible to receive donations from generous participants. When donors make a donation, they receive a unique NFT as a donation receipt, commemorating their contribution. The NFT's metadata includes the donor's address, the date of the donation, and the amount donated.

Actors
Admin (Trusted) - Can verify registered charities.
Charities - Can register to receive donations once verified.
Donors - Can donate Ether to verified charities and receive a donation receipt NFT.
Scope (contracts)
All Contracts in `src` are in scope.
├── src
│   ├── CharityRegistry.sol
│   └── GivingThanks.sol
@audit
All Findings in @audit and full report.

├── @audit
│   ├── audit-report
│       ├── auditreportforpdf.md
│       └── auditreportforpdf.pdf
Compatibilities
Compatibilities: Blockchains: - Ethereum/Any EVM Tokens: - ETH - ERC721

Setup
Build:

git clone https://github.com/Cyfrin/2024-11-giving-thanks.git

cd 2024-11-giving-thanks

forge build
Tests:

Forge test
Known Issues
No known issues
