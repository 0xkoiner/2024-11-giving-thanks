# First Flight #29: TwentyOne

- Starts: November 21, 2024 Noon UTC
- Ends: November 28, 2024 Noon UTC

- nSLOC: 147

[//]: # "contest-details-open"

## About the Project

The "TwentyOne" protocol is a smart contract implementation of the classic blackjack card game, where users can wager 1 ETH to participate with a chance to double their money!

## Actors

- Player: The user who interacts with the contract to start and play a game. A player must deposit 1 ETH to play, with a maximum payout of 2 ETH upon winning.
- Dealer: The virtual counterpart managed by the smart contract. The dealer draws cards based on game logic.

[//]: # "contest-details-close"
[//]: # "scope-open"

## Scope (contracts)

```
All Contracts in `src` are in scope.
```

```js
src/
└── TwentyOne.sol
```

## @audit

All Findings in `@audit` and full report.

```js
├── @audit
│   ├── audit-report
│       ├── auditreportforpdf.md
│       └── auditreportforpdf.pdf

```

## Compatibilities

Compatibilities:
Blockchains: - Ethereum/Any EVM
Tokens: - ETH

[//]: # "scope-close"
[//]: # "getting-started-open"

## Setup

Build:

```bash
git clone https://github.com/Cyfrin/2024-11-twentyone.git

cd 2024-11-twentyone
 
forge build
```

Tests:

```bash
Forge test
```

[//]: # "getting-started-close"
[//]: # "known-issues-open"

## Known Issues

No known issues

[//]: # "known-issues-close"
