# Smart Contract Auditor

A command-line security auditing tool for Solidity smart contracts. Detects common vulnerabilities and security issues in your smart contract code.

## Features

- **Reentrancy Detection**: Identifies potential reentrancy vulnerabilities
- **Integer Overflow Detection**: Finds unsafe arithmetic operations in pre-0.8.0 contracts
- **AST Parsing**: Deep analysis of Solidity contract structure
- **Colored Output**: Easy-to-read severity-based vulnerability reports

## Installation

```bash
npm install
```

## Usage

```bash
node src/index.js <contract-file>
```

### Examples

Audit a single contract:
```bash
node src/index.js examples/vulnerable.sol
```

Verbose output:
```bash
node src/index.js examples/vulnerable.sol --verbose
```

## Vulnerability Types

### Reentrancy (HIGH)
Detects functions that make external calls before updating state variables.

### Integer Overflow (MEDIUM) 
Identifies arithmetic operations that could overflow in Solidity versions < 0.8.0.

## Example Output

```
Smart Contract Auditor v0.1.0
Analyzing contract: examples/vulnerable.sol

✓ Successfully parsed Solidity file
Found 1 contract(s):
  - VulnerableBank
    Functions: 4

Running security audit...

AUDIT RESULTS
══════════════════════════════════════════════════

[HIGH] REENTRANCY
Contract: VulnerableBank
Function: withdraw (line 12)
Description: Potential reentrancy vulnerability: state changes after external call

Summary:
  High: 1 | Medium: 0 | Low: 0 | Info: 0
```

## Testing

The `examples/` directory contains vulnerable contracts for testing:
- `vulnerable.sol` - Contains reentrancy vulnerability
- `overflow.sol` - Contains integer overflow issues

## License

MIT