# Smart Contract Auditor

A command-line security auditing tool for Solidity smart contracts. Detects common vulnerabilities and security issues in your smart contract code.

## Features

- **Reentrancy Detection**: Identifies potential reentrancy vulnerabilities
- **Integer Overflow Detection**: Finds unsafe arithmetic operations in pre-0.8.0 contracts  
- **Access Control Analysis**: Detects missing access modifiers on critical functions
- **Gas Optimization**: Identifies expensive operations and optimization opportunities
- **AST Parsing**: Deep analysis of Solidity contract structure using @solidity-parser/parser
- **Configurable Output**: JSON and console formats with customizable colors and verbosity
- **Flexible Configuration**: JSON config files and CLI option overrides

## Installation

```bash
npm install
```

## Usage

```bash
node src/index.js <contract-file> [options]
```

### Options

- `-v, --verbose` - Show detailed vulnerability descriptions
- `--json` - Output results in JSON format
- `--no-colors` - Disable colored output  
- `--severity <levels>` - Filter by severity (high,medium,low,info)
- `--detectors <types>` - Choose detectors (reentrancy,overflow,gas,access)
- `-c, --config <path>` - Use custom config file

### Examples

Basic audit:
```bash
node src/index.js examples/vulnerable.sol
```

Verbose output with descriptions:
```bash
node src/index.js examples/vulnerable.sol --verbose
```

Only high severity issues:
```bash
node src/index.js examples/vulnerable.sol --severity high
```

JSON output for CI/CD:
```bash
node src/index.js examples/vulnerable.sol --json
```

Run only specific detectors:
```bash
node src/index.js examples/vulnerable.sol --detectors reentrancy,access
```

## Vulnerability Types

### Reentrancy (HIGH)
Detects functions that make external calls before updating state variables.

### Integer Overflow (MEDIUM) 
Identifies arithmetic operations that could overflow in Solidity versions < 0.8.0.

### Access Control (HIGH/MEDIUM)
Detects missing access control modifiers on state-changing functions.

### Gas Optimization (LOW)
Finds expensive operations like unbounded loops and repeated external calls.

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

## Configuration

Create an `audit.config.json` file to customize behavior:

```json
{
  "detectors": {
    "reentrancy": true,
    "overflow": true,
    "gas": true,
    "access": true
  },
  "severity": {
    "high": true,
    "medium": true,
    "low": false,
    "info": false
  },
  "output": {
    "format": "console",
    "verbose": false,
    "colors": true
  }
}
```

## Testing

The `examples/` directory contains contracts for testing:
- `vulnerable.sol` - Basic reentrancy vulnerability
- `overflow.sol` - Integer overflow issues (Solidity 0.7.6)
- `access.sol` - Access control vulnerabilities
- `complex.sol` - Multiple vulnerability types
- `safe.sol` - Well-secured contract example

## License

MIT