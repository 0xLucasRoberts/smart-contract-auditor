// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;  // Old version without built-in overflow protection

contract OverflowExample {
    uint256 public totalSupply;
    mapping(address => uint256) public balances;
    
    constructor(uint256 _initialSupply) {
        totalSupply = _initialSupply;
        balances[msg.sender] = _initialSupply;
    }
    
    // Vulnerable to overflow
    function mint(address to, uint256 amount) external {
        balances[to] += amount;  // Can overflow
        totalSupply += amount;   // Can overflow
    }
    
    // Vulnerable to underflow  
    function burn(uint256 amount) external {
        balances[msg.sender] -= amount;  // Can underflow
        totalSupply -= amount;           // Can underflow
    }
    
    // Multiplication overflow
    function calculateReward(uint256 amount, uint256 multiplier) external pure returns (uint256) {
        return amount * multiplier;  // Can overflow
    }
    
    // Exponential overflow
    function powerCalculation(uint256 base, uint256 exp) external pure returns (uint256) {
        return base ** exp;  // Can overflow easily
    }
}