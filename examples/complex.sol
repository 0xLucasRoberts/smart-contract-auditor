// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

// Complex contract with multiple vulnerability types
contract ComplexVulnerable {
    address public owner;
    mapping(address => uint256) public balances;
    mapping(address => bool) public authorized;
    uint256[] public rewards;
    
    event Transfer(address from, address to, uint256 amount);
    
    constructor() {
        owner = msg.sender;
    }
    
    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }
    
    // Multiple issues: reentrancy + access control
    function withdraw() external {
        uint256 balance = balances[msg.sender];
        require(balance > 0, "No balance");
        
        // Reentrancy vulnerability - external call before state change
        (bool success, ) = msg.sender.call{value: balance}("");
        require(success, "Transfer failed");
        
        balances[msg.sender] = 0;  // State change after external call
    }
    
    // Access control issue - missing modifier
    function mint(address to, uint256 amount) external {
        // Anyone can mint! Should be onlyOwner
        balances[to] += amount;  // Also potential overflow in 0.7.6
    }
    
    // Gas optimization issues
    function distributeRewards(address[] memory recipients) external onlyOwner {
        for (uint256 i = 0; i < recipients.length; i++) {  // Unbounded loop
            // Multiple storage reads in loop - expensive
            if (balances[recipients[i]] > 0) {
                balances[recipients[i]] += rewards[i % rewards.length];  // More storage ops
                balances[recipients[i]] *= 2;  // Potential overflow
            }
        }
    }
    
    // Public function that should be internal
    function _calculateBonus(uint256 base) public pure returns (uint256) {
        return base * 10;  // Potential overflow
    }
    
    // Multiple external calls - gas waste
    function processPayments(address[] memory recipients, uint256[] memory amounts) external {
        for (uint256 i = 0; i < recipients.length; i++) {
            // Repeated pattern - could be optimized
            require(authorized[recipients[i]], "Not authorized");
            require(authorized[recipients[i]], "Still checking");  // Redundant
            
            payable(recipients[i]).transfer(amounts[i]);
        }
    }
    
    // Proper function with good practices
    function safeTransfer(address to, uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        balances[msg.sender] -= amount;  // State change first
        balances[to] += amount;
        
        emit Transfer(msg.sender, to, amount);
    }
    
    // Owner functions
    function addAuthorized(address user) external onlyOwner {
        authorized[user] = true;
    }
    
    receive() external payable {
        balances[msg.sender] += msg.value;
    }
}