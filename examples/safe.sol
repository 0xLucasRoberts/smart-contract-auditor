// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;  // Latest version with built-in overflow protection

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

// Example of a well-secured contract
contract SafeToken is Ownable, ReentrancyGuard {
    mapping(address => uint256) private _balances;
    mapping(address => bool) private _authorized;
    
    uint256 private _totalSupply;
    string public name = "SafeToken";
    string public symbol = "SAFE";
    
    event Transfer(address indexed from, address indexed to, uint256 value);
    event AuthorizedAdded(address indexed user);
    event AuthorizedRemoved(address indexed user);
    
    constructor(uint256 initialSupply) {
        _totalSupply = initialSupply;
        _balances[msg.sender] = initialSupply;
        emit Transfer(address(0), msg.sender, initialSupply);
    }
    
    modifier onlyAuthorized() {
        require(_authorized[msg.sender] || msg.sender == owner(), "Not authorized");
        _;
    }
    
    // Safe withdrawal with reentrancy protection
    function withdraw(uint256 amount) external nonReentrant {
        require(_balances[msg.sender] >= amount, "Insufficient balance");
        
        // State changes before external call
        _balances[msg.sender] -= amount;
        
        // Safe external call
        (bool success, ) = payable(msg.sender).call{value: amount}("");
        require(success, "Transfer failed");
        
        emit Transfer(msg.sender, address(0), amount);
    }
    
    // Properly protected minting
    function mint(address to, uint256 amount) external onlyOwner {
        require(to != address(0), "Invalid recipient");
        
        _balances[to] += amount;
        _totalSupply += amount;
        
        emit Transfer(address(0), to, amount);
    }
    
    // Gas-optimized batch operations
    function batchTransfer(
        address[] calldata recipients, 
        uint256[] calldata amounts
    ) external onlyAuthorized {
        require(recipients.length == amounts.length, "Length mismatch");
        require(recipients.length <= 100, "Too many recipients"); // Bounded
        
        uint256 totalAmount = 0;
        
        // Calculate total first to check balance once
        for (uint256 i = 0; i < amounts.length; i++) {
            totalAmount += amounts[i];
        }
        
        require(_balances[msg.sender] >= totalAmount, "Insufficient balance");
        
        // Update balances efficiently
        _balances[msg.sender] -= totalAmount;
        
        for (uint256 i = 0; i < recipients.length; i++) {
            require(recipients[i] != address(0), "Invalid recipient");
            _balances[recipients[i]] += amounts[i];
            emit Transfer(msg.sender, recipients[i], amounts[i]);
        }
    }
    
    // Internal helper function (proper visibility)
    function _beforeTokenTransfer(
        address from, 
        address to, 
        uint256 amount
    ) internal virtual {
        // Custom logic can be added here
    }
    
    // View functions
    function balanceOf(address account) external view returns (uint256) {
        return _balances[account];
    }
    
    function totalSupply() external view returns (uint256) {
        return _totalSupply;
    }
    
    function isAuthorized(address user) external view returns (bool) {
        return _authorized[user];
    }
    
    // Admin functions
    function addAuthorized(address user) external onlyOwner {
        require(user != address(0), "Invalid address");
        require(!_authorized[user], "Already authorized");
        
        _authorized[user] = true;
        emit AuthorizedAdded(user);
    }
    
    function removeAuthorized(address user) external onlyOwner {
        require(_authorized[user], "Not authorized");
        
        _authorized[user] = false;
        emit AuthorizedRemoved(user);
    }
    
    // Emergency functions
    function pause() external onlyOwner {
        // Implementation would use OpenZeppelin's Pausable
    }
    
    receive() external payable {
        // Safe to receive ETH
    }
}