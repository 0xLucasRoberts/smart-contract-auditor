// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract AccessControlExample {
    address public owner;
    uint256 public totalSupply;
    mapping(address => uint256) public balances;
    
    constructor() {
        owner = msg.sender;
        totalSupply = 1000000;
    }
    
    // Missing access control - anyone can mint!
    function mint(address to, uint256 amount) external {
        balances[to] += amount;
        totalSupply += amount;
    }
    
    // Missing access control - anyone can burn others' tokens!
    function burn(address from, uint256 amount) external {
        balances[from] -= amount;
        totalSupply -= amount;
    }
    
    // Dangerous function without protection
    function emergencyWithdraw() external {
        payable(msg.sender).transfer(address(this).balance);
    }
    
    // This should be internal
    function _calculateFee(uint256 amount) public pure returns (uint256) {
        return amount / 100;
    }
    
    // Good: properly protected function
    function transferOwnership(address newOwner) external {
        require(msg.sender == owner, "Only owner");
        owner = newOwner;
    }
    
    // View function - no access control needed
    function getBalance(address account) external view returns (uint256) {
        return balances[account];
    }
    
    receive() external payable {}
}