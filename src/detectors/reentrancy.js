class ReentrancyDetector {
  constructor(parser) {
    this.parser = parser;
    this.vulnerabilities = [];
  }

  detect() {
    this.vulnerabilities = [];
    const contracts = this.parser.getContracts();

    contracts.forEach(contract => {
      this.checkContract(contract);
    });

    return this.vulnerabilities;
  }

  checkContract(contract) {
    const functions = this.parser.getFunctions(contract);
    
    functions.forEach(func => {
      if (this.isStateChangingFunction(func) && this.hasExternalCall(func)) {
        const hasStateChangeAfterCall = this.hasStateChangeAfterExternalCall(func);
        
        if (hasStateChangeAfterCall) {
          this.vulnerabilities.push({
            type: 'REENTRANCY',
            severity: 'HIGH',
            contract: contract.name,
            function: func.name,
            line: func.loc ? func.loc.start.line : 'unknown',
            description: 'Potential reentrancy vulnerability: state changes after external call'
          });
        }
      }
    });
  }

  isStateChangingFunction(func) {
    if (!func.modifiers) return true;
    
    const readOnlyModifiers = ['view', 'pure'];
    return !func.modifiers.some(mod => 
      readOnlyModifiers.includes(mod.name)
    );
  }

  hasExternalCall(func) {
    return this.traverseForExternalCalls(func.body);
  }

  traverseForExternalCalls(node) {
    if (!node) return false;

    if (node.type === 'FunctionCall') {
      // Check for .call(), .send(), or similar
      if (node.identifiers && 
          (node.identifiers.includes('call') || 
           node.identifiers.includes('send') ||
           node.identifiers.includes('transfer'))) {
        return true;
      }
    }

    // Recursively check child nodes
    if (node.statements) {
      return node.statements.some(stmt => this.traverseForExternalCalls(stmt));
    }

    if (node.body) {
      return this.traverseForExternalCalls(node.body);
    }

    return false;
  }

  hasStateChangeAfterExternalCall(func) {
    // Simplified check - in real implementation would need more sophisticated analysis
    if (!func.body || !func.body.statements) return false;
    
    let foundExternalCall = false;
    
    for (const stmt of func.body.statements) {
      if (this.traverseForExternalCalls(stmt)) {
        foundExternalCall = true;
      } else if (foundExternalCall && this.isStateChange(stmt)) {
        return true;
      }
    }
    
    return false;
  }

  isStateChange(stmt) {
    if (!stmt) return false;
    
    // Check for assignments
    if (stmt.type === 'AssignmentOperator') return true;
    
    // Check for function calls that might change state
    if (stmt.type === 'ExpressionStatement' && stmt.expression) {
      const expr = stmt.expression;
      if (expr.type === 'FunctionCall') {
        // Common state-changing patterns
        const stateChangingCalls = ['transfer', 'mint', 'burn', 'approve'];
        return stateChangingCalls.some(call => 
          expr.identifiers && expr.identifiers.includes(call)
        );
      }
    }
    
    return false;
  }
}

module.exports = ReentrancyDetector;