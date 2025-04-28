class GasOptimizationDetector {
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
      this.checkFunctionForGasIssues(contract, func);
    });
    
    this.checkStateVariableOptimizations(contract);
  }

  checkFunctionForGasIssues(contract, func) {
    if (!func.body) return;
    
    // Check for loops that could be expensive
    this.checkForExpensiveLoops(contract, func);
    
    // Check for repeated external calls
    this.checkRepeatedExternalCalls(contract, func);
    
    // Check for unnecessary storage reads
    this.checkStorageOptimizations(contract, func);
  }

  checkForExpensiveLoops(contract, func) {
    const loops = this.findLoops(func.body);
    
    loops.forEach(loop => {
      // Check if loop has unbounded iteration
      if (this.hasUnboundedIteration(loop)) {
        this.vulnerabilities.push({
          type: 'GAS_UNBOUNDED_LOOP',
          severity: 'LOW',
          contract: contract.name,
          function: func.name,
          line: loop.line || 'unknown',
          description: 'Unbounded loop detected. Consider adding limits or using pagination.'
        });
      }
      
      // Check for expensive operations in loops
      if (this.hasExpensiveOperationsInLoop(loop)) {
        this.vulnerabilities.push({
          type: 'GAS_EXPENSIVE_LOOP',
          severity: 'LOW',
          contract: contract.name,
          function: func.name,
          line: loop.line || 'unknown',
          description: 'Expensive operations detected in loop. Consider optimization.'
        });
      }
    });
  }

  checkRepeatedExternalCalls(contract, func) {
    // Check for multiple calls to the same external function
    const externalCalls = this.findExternalCalls(func.body);
    const callCounts = {};
    
    externalCalls.forEach(call => {
      const callSignature = this.getCallSignature(call);
      callCounts[callSignature] = (callCounts[callSignature] || 0) + 1;
    });
    
    Object.entries(callCounts).forEach(([signature, count]) => {
      if (count > 1) {
        this.vulnerabilities.push({
          type: 'GAS_REPEATED_CALLS',
          severity: 'LOW',
          contract: contract.name,
          function: func.name,
          line: 'multiple',
          description: `Function makes ${count} calls to ${signature}. Consider caching the result.`
        });
      }
    });
  }

  checkStorageOptimizations(contract, func) {
    // Look for storage variables read multiple times
    const storageReads = this.findStorageReads(func.body);
    const readCounts = {};
    
    storageReads.forEach(read => {
      readCounts[read.variable] = (readCounts[read.variable] || 0) + 1;
    });
    
    Object.entries(readCounts).forEach(([variable, count]) => {
      if (count > 2) {
        this.vulnerabilities.push({
          type: 'GAS_STORAGE_OPTIMIZATION',
          severity: 'LOW',
          contract: contract.name,
          function: func.name,
          line: 'multiple',
          description: `Storage variable '${variable}' read ${count} times. Consider caching in memory.`
        });
      }
    });
  }

  checkStateVariableOptimizations(contract) {
    if (!contract.body || !contract.body.statements) return;
    
    const stateVars = contract.body.statements.filter(stmt => 
      stmt.type === 'StateVariableDeclaration'
    );
    
    // Check for public arrays/mappings
    stateVars.forEach(varDecl => {
      if (varDecl.variables) {
        varDecl.variables.forEach(variable => {
          if (variable.visibility === 'public' && this.isComplexType(variable.typeName)) {
            this.vulnerabilities.push({
              type: 'GAS_PUBLIC_COMPLEX_TYPE',
              severity: 'LOW',
              contract: contract.name,
              function: 'state variable',
              line: variable.loc ? variable.loc.start.line : 'unknown',
              description: `Public ${this.getTypeName(variable.typeName)} '${variable.name}' generates expensive getter. Consider private with custom getter.`
            });
          }
        });
      }
    });
  }

  findLoops(node, loops = []) {
    if (!node) return loops;
    
    if (node.type === 'ForStatement' || node.type === 'WhileStatement') {
      loops.push({
        type: node.type,
        line: node.loc ? node.loc.start.line : 'unknown',
        node: node
      });
    }
    
    if (node.statements) {
      node.statements.forEach(stmt => this.findLoops(stmt, loops));
    }
    
    if (node.body) {
      this.findLoops(node.body, loops);
    }
    
    return loops;
  }

  hasUnboundedIteration(loop) {
    // Simple check - in real implementation would need more sophisticated analysis
    if (loop.type === 'WhileStatement') return true;
    
    // Check if for loop uses array.length without bounds checking
    if (loop.node && loop.node.condition) {
      const conditionStr = JSON.stringify(loop.node.condition);
      return conditionStr.includes('length') && !conditionStr.includes('min');
    }
    
    return false;
  }

  hasExpensiveOperationsInLoop(loop) {
    if (!loop.node || !loop.node.body) return false;
    
    // Look for external calls, storage writes, or complex operations in loop
    const hasExpensiveOps = this.containsExpensiveOperations(loop.node.body);
    return hasExpensiveOps;
  }

  containsExpensiveOperations(node) {
    if (!node) return false;
    
    // Check for external calls
    if (node.type === 'FunctionCall' && this.isExternalCall(node)) {
      return true;
    }
    
    // Check for storage assignments
    if (node.type === 'AssignmentOperator') {
      return true;
    }
    
    // Recursively check child nodes
    if (node.statements) {
      return node.statements.some(stmt => this.containsExpensiveOperations(stmt));
    }
    
    if (node.body) {
      return this.containsExpensiveOperations(node.body);
    }
    
    return false;
  }

  findExternalCalls(node, calls = []) {
    // Simplified implementation
    return calls;
  }

  findStorageReads(node, reads = []) {
    // Simplified implementation
    return reads;
  }

  getCallSignature(call) {
    return 'external_call';
  }

  isComplexType(typeName) {
    if (!typeName) return false;
    
    const complexTypes = ['mapping', 'array'];
    return complexTypes.some(type => 
      typeName.type && typeName.type.toLowerCase().includes(type)
    );
  }

  isExternalCall(node) {
    return false; // Simplified
  }

  getTypeName(typeName) {
    return typeName.type || 'unknown';
  }
}

module.exports = GasOptimizationDetector;