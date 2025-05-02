class AccessControlDetector {
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
    const modifiers = this.parser.getModifiers(contract);
    
    // Get available access control modifiers
    const accessModifiers = this.getAccessControlModifiers(modifiers);
    
    functions.forEach(func => {
      this.checkFunctionAccess(contract, func, accessModifiers);
    });
    
    // Check for missing owner functionality
    this.checkOwnershipPattern(contract, functions);
  }

  checkFunctionAccess(contract, func, availableModifiers) {
    // Skip view/pure functions
    if (this.isReadOnlyFunction(func)) return;
    
    // Skip constructor
    if (func.isConstructor) return;
    
    const isPublic = !func.visibility || func.visibility === 'public';
    const hasAccessControl = this.hasAccessControlModifier(func, availableModifiers);
    const isStateChanging = this.isStateChangingFunction(func);
    
    // Check for missing access control on state-changing functions
    if (isPublic && isStateChanging && !hasAccessControl) {
      const severity = this.assessMissingAccessControlSeverity(func);
      
      this.vulnerabilities.push({
        type: 'ACCESS_CONTROL_MISSING',
        severity: severity,
        contract: contract.name,
        function: func.name,
        line: func.loc ? func.loc.start.line : 'unknown',
        description: `Public function '${func.name}' modifies state without access control`
      });
    }
    
    // Check for functions that should be internal
    if (isPublic && this.shouldBeInternal(func)) {
      this.vulnerabilities.push({
        type: 'ACCESS_CONTROL_VISIBILITY',
        severity: 'LOW',
        contract: contract.name,
        function: func.name,
        line: func.loc ? func.loc.start.line : 'unknown',
        description: `Function '${func.name}' could be internal - only used internally`
      });
    }
  }

  checkOwnershipPattern(contract, functions) {
    const hasOwner = this.hasOwnerVariable(contract);
    const hasOnlyOwnerModifier = functions.some(func => 
      func.modifiers && func.modifiers.some(mod => 
        mod.name === 'onlyOwner' || mod.name === 'onlyAdmin'
      )
    );
    
    if (hasOnlyOwnerModifier && !hasOwner) {
      this.vulnerabilities.push({
        type: 'ACCESS_CONTROL_OWNER_PATTERN',
        severity: 'MEDIUM',
        contract: contract.name,
        function: 'contract',
        line: 'unknown',
        description: 'Contract uses owner modifiers but missing owner state variable'
      });
    }
    
    // Check for missing ownership transfer function
    if (hasOwner && !this.hasOwnershipTransfer(functions)) {
      this.vulnerabilities.push({
        type: 'ACCESS_CONTROL_OWNER_TRANSFER',
        severity: 'LOW',
        contract: contract.name,
        function: 'contract',
        line: 'unknown',
        description: 'Contract has owner but missing ownership transfer functionality'
      });
    }
  }

  getAccessControlModifiers(modifiers) {
    const accessModifiers = new Set();
    
    modifiers.forEach(modifier => {
      if (this.isAccessControlModifier(modifier.name)) {
        accessModifiers.add(modifier.name);
      }
    });
    
    return accessModifiers;
  }

  isAccessControlModifier(name) {
    const accessModifierNames = [
      'onlyOwner', 'onlyAdmin', 'onlyMinter', 'onlyBurner',
      'onlyAuthorized', 'onlyGovernance', 'onlyController',
      'requireAuth', 'onlyRole'
    ];
    
    return accessModifierNames.includes(name);
  }

  hasAccessControlModifier(func, availableModifiers) {
    if (!func.modifiers) return false;
    
    return func.modifiers.some(modifier => 
      availableModifiers.has(modifier.name) || 
      this.isAccessControlModifier(modifier.name)
    );
  }

  isReadOnlyFunction(func) {
    if (!func.modifiers) return false;
    
    return func.modifiers.some(mod => 
      mod.name === 'view' || mod.name === 'pure'
    );
  }

  isStateChangingFunction(func) {
    if (!func.body) return false;
    
    // Look for state changes in function body
    return this.containsStateChanges(func.body);
  }

  containsStateChanges(node) {
    if (!node) return false;
    
    // Check for assignments
    if (node.type === 'AssignmentOperator') return true;
    
    // Check for function calls that might change state
    if (node.type === 'FunctionCall') {
      const stateChangingCalls = [
        'transfer', 'mint', 'burn', 'approve', 'transferFrom',
        'push', 'pop', 'delete'
      ];
      
      if (node.identifiers && 
          stateChangingCalls.some(call => node.identifiers.includes(call))) {
        return true;
      }
    }
    
    // Recursively check child nodes
    if (node.statements) {
      return node.statements.some(stmt => this.containsStateChanges(stmt));
    }
    
    if (node.body) {
      return this.containsStateChanges(node.body);
    }
    
    return false;
  }

  assessMissingAccessControlSeverity(func) {
    // High severity for functions with dangerous operations
    const dangerousPatterns = ['transfer', 'withdraw', 'mint', 'burn', 'destroy'];
    const funcName = func.name.toLowerCase();
    
    if (dangerousPatterns.some(pattern => funcName.includes(pattern))) {
      return 'HIGH';
    }
    
    return 'MEDIUM';
  }

  shouldBeInternal(func) {
    // Simple heuristic: functions starting with underscore
    return func.name.startsWith('_');
  }

  hasOwnerVariable(contract) {
    if (!contract.body || !contract.body.statements) return false;
    
    const stateVars = contract.body.statements.filter(stmt => 
      stmt.type === 'StateVariableDeclaration'
    );
    
    return stateVars.some(varDecl => {
      if (varDecl.variables) {
        return varDecl.variables.some(variable => 
          ['owner', 'admin', '_owner'].includes(variable.name)
        );
      }
      return false;
    });
  }

  hasOwnershipTransfer(functions) {
    return functions.some(func => {
      const funcName = func.name.toLowerCase();
      return funcName.includes('transferownership') || 
             funcName.includes('changeowner') ||
             funcName.includes('setowner');
    });
  }
}

module.exports = AccessControlDetector;