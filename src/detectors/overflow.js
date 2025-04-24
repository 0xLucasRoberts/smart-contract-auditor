class OverflowDetector {
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
    // Check pragma version for SafeMath requirement
    const pragmaVersion = this.getPragmaVersion();
    const needsSafeMath = this.needsSafeMathCheck(pragmaVersion);
    
    if (needsSafeMath) {
      const hasSafeMath = this.contractUsesSafeMath(contract);
      
      if (!hasSafeMath) {
        const functions = this.parser.getFunctions(contract);
        
        functions.forEach(func => {
          this.checkFunctionForArithmetic(contract, func);
        });
      }
    }
  }

  getPragmaVersion() {
    if (!this.parser.ast || !this.parser.ast.children) return null;
    
    const pragmaNode = this.parser.ast.children.find(node => 
      node.type === 'PragmaDirective' && node.name === 'solidity'
    );
    
    return pragmaNode ? pragmaNode.value : null;
  }

  needsSafeMathCheck(pragmaVersion) {
    if (!pragmaVersion) return true;
    
    // Versions before 0.8.0 need SafeMath checks
    const match = pragmaVersion.match(/(\d+)\.(\d+)\.(\d+)/);
    if (match) {
      const major = parseInt(match[1]);
      const minor = parseInt(match[2]);
      return major === 0 && minor < 8;
    }
    
    return true; // Conservative approach
  }

  contractUsesSafeMath(contract) {
    // Check if contract imports SafeMath
    if (this.parser.ast && this.parser.ast.children) {
      const imports = this.parser.ast.children.filter(node => 
        node.type === 'ImportDirective'
      );
      
      return imports.some(imp => 
        imp.path && imp.path.includes('SafeMath')
      );
    }
    
    // Check if contract uses SafeMath library
    if (contract.body && contract.body.statements) {
      return contract.body.statements.some(stmt => 
        stmt.type === 'UsingForDeclaration' && 
        stmt.libraryName === 'SafeMath'
      );
    }
    
    return false;
  }

  checkFunctionForArithmetic(contract, func) {
    if (!func.body) return;
    
    const arithmeticOps = this.findArithmeticOperations(func.body);
    
    arithmeticOps.forEach(op => {
      this.vulnerabilities.push({
        type: 'INTEGER_OVERFLOW',
        severity: 'MEDIUM',
        contract: contract.name,
        function: func.name,
        line: op.line || 'unknown',
        description: `Potential integer overflow in ${op.operator} operation. Consider using SafeMath.`
      });
    });
  }

  findArithmeticOperations(node, operations = []) {
    if (!node) return operations;

    if (node.type === 'BinaryOperation') {
      const dangerousOps = ['+', '-', '*', '**'];
      if (dangerousOps.includes(node.operator)) {
        operations.push({
          operator: node.operator,
          line: node.loc ? node.loc.start.line : 'unknown'
        });
      }
    }

    // Check assignments that could overflow
    if (node.type === 'AssignmentOperator') {
      const compoundOps = ['+=', '-=', '*='];
      if (compoundOps.includes(node.operator)) {
        operations.push({
          operator: node.operator,
          line: node.loc ? node.loc.start.line : 'unknown'
        });
      }
    }

    // Recursively check child nodes
    if (node.statements) {
      node.statements.forEach(stmt => 
        this.findArithmeticOperations(stmt, operations)
      );
    }

    if (node.body) {
      this.findArithmeticOperations(node.body, operations);
    }

    if (node.left) {
      this.findArithmeticOperations(node.left, operations);
    }

    if (node.right) {
      this.findArithmeticOperations(node.right, operations);
    }

    return operations;
  }
}

module.exports = OverflowDetector;