const Parser = require('@solidity-parser/parser');
const fs = require('fs');

class SolidityParser {
  constructor() {
    this.ast = null;
    this.sourceCode = '';
  }

  parseFile(filePath) {
    try {
      this.sourceCode = fs.readFileSync(filePath, 'utf8');
      this.ast = Parser.parse(this.sourceCode, {
        loc: true,
        range: true
      });
      return this.ast;
    } catch (error) {
      throw new Error(`Failed to parse Solidity file: ${error.message}`);
    }
  }

  getContracts() {
    if (!this.ast) return [];
    
    return this.ast.children.filter(node => 
      node.type === 'ContractStatement'
    );
  }

  getFunctions(contract) {
    if (!contract || !contract.body) return [];
    
    return contract.body.statements.filter(node =>
      node.type === 'FunctionDefinition'
    );
  }

  getModifiers(contract) {
    if (!contract || !contract.body) return [];
    
    return contract.body.statements.filter(node =>
      node.type === 'ModifierDefinition'
    );
  }
}

module.exports = SolidityParser;