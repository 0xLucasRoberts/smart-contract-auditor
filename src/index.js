#!/usr/bin/env node

const { program } = require('commander');
const chalk = require('chalk');
const fs = require('fs');
const SolidityParser = require('./parser');
const ContractAuditor = require('./auditor');
const ConfigManager = require('./config');

program
  .name('smart-contract-auditor')
  .description('Security auditing tool for Solidity smart contracts')
  .version('0.1.0');

program
  .argument('<file>', 'Solidity file to audit')
  .option('-v, --verbose', 'verbose output')
  .option('-c, --config <path>', 'path to config file')
  .action((file, options) => {
    const config = new ConfigManager();
    
    if (options.config) {
      // Load specific config file if provided
      // TODO: implement custom config loading
    }
    console.log(chalk.blue.bold('Smart Contract Auditor v0.1.0'));
    console.log(chalk.gray('Analyzing contract:', file));
    
    if (!fs.existsSync(file)) {
      console.error(chalk.red('Error: File not found'));
      process.exit(1);
    }
    
    try {
      const parser = new SolidityParser();
      const ast = parser.parseFile(file);
      
      console.log(chalk.green('✓ Successfully parsed Solidity file'));
      
      const contracts = parser.getContracts();
      console.log(chalk.cyan(`Found ${contracts.length} contract(s):`));
      
      contracts.forEach(contract => {
        console.log(chalk.white(`  - ${contract.name}`));
        const functions = parser.getFunctions(contract);
        console.log(chalk.gray(`    Functions: ${functions.length}`));
      });

      console.log('\n' + chalk.blue.bold('Running security audit...'));
      
      const auditor = new ContractAuditor(parser, config);
      const auditResults = auditor.audit();
      
      console.log('\n' + chalk.yellow.bold('AUDIT RESULTS'));
      console.log('═'.repeat(50));
      
      if (auditResults.vulnerabilities.length === 0) {
        console.log(chalk.green('✓ No vulnerabilities detected'));
      } else {
        auditResults.vulnerabilities.forEach(vuln => {
          // Filter by config severity settings
          if (config.shouldShowSeverity(vuln.severity)) {
            const useColors = config.useColors();
            const color = useColors ? (
              vuln.severity === 'HIGH' ? chalk.red : 
              vuln.severity === 'MEDIUM' ? chalk.yellow : chalk.blue
            ) : (x => x);
            
            console.log(color.bold(`[${vuln.severity}] ${vuln.type}`));
            console.log(`Contract: ${vuln.contract}`);
            console.log(`Function: ${vuln.function} (line ${vuln.line})`);
            
            if (config.isVerbose() || options.verbose) {
              console.log(chalk.gray(`Description: ${vuln.description}`));
            }
            console.log('');
          }
        });
      }
      
      const summary = auditResults.summary;
      console.log(chalk.cyan.bold('Summary:'));
      console.log(`  High: ${summary.high} | Medium: ${summary.medium} | Low: ${summary.low} | Info: ${summary.info}`);
      
    } catch (error) {
      console.error(chalk.red('Parse error:'), error.message);
      process.exit(1);
    }
  });

program.parse();