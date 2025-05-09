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
  .option('-v, --verbose', 'verbose output with detailed descriptions')
  .option('-c, --config <path>', 'path to config file')
  .option('--no-colors', 'disable colored output')
  .option('--severity <levels>', 'comma-separated severity levels to show (high,medium,low,info)', 'high,medium,low,info')
  .option('--detectors <types>', 'comma-separated detector types to run (reentrancy,overflow,gas,access)', 'reentrancy,overflow,gas,access')
  .option('--json', 'output results in JSON format')
  .action((file, options) => {
    const config = new ConfigManager();
    
    // Override config with CLI options
    if (options.noColors) {
      config.config.output.colors = false;
    }
    
    if (options.json) {
      config.config.output.format = 'json';
    }
    
    if (options.verbose) {
      config.config.output.verbose = true;
    }
    
    // Parse severity filter
    if (options.severity) {
      const allowedSeverities = options.severity.split(',').map(s => s.trim().toLowerCase());
      config.config.severity = {
        high: allowedSeverities.includes('high'),
        medium: allowedSeverities.includes('medium'),
        low: allowedSeverities.includes('low'),
        info: allowedSeverities.includes('info')
      };
    }
    
    // Parse detector filter  
    if (options.detectors) {
      const enabledDetectors = options.detectors.split(',').map(d => d.trim().toLowerCase());
      config.config.detectors = {
        reentrancy: enabledDetectors.includes('reentrancy'),
        overflow: enabledDetectors.includes('overflow'),
        gas: enabledDetectors.includes('gas'),
        access: enabledDetectors.includes('access')
      };
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
      
      // Handle JSON output
      if (config.getOutputFormat() === 'json') {
        console.log(JSON.stringify(auditResults, null, 2));
        return;
      }
      
      // Console output
      console.log('\n' + chalk.yellow.bold('AUDIT RESULTS'));
      console.log('═'.repeat(50));
      
      const filteredVulns = auditResults.vulnerabilities.filter(vuln => 
        config.shouldShowSeverity(vuln.severity)
      );
      
      if (filteredVulns.length === 0) {
        console.log(chalk.green('✓ No vulnerabilities detected'));
      } else {
        filteredVulns.forEach(vuln => {
          const useColors = config.useColors();
          const color = useColors ? (
            vuln.severity === 'HIGH' ? chalk.red : 
            vuln.severity === 'MEDIUM' ? chalk.yellow : chalk.blue
          ) : (x => x);
          
          console.log(color.bold(`[${vuln.severity}] ${vuln.type}`));
          console.log(`Contract: ${vuln.contract}`);
          console.log(`Function: ${vuln.function} (line ${vuln.line})`);
          
          if (config.isVerbose() || options.verbose) {
            const descColor = useColors ? chalk.gray : (x => x);
            console.log(descColor(`Description: ${vuln.description}`));
          }
          console.log('');
        });
      }
      
      const summary = auditResults.summary;
      const summaryColor = config.useColors() ? chalk.cyan.bold : (x => x);
      console.log(summaryColor('Summary:'));
      console.log(`  High: ${summary.high} | Medium: ${summary.medium} | Low: ${summary.low} | Info: ${summary.info}`);
      
    } catch (error) {
      console.error(chalk.red('Parse error:'), error.message);
      process.exit(1);
    }
  });

program.parse();