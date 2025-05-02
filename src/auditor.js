const ReentrancyDetector = require('./detectors/reentrancy');
const OverflowDetector = require('./detectors/overflow');
const GasOptimizationDetector = require('./detectors/gas');
const AccessControlDetector = require('./detectors/access');

class ContractAuditor {
  constructor(parser) {
    this.parser = parser;
    this.detectors = [
      new ReentrancyDetector(parser),
      new OverflowDetector(parser),
      new GasOptimizationDetector(parser),
      new AccessControlDetector(parser)
    ];
  }

  audit() {
    const results = {
      vulnerabilities: [],
      summary: {
        high: 0,
        medium: 0,
        low: 0,
        info: 0
      }
    };

    this.detectors.forEach(detector => {
      const vulns = detector.detect();
      results.vulnerabilities.push(...vulns);
      
      vulns.forEach(vuln => {
        const severity = vuln.severity.toLowerCase();
        if (results.summary[severity] !== undefined) {
          results.summary[severity]++;
        }
      });
    });

    return results;
  }
}

module.exports = ContractAuditor;