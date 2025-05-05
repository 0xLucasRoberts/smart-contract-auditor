const ReentrancyDetector = require('./detectors/reentrancy');
const OverflowDetector = require('./detectors/overflow');
const GasOptimizationDetector = require('./detectors/gas');
const AccessControlDetector = require('./detectors/access');

class ContractAuditor {
  constructor(parser, config = null) {
    this.parser = parser;
    this.config = config;
    
    this.detectors = this.initializeDetectors();
  }

  initializeDetectors() {
    const detectors = [];
    
    if (!this.config || this.config.isDetectorEnabled('reentrancy')) {
      detectors.push(new ReentrancyDetector(this.parser));
    }
    
    if (!this.config || this.config.isDetectorEnabled('overflow')) {
      detectors.push(new OverflowDetector(this.parser));
    }
    
    if (!this.config || this.config.isDetectorEnabled('gas')) {
      detectors.push(new GasOptimizationDetector(this.parser));
    }
    
    if (!this.config || this.config.isDetectorEnabled('access')) {
      detectors.push(new AccessControlDetector(this.parser));
    }
    
    return detectors;
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
        // Filter by severity if config is provided
        if (!this.config || this.config.shouldShowSeverity(vuln.severity)) {
          const severity = vuln.severity.toLowerCase();
          if (results.summary[severity] !== undefined) {
            results.summary[severity]++;
          }
        }
      });
    });

    return results;
  }
}

module.exports = ContractAuditor;