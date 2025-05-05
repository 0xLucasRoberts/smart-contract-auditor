const fs = require('fs');
const path = require('path');

class ConfigManager {
  constructor() {
    this.defaultConfig = {
      detectors: {
        reentrancy: true,
        overflow: true,
        gas: true,
        access: true
      },
      severity: {
        high: true,
        medium: true,
        low: true,
        info: true
      },
      output: {
        format: 'console',
        verbose: false,
        colors: true
      },
      rules: {
        maxLoopIterations: 1000,
        warnOnPublicArrays: true,
        requireAccessControl: true
      }
    };
    
    this.config = this.loadConfig();
  }

  loadConfig() {
    const configPaths = [
      './audit.config.json',
      './auditor.config.json',
      './.auditorrc.json',
      path.join(process.cwd(), 'audit.config.json')
    ];

    for (const configPath of configPaths) {
      if (fs.existsSync(configPath)) {
        try {
          const configData = fs.readFileSync(configPath, 'utf8');
          const userConfig = JSON.parse(configData);
          return this.mergeConfig(this.defaultConfig, userConfig);
        } catch (error) {
          console.warn(`Warning: Could not parse config file ${configPath}: ${error.message}`);
        }
      }
    }

    return this.defaultConfig;
  }

  mergeConfig(defaultConfig, userConfig) {
    const merged = JSON.parse(JSON.stringify(defaultConfig));
    
    Object.keys(userConfig).forEach(key => {
      if (typeof userConfig[key] === 'object' && userConfig[key] !== null) {
        merged[key] = { ...merged[key], ...userConfig[key] };
      } else {
        merged[key] = userConfig[key];
      }
    });
    
    return merged;
  }

  isDetectorEnabled(detectorName) {
    return this.config.detectors[detectorName] !== false;
  }

  shouldShowSeverity(severity) {
    return this.config.severity[severity.toLowerCase()] !== false;
  }

  getOutputFormat() {
    return this.config.output.format;
  }

  isVerbose() {
    return this.config.output.verbose;
  }

  useColors() {
    return this.config.output.colors;
  }

  getRule(ruleName) {
    return this.config.rules[ruleName];
  }

  getConfig() {
    return this.config;
  }
}

module.exports = ConfigManager;