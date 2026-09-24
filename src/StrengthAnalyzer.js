/**
 * @file Password Strength Analyzer Module
 * @description Evaluates password strength using entropy and pattern detection
 */

class StrengthAnalyzer {
  /**
   * Analyzes password strength and returns detailed metrics
   * @param {string} password - Password to analyze
   * @returns {object} Analysis result with length, entropy, flags, and strength level
   */
  analyze(password) {
    const hasLower = /[a-z]/.test(password);
    const hasUpper = /[A-Z]/.test(password);
    const hasNumber = /\d/.test(password);
    const hasSymbol = /[^A-Za-z0-9]/.test(password);

    let poolSize = 0;
    if (hasLower) poolSize += 26;
    if (hasUpper) poolSize += 26;
    if (hasNumber) poolSize += 10;
    if (hasSymbol) poolSize += 32;

    const entropy = password.length * Math.log2(poolSize);
    
    let strength = 'weak';
    if (entropy >= 80 && hasLower && hasUpper && hasNumber) strength = 'strong';
    else if (entropy >= 50) strength = 'medium';
    else if (entropy >= 30) strength = 'fair';

    return {
      length: password.length,
      entropy: Math.round(entropy),
      poolSize,
      hasLower, hasUpper, hasNumber, hasSymbol,
      strength
    };
  }
}

export default StrengthAnalyzer;
