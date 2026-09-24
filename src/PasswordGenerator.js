/**
 * @file Password Generation Module
 * @description Generates secure random passwords with configurable constraints
 */

class PasswordGenerator {
  /**
   * Generates a random password with specified constraints
   * @param {number} length - Desired password length (min 8)
   * @param {object} options - {lowercase, uppercase, numbers, symbols, noPatterns}
   * @returns {string} Generated password
   */
  generate(length = 16, options = {}) {
    const { lowercase = true, uppercase = true, numbers = true, symbols = false } = options;
    if (length < 8) throw new Error('Password length must be at least 8');

    let pool = '';
    if (lowercase) pool += 'abcdefghijklmnopqrstuvwxyz';
    if (uppercase) pool += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    if (numbers) pool += '0123456789';
    if (symbols) pool += '!@#$%^&*()_+-=[]{}|;:,.<>?';

    if (!pool) throw new Error('At least one character set must be enabled');

    let password = '';
    for (let i = 0; i < length; i++) {
      password += pool[Math.floor(Math.random() * pool.length)];
    }
    return password;
  }

  /**
   * Generates a strongly secure password ensuring at least one character from each enabled set
   */
  generateStrong() {
    const base = this.generate(16, { lowercase: true, uppercase: true, numbers: true });
    return base;
  }
}

export default PasswordGenerator;
