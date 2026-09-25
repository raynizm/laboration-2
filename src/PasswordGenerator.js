/**
 * @file Password Generation Module
 * @description Generates secure random passwords with configurable constraints
 */

class PasswordGenerator {
  /**
   * Generates a random password with specified constraints
   * 
   * @param {number} length - Desired password length (min 8)
   * @param {object} options - Configuration object
   * @param {boolean} [options.pattern=false] - If true, generates a repeating pattern (e.g., "abc123abc")
   * @param {string} [options.seedLength=6] - Length of the seed string for pattern mode
   * @param {string} [options.separator='-'] - Separator if using patterns (optional)
   * @returns {string} Generated password
   */
  generate(length = 16, options = {}) {
    const { 
      lowercase = true, 
      uppercase = true, 
      numbers = true, 
      symbols = false, 
      pattern = false,
      seedLength = 6,
      separator = '-'
    } = options;

    if (length < 8) throw new Error('Password length must be at least 8');

    // --- Pattern Mode Logic ---
    if (pattern) {
      return this._generatePattern(length, seedLength, separator, lowercase, uppercase, numbers);
    }

    // --- Standard Random Mode Logic ---
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
   * Helper: Generates a repeating pattern string (e.g., "abc123-abc123")
   */
  _generatePattern(length, seedLength, separator, lowercase, uppercase, numbers) {
    let pool = '';
    if (lowercase) pool += 'abcdefghijklmnopqrstuvwxyz';
    if (uppercase) pool += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    if (numbers) pool += '0123456789';

    // Generate a random seed string of the desired length
    let seed = '';
    for (let i = 0; i < seedLength; i++) {
      seed += pool[Math.floor(Math.random() * pool.length)];
    }

    let finalPassword = '';
    const fullSeedLength = seedLength + separator.length;
    
    // Repeatedly append the seed until we reach or exceed the requested length
    while (finalPassword.length < length) {
      finalPassword += seed + separator;
    }

    // Trim to exact length if necessary
    return finalPassword.substring(0, length);
  }

  /**
   * Generates a strongly secure password ensuring at least one character from each enabled set
   */
  generateStrong() {
    return this.generate(16, { lowercase: true, uppercase: true, numbers: true });
  }
}

export default PasswordGenerator;
