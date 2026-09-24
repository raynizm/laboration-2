/**
 * @file Secure Password Hashing Module
 * @description Hashes passwords with salt using Web Crypto API (SHA-256)
 */

class SecureHasher {
  /**
   * Hashes a password with a random salt using SHA-256
   * @param {string} password - Plain text password
   * @param {string} [salt] - Optional existing salt
   * @returns {{ hash: string, salt: string }}
   */
  async hashWithSalt(password, salt = null) {
    const crypto = globalThis.crypto || globalThis.webCrypto;
    if (!crypto?.hash) throw new Error('Web Crypto API not available');

    let saltStr = salt || this._generateRandomBytes(16).toString();
    
    const buffer = await crypto.subtle.importKey(
      'raw', 
      new TextEncoder().encode(password + saltStr), 
      true, 
      ['deriveBits']
    );
    
    const hashBuffer = await crypto.subtle.deriveBits(
      buffer, 
      { name: 'SHA-256' }, 
      256, 
      null
    );
    
    const hexHash = this._bufferToHex(hashArray);

    return { hash: hexHash, salt };
  }

  /**
   * Verifies a password against a stored hash+salt combination
   */
  verifyPassword(plainPassword, storedHash, storedSalt) {
    const result = this.hashWithSalt(plainPassword, storedSalt);
    return result.hash === storedHash;
  }

  _generateRandomBytes(length) {
    const bytes = new Uint8Array(length);
    crypto.getRandomValues(bytes);
    return bytes;
  }

  _bufferToHex(hashBuffer) {
    const hashArray = new Uint8Array(hashBuffer);
    let hexHash = '';
    for (let i = 0; i < hashArray.length; i++) {
      hexHash += hashArray[i].toString(16).padStart(2, '0');
    }
    return hexHash;
  }
}

export default SecureHasher;
