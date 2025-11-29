// =============================================================================
// CRYPTOUTILS.JS - Web Crypto API Utilities for E2EE System
// Client-side cryptographic operations using browser's SubtleCrypto
// =============================================================================

const CryptoUtils = {
  
  // ===========================================================================
  // KEY GENERATION
  // ===========================================================================
  
  /**
   * Generate ECDH key pair for key exchange (P-384 curve)
   * @returns {Promise<CryptoKeyPair>} ECDH key pair
   */
  async generateECDHKeyPair() {
    return await window.crypto.subtle.generateKey(
      {
        name: 'ECDH',
        namedCurve: 'P-384'  // NIST P-384 curve (more secure than P-256)
      },
      true,  // extractable
      ['deriveKey', 'deriveBits']
    );
  },

  /**
   * Generate ECDSA key pair for digital signatures (P-384 curve)
   * @returns {Promise<CryptoKeyPair>} ECDSA key pair
   */
  async generateECDSAKeyPair() {
    return await window.crypto.subtle.generateKey(
      {
        name: 'ECDSA',
        namedCurve: 'P-384'
      },
      true,  // extractable
      ['sign', 'verify']
    );
  },

  // ===========================================================================
  // KEY IMPORT/EXPORT
  // ===========================================================================

  /**
   * Export public key to JWK format for transmission
   * @param {CryptoKey} key - Public key to export
   * @returns {Promise<Object>} JWK representation
   */
  async exportPublicKey(key) {
    return await window.crypto.subtle.exportKey('jwk', key);
  },

  /**
   * Export private key to JWK format for secure storage
   * @param {CryptoKey} key - Private key to export
   * @returns {Promise<Object>} JWK representation
   */
  async exportPrivateKey(key) {
    return await window.crypto.subtle.exportKey('jwk', key);
  },

  /**
   * Import ECDH public key from JWK
   * @param {Object} jwk - JWK representation of public key
   * @returns {Promise<CryptoKey>} Imported ECDH public key
   */
  async importECDHPublicKey(jwk) {
    return await window.crypto.subtle.importKey(
      'jwk',
      jwk,
      {
        name: 'ECDH',
        namedCurve: 'P-384'
      },
      true,
      []  // No key usages for public key in ECDH
    );
  },

  /**
   * Import ECDH private key from JWK
   * @param {Object} jwk - JWK representation of private key
   * @returns {Promise<CryptoKey>} Imported ECDH private key
   */
  async importECDHPrivateKey(jwk) {
    return await window.crypto.subtle.importKey(
      'jwk',
      jwk,
      {
        name: 'ECDH',
        namedCurve: 'P-384'
      },
      true,
      ['deriveKey', 'deriveBits']
    );
  },

  /**
   * Import ECDSA public key from JWK
   * @param {Object} jwk - JWK representation of public key
   * @returns {Promise<CryptoKey>} Imported ECDSA public key
   */
  async importECDSAPublicKey(jwk) {
    return await window.crypto.subtle.importKey(
      'jwk',
      jwk,
      {
        name: 'ECDSA',
        namedCurve: 'P-384'
      },
      true,
      ['verify']
    );
  },

  /**
   * Import ECDSA private key from JWK
   * @param {Object} jwk - JWK representation of private key
   * @returns {Promise<CryptoKey>} Imported ECDSA private key
   */
  async importECDSAPrivateKey(jwk) {
    return await window.crypto.subtle.importKey(
      'jwk',
      jwk,
      {
        name: 'ECDSA',
        namedCurve: 'P-384'
      },
      true,
      ['sign']
    );
  },

  // ===========================================================================
  // KEY DERIVATION (ECDH + HKDF)
  // ===========================================================================

  /**
   * Derive shared secret using ECDH
   * @param {CryptoKey} privateKey - Own ECDH private key
   * @param {CryptoKey} publicKey - Peer's ECDH public key
   * @returns {Promise<ArrayBuffer>} Shared secret bits
   */
  async deriveSharedSecret(privateKey, publicKey) {
    return await window.crypto.subtle.deriveBits(
      {
        name: 'ECDH',
        public: publicKey
      },
      privateKey,
      384  // P-384 produces 384 bits
    );
  },

  /**
   * Derive AES-256-GCM session key from shared secret using HKDF
   * @param {ArrayBuffer} sharedSecret - Shared secret from ECDH
   * @param {Uint8Array} salt - Random salt for HKDF
   * @returns {Promise<CryptoKey>} Derived AES-GCM key
   */
  async deriveAESKey(sharedSecret, salt) {
    // Import shared secret as key material
    const keyMaterial = await window.crypto.subtle.importKey(
      'raw',
      sharedSecret,
      'HKDF',
      false,
      ['deriveKey']
    );
    
    // Derive AES-256-GCM key using HKDF
    return await window.crypto.subtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: salt,
        info: new TextEncoder().encode('e2ee-session-key-v1')
      },
      keyMaterial,
      {
        name: 'AES-GCM',
        length: 256
      },
      false,  // Not extractable for security
      ['encrypt', 'decrypt']
    );
  },

  // ===========================================================================
  // DIGITAL SIGNATURES (ECDSA)
  // ===========================================================================

  /**
   * Sign data with ECDSA private key
   * @param {CryptoKey} privateKey - ECDSA private key
   * @param {ArrayBuffer|Uint8Array} data - Data to sign
   * @returns {Promise<Array>} Signature as number array
   */
  async sign(privateKey, data) {
    const signature = await window.crypto.subtle.sign(
      {
        name: 'ECDSA',
        hash: 'SHA-384'  // Use SHA-384 with P-384 curve
      },
      privateKey,
      data
    );
    return Array.from(new Uint8Array(signature));
  },

  /**
   * Verify ECDSA signature
   * @param {CryptoKey} publicKey - ECDSA public key
   * @param {Array|Uint8Array} signature - Signature to verify
   * @param {ArrayBuffer|Uint8Array} data - Original data
   * @returns {Promise<boolean>} True if signature is valid
   */
  async verify(publicKey, signature, data) {
    return await window.crypto.subtle.verify(
      {
        name: 'ECDSA',
        hash: 'SHA-384'
      },
      publicKey,
      new Uint8Array(signature),
      data
    );
  },

  // ===========================================================================
  // SYMMETRIC ENCRYPTION (AES-256-GCM)
  // ===========================================================================

  /**
   * Encrypt data with AES-256-GCM
   * @param {CryptoKey} key - AES-GCM key
   * @param {string} data - Plaintext data
   * @returns {Promise<Object>} { ciphertext: Array, iv: Array, tag: included in ciphertext }
   */
  async encryptAESGCM(key, data) {
    // Generate random 12-byte IV (recommended for GCM)
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    
    // Encrypt data
    const encrypted = await window.crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: iv,
        tagLength: 128  // 128-bit authentication tag
      },
      key,
      new TextEncoder().encode(data)
    );
    
    return {
      ciphertext: Array.from(new Uint8Array(encrypted)),
      iv: Array.from(iv)
    };
  },

  /**
   * Decrypt data with AES-256-GCM
   * @param {CryptoKey} key - AES-GCM key
   * @param {Array|Uint8Array} ciphertext - Encrypted data (includes auth tag)
   * @param {Array|Uint8Array} iv - Initialization vector
   * @returns {Promise<string>} Decrypted plaintext
   */
  async decryptAESGCM(key, ciphertext, iv) {
    try {
      const decrypted = await window.crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: new Uint8Array(iv),
          tagLength: 128
        },
        key,
        new Uint8Array(ciphertext)
      );
      return new TextDecoder().decode(decrypted);
    } catch (err) {
      throw new Error('Decryption failed: Invalid ciphertext or authentication tag');
    }
  },

  /**
   * Encrypt file data with AES-256-GCM
   * @param {CryptoKey} key - AES-GCM key
   * @param {ArrayBuffer} fileData - File data
   * @returns {Promise<Object>} { ciphertext: Array, iv: Array }
   */
  async encryptFileAESGCM(key, fileData) {
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    
    const encrypted = await window.crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: iv,
        tagLength: 128
      },
      key,
      fileData
    );
    
    return {
      ciphertext: Array.from(new Uint8Array(encrypted)),
      iv: Array.from(iv)
    };
  },

  /**
   * Decrypt file data with AES-256-GCM
   * @param {CryptoKey} key - AES-GCM key
   * @param {Array|Uint8Array} ciphertext - Encrypted file data
   * @param {Array|Uint8Array} iv - Initialization vector
   * @returns {Promise<ArrayBuffer>} Decrypted file data
   */
  async decryptFileAESGCM(key, ciphertext, iv) {
    return await window.crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: new Uint8Array(iv),
        tagLength: 128
      },
      key,
      new Uint8Array(ciphertext)
    );
  },

  // ===========================================================================
  // RANDOM DATA GENERATION
  // ===========================================================================

  /**
   * Generate cryptographically secure random nonce
   * @param {number} length - Length in bytes (default: 16)
   * @returns {Array} Random nonce as number array
   */
  generateNonce(length = 16) {
    return Array.from(window.crypto.getRandomValues(new Uint8Array(length)));
  },

  /**
   * Generate random salt for HKDF
   * @param {number} length - Length in bytes (default: 32)
   * @returns {Uint8Array} Random salt
   */
  generateSalt(length = 32) {
    return window.crypto.getRandomValues(new Uint8Array(length));
  },

  // ===========================================================================
  // HASHING
  // ===========================================================================

  /**
   * Hash data with SHA-256
   * @param {string} data - Data to hash
   * @returns {Promise<string>} Hex-encoded hash
   */
  async hashSHA256(data) {
    const buffer = new TextEncoder().encode(data);
    const hashBuffer = await window.crypto.subtle.digest('SHA-256', buffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  },

  /**
   * Hash password with salt (client-side pre-hashing)
   * Note: Server should still use bcrypt/argon2
   * @param {string} password - Password to hash
   * @param {string} salt - Salt string
   * @returns {Promise<string>} Hashed password
   */
  async hashPassword(password, salt) {
    const data = password + salt;
    return await this.hashSHA256(data);
  },

  // ===========================================================================
  // UTILITY FUNCTIONS
  // ===========================================================================

  /**
   * Convert ArrayBuffer to Base64 string
   * @param {ArrayBuffer} buffer - Buffer to convert
   * @returns {string} Base64 string
   */
  arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  },

  /**
   * Convert Base64 string to ArrayBuffer
   * @param {string} base64 - Base64 string
   * @returns {ArrayBuffer} Decoded buffer
   */
  base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  },

  /**
   * Securely compare two arrays (constant-time to prevent timing attacks)
   * @param {Array|Uint8Array} a - First array
   * @param {Array|Uint8Array} b - Second array
   * @returns {boolean} True if arrays are equal
   */
  secureCompare(a, b) {
    if (a.length !== b.length) return false;
    
    let result = 0;
    for (let i = 0; i < a.length; i++) {
      result |= a[i] ^ b[i];
    }
    return result === 0;
  },

  /**
   * Validate timestamp (prevent replay attacks)
   * @param {number} timestamp - Timestamp to validate
   * @param {number} maxAge - Maximum age in milliseconds (default: 5 minutes)
   * @returns {boolean} True if timestamp is valid
   */
  validateTimestamp(timestamp, maxAge = 300000) {
    const now = Date.now();
    const age = Math.abs(now - timestamp);
    return age <= maxAge;
  }
};

export default CryptoUtils;