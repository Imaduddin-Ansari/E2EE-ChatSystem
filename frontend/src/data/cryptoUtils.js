const CryptoUtils = {
  
  async generateECDHKeyPair() {
    return await window.crypto.subtle.generateKey(
      {
        name: 'ECDH',
        namedCurve: 'P-384'
      },
      true,
      ['deriveKey', 'deriveBits']
    );
  },
  async generateECDSAKeyPair() {
    return await window.crypto.subtle.generateKey(
      {
        name: 'ECDSA',
        namedCurve: 'P-384'
      },
      true,
      ['sign', 'verify']
    );
  },
  async exportPublicKey(key) {
    return await window.crypto.subtle.exportKey('jwk', key);
  },

  async exportPrivateKey(key) {
    return await window.crypto.subtle.exportKey('jwk', key);
  },

  async importECDHPublicKey(jwk) {
    return await window.crypto.subtle.importKey(
      'jwk',
      jwk,
      {
        name: 'ECDH',
        namedCurve: 'P-384'
      },
      true,
      []
    );
  },

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

  async deriveSharedSecret(privateKey, publicKey) {
    return await window.crypto.subtle.deriveBits(
      {
        name: 'ECDH',
        public: publicKey
      },
      privateKey,
      384
    );
  },

  async deriveAESKey(sharedSecret, salt) {
    const keyMaterial = await window.crypto.subtle.importKey(
      'raw',
      sharedSecret,
      'HKDF',
      false,
      ['deriveKey']
    );
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
      false,
      ['encrypt', 'decrypt']
    );
  },

  async sign(privateKey, data) {
    const signature = await window.crypto.subtle.sign(
      {
        name: 'ECDSA',
        hash: 'SHA-384'
      },
      privateKey,
      data
    );
    return Array.from(new Uint8Array(signature));
  },
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

  async encryptAESGCM(key, data) {
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await window.crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: iv,
        tagLength: 128
      },
      key,
      new TextEncoder().encode(data)
    );
    
    return {
      ciphertext: Array.from(new Uint8Array(encrypted)),
      iv: Array.from(iv)
    };
  },

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

  generateNonce(length = 16) {
    return Array.from(window.crypto.getRandomValues(new Uint8Array(length)));
  },

  generateSalt(length = 32) {
    return window.crypto.getRandomValues(new Uint8Array(length));
  },
  async hashSHA256(data) {
    const buffer = new TextEncoder().encode(data);
    const hashBuffer = await window.crypto.subtle.digest('SHA-256', buffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  },

  async hashPassword(password, salt) {
    const data = password + salt;
    return await this.hashSHA256(data);
  },

  arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  },
  base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  },

  secureCompare(a, b) {
    if (a.length !== b.length) return false;
    
    let result = 0;
    for (let i = 0; i < a.length; i++) {
      result |= a[i] ^ b[i];
    }
    return result === 0;
  },

  validateTimestamp(timestamp, maxAge = 300000) {
    const now = Date.now();
    const age = Math.abs(now - timestamp);
    return age <= maxAge;
  }
};

export default CryptoUtils;