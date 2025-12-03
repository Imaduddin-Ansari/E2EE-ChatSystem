const KeyStorage = {
  dbName: 'E2EEKeyStore',
  version: 1,
  storeName: 'keys',
  async openDB() {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(this.dbName, this.version);
      
      request.onerror = () => {
        console.error('IndexedDB error:', request.error);
        reject(request.error);
      };
      
      request.onsuccess = () => {
        resolve(request.result);
      };
      
      request.onupgradeneeded = (event) => {
        const db = event.target.result;
        
        // Create object store for keys
        if (!db.objectStoreNames.contains(this.storeName)) {
          const objectStore = db.createObjectStore(this.storeName, { keyPath: 'userId' });
          
          // Create indexes
          objectStore.createIndex('userId', 'userId', { unique: true });
          objectStore.createIndex('timestamp', 'timestamp', { unique: false });
          
          console.log('IndexedDB object store created');
        }
      };

      request.onblocked = () => {
        console.warn('IndexedDB blocked - close other tabs');
      };
    });
  },

  async saveKeys(userId, ecdhKeyPair, ecdsaKeyPair) {
    try {
      const db = await this.openDB();
      
      // Export private keys to JWK format
      const ecdhPrivate = await window.crypto.subtle.exportKey('jwk', ecdhKeyPair.privateKey);
      const ecdsaPrivate = await window.crypto.subtle.exportKey('jwk', ecdsaKeyPair.privateKey);
      
      // Store in IndexedDB
      return new Promise((resolve, reject) => {
        const transaction = db.transaction([this.storeName], 'readwrite');
        const objectStore = transaction.objectStore(this.storeName);
        
        const keyData = {
          userId: userId,
          ecdhPrivate: ecdhPrivate,
          ecdsaPrivate: ecdsaPrivate,
          timestamp: Date.now(),
          version: '1.0'
        };
        
        const request = objectStore.put(keyData);
        
        request.onsuccess = () => {
          console.log(`✓ Private keys stored securely for user ${userId}`);
          resolve();
        };
        
        request.onerror = () => {
          console.error('Failed to store keys:', request.error);
          reject(request.error);
        };
        
        transaction.oncomplete = () => {
          db.close();
        };
        
        transaction.onerror = () => {
          console.error('Transaction error:', transaction.error);
          reject(transaction.error);
        };
      });
    } catch (err) {
      console.error('Error saving keys:', err);
      throw err;
    }
  },

  async loadKeys(userId) {
    try {
      const db = await this.openDB();
      
      return new Promise((resolve, reject) => {
        const transaction = db.transaction([this.storeName], 'readonly');
        const objectStore = transaction.objectStore(this.storeName);
        const request = objectStore.get(userId);
        
        request.onsuccess = async () => {
          if (!request.result) {
            console.warn(`No private keys found for user ${userId}`);
            resolve(null);
            return;
          }
          
          try {
            // Import private keys from JWK
            const ecdhPrivate = await window.crypto.subtle.importKey(
              'jwk',
              request.result.ecdhPrivate,
              {
                name: 'ECDH',
                namedCurve: 'P-384'
              },
              true,
              ['deriveKey', 'deriveBits']
            );
            
            const ecdsaPrivate = await window.crypto.subtle.importKey(
              'jwk',
              request.result.ecdsaPrivate,
              {
                name: 'ECDSA',
                namedCurve: 'P-384'
              },
              true,
              ['sign']
            );
            
            console.log(`✓ Private keys loaded for user ${userId}`);
            resolve({ ecdhPrivate, ecdsaPrivate });
          } catch (err) {
            console.error('Failed to import keys:', err);
            reject(err);
          }
        };
        
        request.onerror = () => {
          console.error('Failed to load keys:', request.error);
          reject(request.error);
        };
        
        transaction.oncomplete = () => {
          db.close();
        };
      });
    } catch (err) {
      console.error('Error loading keys:', err);
      throw err;
    }
  },
  async hasKeys(userId) {
    try {
      const db = await this.openDB();
      
      return new Promise((resolve, reject) => {
        const transaction = db.transaction([this.storeName], 'readonly');
        const objectStore = transaction.objectStore(this.storeName);
        const request = objectStore.get(userId);
        
        request.onsuccess = () => {
          resolve(!!request.result);
        };
        
        request.onerror = () => {
          reject(request.error);
        };
        
        transaction.oncomplete = () => {
          db.close();
        };
      });
    } catch (err) {
      console.error('Error checking keys:', err);
      return false;
    }
  },

  async deleteKeys(userId) {
    try {
      const db = await this.openDB();
      
      return new Promise((resolve, reject) => {
        const transaction = db.transaction([this.storeName], 'readwrite');
        const objectStore = transaction.objectStore(this.storeName);
        const request = objectStore.delete(userId);
        
        request.onsuccess = () => {
          console.log(`✓ Private keys deleted for user ${userId}`);
          resolve();
        };
        
        request.onerror = () => {
          console.error('Failed to delete keys:', request.error);
          reject(request.error);
        };
        
        transaction.oncomplete = () => {
          db.close();
        };
      });
    } catch (err) {
      console.error('Error deleting keys:', err);
      throw err;
    }
  },
  async clearAllKeys() {
    try {
      const db = await this.openDB();
      
      return new Promise((resolve, reject) => {
        const transaction = db.transaction([this.storeName], 'readwrite');
        const objectStore = transaction.objectStore(this.storeName);
        const request = objectStore.clear();
        
        request.onsuccess = () => {
          console.log('✓ All private keys cleared');
          resolve();
        };
        
        request.onerror = () => {
          console.error('Failed to clear keys:', request.error);
          reject(request.error);
        };
        
        transaction.oncomplete = () => {
          db.close();
        };
      });
    } catch (err) {
      console.error('Error clearing keys:', err);
      throw err;
    }
  },
  async listUserIds() {
    try {
      const db = await this.openDB();
      
      return new Promise((resolve, reject) => {
        const transaction = db.transaction([this.storeName], 'readonly');
        const objectStore = transaction.objectStore(this.storeName);
        const request = objectStore.getAllKeys();
        
        request.onsuccess = () => {
          resolve(request.result);
        };
        
        request.onerror = () => {
          reject(request.error);
        };
        
        transaction.oncomplete = () => {
          db.close();
        };
      });
    } catch (err) {
      console.error('Error listing user IDs:', err);
      return [];
    }
  },

  async exportKeysForBackup(userId, password) {
    try {
      const db = await this.openDB();
      
      const keyData = await new Promise((resolve, reject) => {
        const transaction = db.transaction([this.storeName], 'readonly');
        const objectStore = transaction.objectStore(this.storeName);
        const request = objectStore.get(userId);
        
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
        
        transaction.oncomplete = () => db.close();
      });
      
      if (!keyData) {
        throw new Error('Keys not found');
      }
      
      const encoder = new TextEncoder();
      const passwordKey = await window.crypto.subtle.importKey(
        'raw',
        encoder.encode(password),
        'PBKDF2',
        false,
        ['deriveKey']
      );
      
      const salt = window.crypto.getRandomValues(new Uint8Array(16));
      const encryptionKey = await window.crypto.subtle.deriveKey(
        {
          name: 'PBKDF2',
          salt: salt,
          iterations: 100000,
          hash: 'SHA-256'
        },
        passwordKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt']
      );
      
      // Encrypt key data
      const iv = window.crypto.getRandomValues(new Uint8Array(12));
      const encryptedData = await window.crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: iv },
        encryptionKey,
        encoder.encode(JSON.stringify(keyData))
      );
      
      // Create backup object
      const backup = {
        version: '1.0',
        salt: Array.from(salt),
        iv: Array.from(iv),
        data: Array.from(new Uint8Array(encryptedData))
      };
      
      return btoa(JSON.stringify(backup));
    } catch (err) {
      console.error('Export keys error:', err);
      throw err;
    }
  },

  async importKeysFromBackup(backupString, password) {
    try {
      const backup = JSON.parse(atob(backupString));
      
      // Derive decryption key from password
      const encoder = new TextEncoder();
      const passwordKey = await window.crypto.subtle.importKey(
        'raw',
        encoder.encode(password),
        'PBKDF2',
        false,
        ['deriveKey']
      );
      
      const decryptionKey = await window.crypto.subtle.deriveKey(
        {
          name: 'PBKDF2',
          salt: new Uint8Array(backup.salt),
          iterations: 100000,
          hash: 'SHA-256'
        },
        passwordKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['decrypt']
      );
      
      // Decrypt key data
      const decryptedData = await window.crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: new Uint8Array(backup.iv)
        },
        decryptionKey,
        new Uint8Array(backup.data)
      );
      
      const keyData = JSON.parse(new TextDecoder().decode(decryptedData));
      
      // Store imported keys
      const db = await this.openDB();
      return new Promise((resolve, reject) => {
        const transaction = db.transaction([this.storeName], 'readwrite');
        const objectStore = transaction.objectStore(this.storeName);
        const request = objectStore.put(keyData);
        
        request.onsuccess = () => {
          console.log('✓ Keys imported successfully');
          resolve();
        };
        
        request.onerror = () => reject(request.error);
        transaction.oncomplete = () => db.close();
      });
    } catch (err) {
      console.error('Import keys error:', err);
      throw new Error('Failed to import keys - incorrect password or corrupted backup');
    }
  }
};

export default KeyStorage;