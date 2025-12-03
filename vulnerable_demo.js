//VULNERABLE DH KEY EXCHANGE W/O signsatures
//MITM

const crypto = require('crypto');

//generate DH parameters
const dhParams = crypto.getDiffieHellman('modp14');

//Dis for ALICE
function aliceVulnerable() {
  const alice = crypto.createDiffieHellman(dhParams.getPrime(), dhParams.getGenerator());
  alice.generateKeys();
  
  console.log('\nTHE GURL ALICE generates her DH key pair');
  console.log('Alice-s Public Key:', alice.getPublicKey('hex').substring(0, 32) + '...');
  
  return alice;
}

//dis for bob who is receiver
function bobVulnerable() {
  const bob = crypto.createDiffieHellman(dhParams.getPrime(), dhParams.getGenerator());
  bob.generateKeys();
  
  console.log('\nTHE GUY BOB generates his DH key pair');
  console.log('Bob Public Key:', bob.getPublicKey('hex').substring(0, 32) + '...');
  
  return bob;
}

// ====== MALLORY (ATTACKER) ======
function malloryAttacker() {
  //mallory whcih is woman in middle generater her own DH key pair
  const mallory = crypto.createDiffieHellman(dhParams.getPrime(), dhParams.getGenerator());
  mallory.generateKeys();
  
  console.log('\nTHE SECOND GURL MALLORY (Attacker) generates her DH key pair');
  console.log('Mallory Public Key:', mallory.getPublicKey('hex').substring(0, 32) + '...');
  
  return mallory;
}


function demonstrateVulnerableMITM() {
  console.log('\n═══════════════════════════════════════════════════');
  console.log('  VULNERABLE DH KEY EXCHANGE (WITHOUT SIGNATURES)');
  console.log('═══════════════════════════════════════════════════\n');
  
  const alice = aliceVulnerable();
  const bob = bobVulnerable();
  const mallory = malloryAttacker();
  
  console.log('\n\n📡 STEP 1: Alice sends her public key to Bob');
  console.log('OHO but Mallory intercepts it!');
  
  console.log('\n TCH TCH, MALLORY intercepts Alice→Bob communication');
  console.log('   - Mallory receives Alice\'s public key');
  console.log('   - Mallory sends HER OWN public key to Bob (pretending to be Alice - DHOKAAA)');
  
 
  const mallory_alice_secret = mallory.computeSecret(alice.getPublicKey());
  console.log('\nEW - Mallory computes shared secret with Alice:');
  console.log('   Secret:', mallory_alice_secret.toString('hex').substring(0, 32) + '...');
  
  console.log('\n\n STEP 2: Bob sends his public key to Alice');
  console.log('    But Mallory intercepts it again! very dheeeth');
  
  console.log('\n MALLORY intercepts Bob→Alice communication');
  console.log('   - Mallory receives Bob\'s public key');
  console.log('   - Mallory sends HER OWN public key to Alice (pretending to be Bob)');
  
  const mallory_bob_secret = mallory.computeSecret(bob.getPublicKey());
  console.log('\n CHALAK Mallory computes shared secret with Bob:');
  console.log('   Secret:', mallory_bob_secret.toString('hex').substring(0, 32) + '...');
  
  const alice_secret = alice.computeSecret(mallory.getPublicKey());
  console.log('\n\n Alice computes shared secret (thinks it\'s with Bob):');
  console.log('   Secret:', alice_secret.toString('hex').substring(0, 32) + '...');
  
  const bob_secret = bob.computeSecret(mallory.getPublicKey());
  console.log('\n Masoom Bob computes shared secret (thinks it\'s with Alice):');
  console.log('   Secret:', bob_secret.toString('hex').substring(0, 32) + '...');
  
  console.log('\n\n═══════════════════════════════════════════════════');
  console.log('           ATTACK SUCCESS VERIFICATION');
  console.log('═══════════════════════════════════════════════════\n');
  
  const aliceMalloryMatch = alice_secret.equals(mallory_alice_secret);
  const bobMalloryMatch = bob_secret.equals(mallory_bob_secret);
  const aliceBobMatch = alice_secret.equals(bob_secret);
  
  console.log('✅ Alice-Mallory secrets match:', aliceMalloryMatch);
  console.log('✅ Bob-Mallory secrets match:', bobMalloryMatch);
  console.log('❌ Alice-Bob secrets match:', aliceBobMatch);
  
  console.log('\n  RESULT: Mallory can now decrypt and read ALL messages!');
  console.log('   - Alice encrypts with her secret (actually shared with Mallory)');
  console.log('   - Mallory decrypts, reads, re-encrypts with Bob\'s secret');
  console.log('   - Bob decrypts (thinking it came from Alice)');
  console.log('   - Neither Alice nor Bob know they\'re compromised!\n');
  
  console.log('\n═══════════════════════════════════════════════════');
  console.log('         MESSAGE INTERCEPTION EXAMPLE');
  console.log('═══════════════════════════════════════════════════\n');
  
  const originalMessage = 'Hello Bob, here is my secret: PASSWORD123';
  console.log('🔵 Alice sends encrypted message:', originalMessage);
  
  const cipher1 = crypto.createCipheriv('aes-256-gcm', alice_secret.slice(0, 32), Buffer.alloc(12, 0));
  let encrypted = cipher1.update(originalMessage, 'utf8', 'hex');
  encrypted += cipher1.final('hex');
  
  console.log('   Encrypted:', encrypted.substring(0, 40) + '...');
  
  console.log('\n Mallory intercepts and decrypts:');
  const decipher1 = crypto.createDecipheriv('aes-256-gcm', mallory_alice_secret.slice(0, 32), Buffer.alloc(12, 0));
  decipher1.setAuthTag(cipher1.getAuthTag());
  let decrypted = decipher1.update(encrypted, 'hex', 'utf8');
  decrypted += decipher1.final('utf8');
  console.log('    Mallory reads:', decrypted);
  console.log('    Mallory logs the password!');
  
  const cipher2 = crypto.createCipheriv('aes-256-gcm', mallory_bob_secret.slice(0, 32), Buffer.alloc(12, 0));
  let reencrypted = cipher2.update(decrypted, 'utf8', 'hex');
  reencrypted += cipher2.final('hex');
  
  console.log('\n Mallory re-encrypts for Bob:');
  console.log('   Re-encrypted:', reencrypted.substring(0, 40) + '...');
  
  console.log('\n Bob receives and decrypts:');
  const decipher2 = crypto.createDecipheriv('aes-256-gcm', bob_secret.slice(0, 32), Buffer.alloc(12, 0));
  decipher2.setAuthTag(cipher2.getAuthTag());
  let bobReceived = decipher2.update(reencrypted, 'hex', 'utf8');
  bobReceived += decipher2.final('utf8');
  console.log('   Bob reads:', bobReceived);
  console.log('    Bob thinks this came directly from Alice!\n');
}

demonstrateVulnerableMITM();

console.log('\n═══════════════════════════════════════════════════');
console.log('  THIS  WORKS BCZ :');
console.log('═══════════════════════════════════════════════════');
console.log('1. No authentication of public keys');
console.log('2. No digital signatures to verify sender identity');
console.log('3. No way to detect key substitution');
console.log('4. Pure DH provides confidentiality but NOT authenticity\n');