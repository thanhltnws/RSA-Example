
const crypto = require('crypto');

/**
 * Generate an RSA key pair (private key & public key)
 * @param {number} keySize - Key size in bits (default: 2048)
 * @returns {{ privateKey: string, publicKey: string }}
 */
function generateRSAKeyPair(keySize = 2048) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: keySize,
    privateKeyEncoding: {
      format: 'pem',
      type: 'pkcs8',
    },
    publicKeyEncoding: {
      format: 'pem',
      type: 'spki',
    },
  });
  return {
    privateKey,
    publicKey,
  };
}

/**
 * Encrypt data using hybrid encryption (RSA + AES)
 * Can handle data of any size
 * 
 * @param {string} data - Plain text data to encrypt
 * @param {string} publicKey - RSA public key (PEM format)
 * @returns {string} Encrypted package in base64 format
 */
function encrypt(data, publicKey) {
  try {
    // Generate random AES-256 key and IV
    const aesKey = crypto.randomBytes(32);
    const iv = crypto.randomBytes(16);
    
    // Encrypt data with AES-256-GCM
    const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
    let encryptedData = cipher.update(data, 'utf8', 'base64');
    encryptedData += cipher.final('base64');
    const authTag = cipher.getAuthTag();
    
    // Encrypt AES key with RSA public key
    const encryptedKey = crypto.publicEncrypt(
      {
        key: publicKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256',
      },
      aesKey
    );
    
    // Package everything together
    const result = {
      key: encryptedKey.toString('base64'),
      iv: iv.toString('base64'),
      data: encryptedData,
      authTag: authTag.toString('base64')
    };
    
    // Return as base64 encoded JSON
    return Buffer.from(JSON.stringify(result)).toString('base64');
  } catch (error) {
    throw new Error(`Encryption failed: ${error.message}`);
  }
}

/**
 * Decrypt data encrypted with encrypt function
 * 
 * @param {string} encryptedData - Encrypted package in base64 format
 * @param {string} privateKey - RSA private key (PEM format)
 * @returns {string} Decrypted plain text
 */
function decrypt(encryptedData, privateKey) {
  try {
    // Parse the encrypted package
    const packageJson = Buffer.from(encryptedData, 'base64').toString('utf8');
    const { key: encryptedKey, iv: ivBase64, data, authTag } = JSON.parse(packageJson);
    
    // Decrypt AES key using RSA private key
    const aesKey = crypto.privateDecrypt(
      {
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256',
      },
      Buffer.from(encryptedKey, 'base64')
    );
    
    // Decrypt data using AES key
    const iv = Buffer.from(ivBase64, 'base64');
    const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, iv);
    decipher.setAuthTag(Buffer.from(authTag, 'base64'));
    
    let decrypted = decipher.update(data, 'base64', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  } catch (error) {
    throw new Error(`Decryption failed: ${error.message}`);
  }
}

module.exports = {
  generateRSAKeyPair,
  encrypt,
  decrypt,
};
