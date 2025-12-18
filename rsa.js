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
 * Encrypt data using an RSA public key
 * Uses RSA-OAEP with SHA-256
 *
 * @param {string} data - Plain text data to encrypt
 * @param {string} publicKey - RSA public key (PEM format)
 * @returns {string} Encrypted data in base64 format
 */
function encrypt(data, publicKey) {
  try {
    const buffer = Buffer.from(data, 'utf8');

    const encrypted = crypto.publicEncrypt(
      {
        key: publicKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256',
      },
      buffer
    );

    return encrypted.toString('base64');
  } catch (error) {
    throw new Error(`Encryption failed: ${error.message}`);
  }
}

/**
 * Decrypt data using an RSA private key
 * Uses RSA-OAEP with SHA-256
 *
 * @param {string} encryptedData - Encrypted data in base64 format
 * @param {string} privateKey - RSA private key (PEM format)
 * @returns {string} Decrypted plain text
 */
function decrypt(encryptedData, privateKey) {
  try {
    const buffer = Buffer.from(encryptedData, 'base64');

    const decrypted = crypto.privateDecrypt(
      {
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256',
      },
      buffer
    );

    return decrypted.toString('utf8');
  } catch (error) {
    throw new Error(`Decryption failed: ${error.message}`);
  }
}