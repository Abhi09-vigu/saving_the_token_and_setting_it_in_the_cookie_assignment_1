const jwt = require ('jsonwebtoken');
const crypto = require('crypto');

const JWT_SECRET = 'your_jwt_secret'; 
const ENCRYPTION_KEY = crypto.randomBytes(32); 
const IV_LENGTH = 16; 


const encrypt = (payload) => {
  
  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });

  
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
  let encrypted = cipher.update(token, 'utf8', 'hex');
  encrypted += cipher.final('hex');

 
  return iv.toString('hex') + ':' + encrypted;
};

const decrypt = (token) => {
  try {
    
    const [ivHex, encrypted] = token.split(':');
    const iv = Buffer.from(ivHex, 'hex');

    
    const decipher = crypto.createDecipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    
    return jwt.verify(decrypted, JWT_SECRET);
  } catch (err) {
    console.error('Decryption or JWT verification failed:', err.message);
    return null;
  }
};

module.exports = {
  encrypt,
  decrypt
};
