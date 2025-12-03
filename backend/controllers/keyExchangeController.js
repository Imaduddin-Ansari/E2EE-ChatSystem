const User = require('../models/User');
const { logSecurityEvent } = require('../utils/securityLogger');

const initiateKeyExchange = async (req, res) => {
  try {
    const { senderId, recipientId, ephemeralPublicKey, nonce, timestamp, signature } = req.body;

    const now = Date.now();
    if (Math.abs(now - timestamp) > 300000) {
      await logSecurityEvent('KEY_EXCHANGE', senderId, 'Key exchange rejected: timestamp too old', req);
      return res.status(400).json({ error: 'Invalid timestamp' });
    }

    const recipient = await User.findById(recipientId);
    if (!recipient) {
      return res.status(404).json({ error: 'Recipient not found' });
    }

    await logSecurityEvent('KEY_EXCHANGE', senderId, `Key exchange initiated with user ${recipientId}`, req);

    res.json({
      success: true,
      recipientPublicKeys: {
        ecdhPublicKey: recipient.ecdhPublicKey,
        ecdsaPublicKey: recipient.ecdsaPublicKey
      }
    });

  } catch (err) {
    console.error('Key exchange error:', err);
    await logSecurityEvent('KEY_EXCHANGE', req.body.senderId, `Key exchange failed: ${err.message}`, req);
    res.status(500).json({ error: 'Key exchange failed' });
  }
};

module.exports = { initiateKeyExchange };