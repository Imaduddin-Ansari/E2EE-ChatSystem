// =============================================================================
// MESSAGE CONTROLLER
// =============================================================================

const Message = require('../models/Message');
const User = require('../models/User');
const { logSecurityEvent } = require('../utils/securityLogger');

const sendMessage = async (req, res) => {
  try {
    const { senderId, recipientId, ciphertext, iv, signature, sequence, nonce } = req.body;

    if (!senderId || !recipientId || !ciphertext || !iv || !signature || sequence === undefined) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const recipient = await User.findById(recipientId);
    if (!recipient) {
      return res.status(404).json({ error: 'Recipient not found' });
    }

    // Check for replay attacks
    const lastMessage = await Message.findOne({ senderId, recipientId }).sort({ sequence: -1 });
    if (lastMessage && sequence <= lastMessage.sequence) {
      await logSecurityEvent('REPLAY_DETECTED', senderId, 
        `Replay attack detected: seq ${sequence} <= ${lastMessage.sequence}`, req);
      return res.status(400).json({ error: 'Replay attack detected' });
    }

    const message = await Message.create({
      senderId,
      recipientId,
      ciphertext,
      iv,
      signature,
      sequence,
      nonce: nonce || []
    });

    await logSecurityEvent('MESSAGE_SENT', senderId, 
      `Message sent to user ${recipientId}, seq: ${sequence}`, req);

    res.status(201).json({ success: true, messageId: message._id });

  } catch (err) {
    console.error('Send message error:', err);
    await logSecurityEvent('MESSAGE_SENT', req.body.senderId, 
      `Send message failed: ${err.message}`, req);
    res.status(500).json({ error: 'Failed to send message' });
  }
};

const getMessages = async (req, res) => {
  try {
    const { userId, recipientId } = req.params;
    
    const messages = await Message.find({
      $or: [
        { senderId: userId, recipientId },
        { senderId: recipientId, recipientId: userId }
      ]
    }).sort({ timestamp: 1 });

    await logSecurityEvent('MESSAGE_RECEIVED', userId, 
      `Retrieved ${messages.length} messages`, req);

    res.json({ success: true, messages });

  } catch (err) {
    console.error('Get messages error:', err);
    res.status(500).json({ error: 'Failed to retrieve messages' });
  }
};

module.exports = { sendMessage, getMessages };