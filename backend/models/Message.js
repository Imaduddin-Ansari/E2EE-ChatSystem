// =============================================================================
// MESSAGE MODEL
// =============================================================================

const mongoose = require('mongoose');

const messageSchema = new mongoose.Schema({
  senderId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true 
  },
  recipientId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true 
  },
  ciphertext: { 
    type: [Number], 
    required: true 
  },
  iv: { 
    type: [Number], 
    required: true 
  },
  signature: { 
    type: [Number], 
    required: true 
  },
  sequence: { 
    type: Number, 
    required: true 
  },
  nonce: { 
    type: [Number], 
    required: true 
  },
  timestamp: { 
    type: Date, 
    default: Date.now 
  }
});

// Compound index for efficient message retrieval
messageSchema.index({ senderId: 1, recipientId: 1, timestamp: 1 });
messageSchema.index({ senderId: 1, recipientId: 1, sequence: -1 });

module.exports = mongoose.model('Message', messageSchema);