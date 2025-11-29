// =============================================================================
// FILE MODEL
// =============================================================================

const mongoose = require('mongoose');

const fileSchema = new mongoose.Schema({
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
  filename: { 
    type: String, 
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
  timestamp: { 
    type: Date, 
    default: Date.now 
  }
});

// Index for efficient file retrieval
fileSchema.index({ senderId: 1, recipientId: 1, timestamp: -1 });

module.exports = mongoose.model('File', fileSchema);