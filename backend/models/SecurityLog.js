const mongoose = require('mongoose');

const securityLogSchema = new mongoose.Schema({
  userId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User' 
  },
  eventType: { 
    type: String, 
    enum: [
      'AUTH_SUCCESS', 
      'AUTH_FAILURE', 
      'KEY_EXCHANGE', 
      'MESSAGE_SENT', 
      'MESSAGE_RECEIVED', 
      'DECRYPT_FAILURE', 
      'REPLAY_DETECTED', 
      'INVALID_SIGNATURE', 
      'FILE_UPLOAD', 
      'FILE_DOWNLOAD'
    ],
    required: true 
  },
  details: { 
    type: String 
  },
  ipAddress: { 
    type: String 
  },
  timestamp: { 
    type: Date, 
    default: Date.now 
  }
});

securityLogSchema.index({ userId: 1, timestamp: -1 });
securityLogSchema.index({ eventType: 1, timestamp: -1 });
securityLogSchema.index({ timestamp: -1 });

module.exports = mongoose.model('SecurityLog', securityLogSchema);