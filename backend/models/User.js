const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  username: { 
    type: String, 
    required: true, 
    unique: true,
    trim: true 
  },
  passwordHash: { 
    type: String, 
    required: true 
  },
  salt: { 
    type: String, 
    required: true 
  },
  ecdhPublicKey: { 
    type: Object, 
    required: true 
  },
  ecdsaPublicKey: { 
    type: Object, 
    required: true 
  },
  createdAt: { 
    type: Date, 
    default: Date.now 
  }
});

userSchema.index({ username: 1 });

module.exports = mongoose.model('User', userSchema);