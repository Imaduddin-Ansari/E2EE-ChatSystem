const bcrypt = require('bcryptjs');
const User = require('../models/User');
const { logSecurityEvent } = require('../utils/securityLogger');

const register = async (req, res) => {
  try {
    const { username, password, ecdhPublicKey, ecdsaPublicKey } = req.body;

    if (!username || !password || !ecdhPublicKey || !ecdsaPublicKey) {
      await logSecurityEvent('AUTH_FAILURE', null, 'Missing registration fields', req);
      return res.status(400).json({ error: 'All fields are required' });
    }

    const existingUser = await User.findOne({ username });
    if (existingUser) {
      await logSecurityEvent('AUTH_FAILURE', null, `Username ${username} already exists`, req);
      return res.status(400).json({ error: 'Username already exists' });
    }

    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(password, salt);

    const user = await User.create({
      username,
      passwordHash,
      salt: salt.toString(),
      ecdhPublicKey,
      ecdsaPublicKey
    });

    await logSecurityEvent('AUTH_SUCCESS', user._id, 'User registered successfully', req);

    res.status(201).json({
      success: true,
      user: {
        id: user._id,
        username: user.username,
        ecdhPublicKey: user.ecdhPublicKey,
        ecdsaPublicKey: user.ecdsaPublicKey
      }
    });

  } catch (err) {
    console.error('Registration error:', err);
    await logSecurityEvent('AUTH_FAILURE', null, `Registration error: ${err.message}`, req);
    res.status(500).json({ error: 'Registration failed' });
  }
};

const login = async (req, res) => {
  try {
    const { username, password } = req.body;

    const user = await User.findOne({ username });
    if (!user) {
      await logSecurityEvent('AUTH_FAILURE', null, `Login failed: User ${username} not found`, req);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const isValid = await bcrypt.compare(password, user.passwordHash);
    if (!isValid) {
      await logSecurityEvent('AUTH_FAILURE', user._id, 'Invalid password', req);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    await logSecurityEvent('AUTH_SUCCESS', user._id, 'User logged in successfully', req);

    res.json({
      success: true,
      user: {
        id: user._id,
        username: user.username,
        ecdhPublicKey: user.ecdhPublicKey,
        ecdsaPublicKey: user.ecdsaPublicKey
      }
    });

  } catch (err) {
    console.error('Login error:', err);
    await logSecurityEvent('AUTH_FAILURE', null, `Login error: ${err.message}`, req);
    res.status(500).json({ error: 'Login failed' });
  }
};

module.exports = { register, login };