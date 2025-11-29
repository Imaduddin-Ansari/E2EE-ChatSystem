// =============================================================================
// USER CONTROLLER
// =============================================================================

const User = require('../models/User');

const getUsers = async (req, res) => {
  try {
    const users = await User.find({ _id: { $ne: req.params.userId } })
      .select('username ecdhPublicKey ecdsaPublicKey');
    res.json({ success: true, users });
  } catch (err) {
    console.error('Get users error:', err);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
};

const getUserProfile = async (req, res) => {
  try {
    const user = await User.findById(req.params.userId)
      .select('username ecdhPublicKey ecdsaPublicKey');
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.json({ success: true, user });
  } catch (err) {
    console.error('Get user profile error:', err);
    res.status(500).json({ error: 'Failed to fetch user' });
  }
};

module.exports = { getUsers, getUserProfile };