// =============================================================================
// SECURITY CONTROLLER
// =============================================================================

const SecurityLog = require('../models/SecurityLog');

const getUserLogs = async (req, res) => {
  try {
    const logs = await SecurityLog.find({ userId: req.params.userId })
      .sort({ timestamp: -1 })
      .limit(100);
    
    res.json({ success: true, logs });
  } catch (err) {
    console.error('Get user logs error:', err);
    res.status(500).json({ error: 'Failed to retrieve logs' });
  }
};

const getAllLogs = async (req, res) => {
  try {
    const logs = await SecurityLog.find()
      .sort({ timestamp: -1 })
      .limit(200);
    
    res.json({ success: true, logs });
  } catch (err) {
    console.error('Get all logs error:', err);
    res.status(500).json({ error: 'Failed to retrieve logs' });
  }
};

const getReplayStats = async (req, res) => {
  try {
    const replayAttempts = await SecurityLog.countDocuments({ 
      eventType: 'REPLAY_DETECTED' 
    });
    const invalidSignatures = await SecurityLog.countDocuments({ 
      eventType: 'INVALID_SIGNATURE' 
    });
    const decryptFailures = await SecurityLog.countDocuments({ 
      eventType: 'DECRYPT_FAILURE' 
    });
    
    res.json({ 
      success: true, 
      stats: { replayAttempts, invalidSignatures, decryptFailures }
    });
  } catch (err) {
    console.error('Get replay stats error:', err);
    res.status(500).json({ error: 'Failed to retrieve stats' });
  }
};

module.exports = { getUserLogs, getAllLogs, getReplayStats };