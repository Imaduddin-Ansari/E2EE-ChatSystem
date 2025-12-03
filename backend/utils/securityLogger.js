const SecurityLog = require('../models/SecurityLog');

const logSecurityEvent = async (eventType, userId, details, req) => {
  try {
    await SecurityLog.create({
      userId,
      eventType,
      details,
      ipAddress: req.ip || req.connection.remoteAddress
    });
  } catch (err) {
    console.error('Security logging failed:', err);
  }
};

module.exports = { logSecurityEvent };