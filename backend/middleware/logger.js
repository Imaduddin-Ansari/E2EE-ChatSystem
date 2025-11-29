// =============================================================================
// REQUEST LOGGER MIDDLEWARE
// =============================================================================

const requestLogger = (req, res, next) => {
  console.log('='.repeat(50));
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
  console.log('Origin:', req.headers.origin);
  console.log('Headers:', JSON.stringify(req.headers, null, 2));
  next();
};

module.exports = requestLogger;