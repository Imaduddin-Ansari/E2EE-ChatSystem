// =============================================================================
// SECURITY ROUTES
// =============================================================================

const express = require('express');
const router = express.Router();
const { getUserLogs, getAllLogs, getReplayStats } = require('../controllers/securityController');

router.get('/logs/:userId', getUserLogs);
router.get('/logs', getAllLogs);
router.get('/replay-stats', getReplayStats);

module.exports = router;