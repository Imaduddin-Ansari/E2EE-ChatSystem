// =============================================================================
// KEY EXCHANGE ROUTES
// =============================================================================

const express = require('express');
const router = express.Router();
const { initiateKeyExchange } = require('../controllers/keyExchangeController');

router.post('/initiate', initiateKeyExchange);

module.exports = router;