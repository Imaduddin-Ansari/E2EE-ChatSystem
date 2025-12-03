const express = require('express');
const router = express.Router();
const { initiateKeyExchange } = require('../controllers/keyExchangeController');

router.post('/exchange-keys', async (req, res) => {
  const { publicKey, userId } = req.body;
  
  await KeyExchange.create({
    userId,
    publicKey,
    timestamp: new Date()
  });
  
  res.json({ success: true });
});

module.exports = router;


