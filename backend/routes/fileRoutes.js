// =============================================================================
// FILE ROUTES
// =============================================================================

const express = require('express');
const router = express.Router();
const { uploadFile, getFiles } = require('../controllers/fileController');

router.post('/', uploadFile);
router.get('/:userId/:recipientId', getFiles);

module.exports = router;