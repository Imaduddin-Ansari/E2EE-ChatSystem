// =============================================================================
// USER ROUTES
// =============================================================================

const express = require('express');
const router = express.Router();
const { getUsers, getUserProfile } = require('../controllers/userController');

router.get('/:userId', getUsers);
router.get('/profile/:userId', getUserProfile);

module.exports = router;