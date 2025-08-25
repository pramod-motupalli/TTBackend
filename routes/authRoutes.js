const express = require('express');
const authController = require('../controllers/authController');

const router = express.Router();

// Your frontend code posts to /forgot-password
router.post('/forgot-password', authController.forgotPassword);

// You'll need this route for the link that's emailed to the user
// router.patch('/reset-password/:token', authController.resetPassword);

module.exports = router;