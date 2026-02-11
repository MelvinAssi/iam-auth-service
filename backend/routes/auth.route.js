const express = require('express');
const router = express.Router();
const {
    registerUser, loginUser, logoutUser, getCurrentUser,
    resendEmailVerification, verifyEmail,
    requestPasswordReset, resetPasswordWithToken
} = require('../controllers/auth.controller');
const authMiddleware = require('../middlewares/auth.middleware');
const { body } = require('express-validator');

router.post('/signup',
    [
        body('email').isEmail().withMessage('Invalid email'),
        body('username').isLength({ min: 2, max: 64 }).withMessage('Name must be between 2 and 64 characters'),
        body('password')
            .isLength({ min: 12, max: 64 }).withMessage('Password must be between 12 and 64 characters')
            .matches(/[A-Z]/).withMessage('Must contain at least one uppercase letter')
            .matches(/[a-z]/).withMessage('Must contain at least one lowercase letter')
            .matches(/\d/).withMessage('Must contain at least one number')
            .matches(/[!@#$%^&*]/).withMessage('Must contain at least one special character'),
    ]
    , registerUser);
router.post('/signin',
    [
        body('email').isEmail().withMessage('Invalid email').optional(),
        body('username').isLength({ min: 2, max: 64 }).withMessage('Name must be between 2 and 64 characters').optional(),
        body('password')
            .isLength({ min: 12, max: 64 }).withMessage('Password must be between 12 and 64 characters')
            .matches(/[A-Z]/).withMessage('Must contain at least one uppercase letter')
            .matches(/[a-z]/).withMessage('Must contain at least one lowercase letter')
            .matches(/\d/).withMessage('Must contain at least one number')
            .matches(/[!@#$%^&*]/).withMessage('Must contain at least one special character'),
    ]
    , loginUser);

router.post('/signout', authMiddleware, logoutUser);
router.get("/me", authMiddleware, getCurrentUser);

module.exports = router;