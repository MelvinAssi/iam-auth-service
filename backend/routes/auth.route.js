const express = require('express');
const router = express.Router();
const {
    registerUser, loginUser, logoutUser, getCurrentUser,
    resendEmailVerification, verifyEmail,
    requestPasswordReset, resetPasswordWithToken,
    refreshTokens
} = require('../controllers/auth.controller');
const authMiddleware = require('../middlewares/auth.middleware');
const { body } = require('express-validator');
const rateLimit = require('express-rate-limit');

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    skipSuccessfulRequests: true,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        error: 'Too many attempts',
        details: 'Please try again in 15 minutes.'
    }
});

const sensitiveLimiter = rateLimit({
   windowMs: 15 * 60 * 1000,
   max: 10
});


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
        body().custom(body => {
            if (!body.email && !body.username) {
                throw new Error("Email or username required");
            }
            return true;
        }),
        body('password')
            .isLength({ min: 12, max: 64 }).withMessage('Password must be between 12 and 64 characters')
            .matches(/[A-Z]/).withMessage('Must contain at least one uppercase letter')
            .matches(/[a-z]/).withMessage('Must contain at least one lowercase letter')
            .matches(/\d/).withMessage('Must contain at least one number')
            .matches(/[!@#$%^&*]/).withMessage('Must contain at least one special character'),
    ]
    , authLimiter, loginUser);

router.post('/signout', authMiddleware, logoutUser);
router.post('/refresh',sensitiveLimiter, refreshTokens);
router.get("/me", authMiddleware, getCurrentUser);

router.post('/resend-verification', authMiddleware, resendEmailVerification);

router.get('/verify-email',sensitiveLimiter, verifyEmail);

router.post('/password/request',sensitiveLimiter, requestPasswordReset);

router.post('/password/reset',sensitiveLimiter, resetPasswordWithToken);

module.exports = router;