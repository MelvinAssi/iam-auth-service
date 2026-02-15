const { logAudit } = require("../services/audit.service");


const validateTurnstile = async (req, res, next) => {
    const { token } = req.body;
    const remoteip = req.ip;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);

    if (!token) {
        return res.status(400).json({ error: 'Token CAPTCHA missing' });
    }

    try {
        const response = await fetch(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify", {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: new URLSearchParams({
                secret: process.env.Turnstile_SECRET_KEY,
                response: token,
                remoteip: remoteip,
            }),
            signal: controller.signal
        });

        clearTimeout(timeout);

        const data = await response.json();
        if (!data.success) {
            await logAudit({
                action: "CAPTCHA_FAILED",
                userId: null,
                req,
                metadata: { errorCodes: data['error-codes'] }
            });

            return res.status(400).json({
                error: 'CAPTCHA check failed',
                errorCodes: data['error-codes'] || ['unknown'],
            });
        }
        next();
    } catch (error) {
        console.error('Error reCAPTCHA:', error);
        await logAudit({
            action: "CAPTCHA_ERROR",
            userId: null,
            req,
            metadata: { message: error.message }
        });
        return res.status(500).json({ error: 'Error CAPTCHA', details: error.message });
    }
};

module.exports = validateTurnstile;