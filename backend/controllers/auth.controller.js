

const argon2 = require("argon2");
const jwt = require("jsonwebtoken");

const { validationResult } = require('express-validator');
const sequelize = require('../config/db');
const models = require("../models");
const { Op } = require("sequelize");
const generateToken = require("../utils/generateToken");
const hashToken = require("../utils/hashToken");
const { sendVerifyEmail, sendResetPasswordEmail } = require("../services/mail");
const { verifyGoogleToken } = require("../services/oauth/verifyGoogleToken");
const { logAudit } = require("../services/audit.service");
const { issueAuthTokens, handleOAuth } = require("../services/auth.service");

const { Users, Roles, UserRoles, UserCredentials, Sessions, LoginAttempts, EmailVerificationTokens, PasswordResetTokens } = models


exports.registerUser = async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ error: errors.array()[0].msg });
        }
        const { email, username, password } = req.body;
        let emailPayload;

        await sequelize.transaction(async (t) => {

            const existingUser = await Users.findOne({
                where: {
                    [Op.or]: [{ email }, { username }]
                },
                transaction: t
            });

            if (existingUser) {
                throw new Error("EMAIL_OR_USERNAME_EXISTS");
            }

            const password_hash = await argon2.hash(password);

            const user = await Users.create({
                email,
                username,
                is_active: true,
                is_email_verified: false
            }, { transaction: t });

            const role = await Roles.findOne({
                where: { name: "USER" },
                transaction: t
            });

            if (!role) {
                throw new Error("ROLE_NOT_FOUND");
            }

            await UserRoles.create({
                user_id: user.id_user,
                role_id: role.id_role
            }, { transaction: t });

            await UserCredentials.create({
                password_hash,
                password_algo: "argon2id",
                user_id: user.id_user
            }, { transaction: t });


            const token = generateToken();
            const hash = hashToken(token);
            const expires_at = new Date(Date.now() + 24 * 60 * 60 * 1000);

            await EmailVerificationTokens.create(
                {
                    token_hash: hash,
                    expires_at,
                    verified_at: null,
                    user_id: user.id_user,
                },
                { transaction: t }
            );

            emailPayload = {
                to: user.email,
                token,
            };
            await logAudit({
                action: "USER_REGISTERED",
                userId: user.id_user,
                req
            });

        });

        await sendVerifyEmail(emailPayload);
        //await issueAuthTokens({ req, res,user,attempt :null,true});
        return res.status(201).json({
            message: "User created successfully but waiting for email verify"
        });

    } catch (err) {
        console.error("signUp error:", err);

        if (err.message === "EMAIL_OR_USERNAME_EXISTS") {
            return res.status(400).json({
                error: "Email or username already in use"
            });
        }

        if (err.message === "ROLE_NOT_FOUND") {
            return res.status(500).json({
                error: "Role USER not found"
            });
        }

        return res.status(500).json({ error: "Server error" });
    }
};

// signin with email or username
exports.loginUser = async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ error: errors.array()[0].msg });
        }
        const { email, password, username } = req.body;
        const user = await Users.findOne({
            where: {
                [Op.or]: [{ email }, { username }]
            },
            include: [
                {
                    model: UserCredentials,
                    as: 'credentials',
                    attributes: ["password_hash"]
                }
            ]
        });

        if (!user) {
            await LoginAttempts.create({
                ip_address: req.ip,
                success: false,
                identifier_attempted: email || username,
                user_id: null
            });
            await logAudit({
                action: "USER_LOGIN_FAILED",
                userId: null,
                req,
                metadata: { identifier: email || username }
            });
            await new Promise(r => setTimeout(r, 500));
            throw new Error("EMAIL_OR_USERNAME_ERROR");
        }

        const recentAttempts = await LoginAttempts.count({
            where: {
                identifier_attempted: email || username,
                success: false,
                created_at: { [Op.gt]: new Date(Date.now() - 15 * 60 * 1000) },
                ip_address: req.ip
            }
        });

        if (recentAttempts >= 4) {
            throw new Error("TOO_MANY_ATTEMPTS");
        }

        const attempt = await LoginAttempts.create({
            ip_address: req.ip,
            success: false,
            identifier_attempted: email || username,
            user_id: user.id_user,
        })

        const isPasswordValid = await argon2.verify(
            user.credentials.password_hash,
            password
        );
        if (!isPasswordValid) {
            throw new Error("PASSWORD_ERROR");
        }

        if (!user.is_active) {
            throw new Error("ACCOUNT_DISABLED");
        }

        await issueAuthTokens({ req, res, user, attempt });

    } catch (err) {
        console.error("signIN error:", err);

        if (err.message === "EMAIL_OR_USERNAME_ERROR" || err.message === "PASSWORD_ERROR") {
            return res.status(400).json({
                error: "Email or username or password wrong"
            });
        }
        if (err.message === "ACCOUNT_DISABLED") {
            return res.status(403).json({
                error: "Account has been disabled"
            });
        }
        if (err.message === "TOO_MANY_ATTEMPTS") {
            return res.status(403).json({
                error: "Account has been suppend for 15 min"
            });
        }
        return res.status(500).json({ error: "Server error" });
    }
};

exports.authWithGoogle = async (req, res) => {
    try {
        const { token } = req.body;
        const payload = await verifyGoogleToken(token);
        const { sub: googleId, email, given_name, family_name } = payload;

        const { user, isNew } = await handleOAuth({
            provider: 'google',
            providerId: googleId,
            email,
            info: { name: family_name, firstname: given_name },
        });

        return issueAuthTokens({ req, res, user, attempt: null, isNew });
    } catch (error) {
        console.error(error);
        res.status(401).json({ message: 'Erreur authentification Google' });
    }
};

exports.logoutUser = async (req, res) => {
    try {
        await req.session.update({ is_revoked: true });

        await logAudit({
            action: "USER_LOGOUT",
            userId: req.user.id_user,
            req,
            targetType: "SESSION",
            targetId: req.session.id_session
        });

        res.clearCookie("access_token");
        res.clearCookie("refresh_token");

        return res.status(200).json({ success: true });

    } catch (err) {
        res.status(500).json({ error: "signOut failed" });
    }
};

exports.refreshTokens = async (req, res) => {
    const refreshToken = req.cookies.refresh_token;

    if (!refreshToken) {
        return res.status(401).json({ message: "Missing refresh token" });
    }

    const refreshTokenHash = hashToken(refreshToken);

    const session = await Sessions.findOne({
        where: {
            refresh_token_hash: refreshTokenHash,
            is_revoked: false,
            expires_at: { [Op.gt]: new Date() }
        }
    });

    if (!session) {
        // possible reuse attack
        const compromisedSession = await Sessions.findOne({
            where: { refresh_token_hash: refreshTokenHash }
        });

        if (compromisedSession) {
            await Sessions.update(
                { is_revoked: true },
                { where: { user_id: compromisedSession.user_id } }
            );

            await logAudit({
                action: "REFRESH_TOKEN_REUSE_DETECTED",
                userId: compromisedSession.user_id,
                req,
                targetType: "SESSION"
            });
        }

        return res.status(401).json({ message: "Invalid session" });
    }

    const newRefreshToken = generateToken();
    const newRefreshTokenHash = hashToken(newRefreshToken);

    await session.update({
        refresh_token_hash: newRefreshTokenHash,
        expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
    });

    const newAccessToken = jwt.sign(
        { sub: session.user_id },
        process.env.JWT_SECRET,
        { expiresIn: "15m" }
    );

    res.cookie("access_token", newAccessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: process.env.NODE_ENV === "production" ? "None" : "Lax"
    });

    res.cookie("refresh_token", newRefreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: process.env.NODE_ENV === "production" ? "None" : "Lax"
    });

    return res.status(200).json({ success: true });
};


exports.resendEmailVerification = async (req, res) => {
    try {
        const id_user = req.user.id_user;
        let emailPayload;

        await sequelize.transaction(async (t) => {
            const user = await Users.findOne({
                where: { id_user },
                transaction: t,
            });

            if (!user) {
                throw new Error("USER_NOT_FOUND");
            }

            if (user.is_email_verified) {
                throw new Error("EMAIL_ALREADY_VERIFIED");
            }

            const token = generateToken();
            const hash = hashToken(token);
            const expires_at = new Date(Date.now() + 24 * 60 * 60 * 1000);

            await EmailVerificationTokens.create(
                {
                    token_hash: hash,
                    expires_at,
                    verified_at: null,
                    user_id: user.id_user,
                },
                { transaction: t }
            );

            emailPayload = {
                to: user.email,
                token,
            };
        });
        await sendVerifyEmail(emailPayload);

        return res.status(200).json({
            message: "Verification email sent",
        });

    } catch (err) {
        console.error("resendLinkVerifyEmail error:", err);

        if (err.message === "EMAIL_ALREADY_VERIFIED") {
            return res.status(400).json({ error: "Email already verified" });
        }

        return res.status(500).json({ error: "Server error" });
    }
};

exports.verifyEmail = async (req, res) => {
    try {
        const { token } = req.query;

        if (!token) {
            return res.status(400).json({ error: "Token is required" });
        }

        const token_hash = hashToken(token);

        await sequelize.transaction(async (t) => {
            const verificationToken = await EmailVerificationTokens.findOne({
                where: {
                    token_hash,
                    verified_at: null,
                    expires_at: { [Op.gt]: new Date() },
                },
                transaction: t,
            });

            if (!verificationToken) {
                throw new Error("INVALID_OR_EXPIRED_TOKEN");
            }

            const user = await Users.findByPk(
                verificationToken.user_id,
                { transaction: t }
            );

            if (!user) {
                throw new Error("USER_NOT_FOUND");
            }

            if (user.is_email_verified) {
                throw new Error("EMAIL_ALREADY_VERIFIED");
            }

            await user.update(
                {
                    is_email_verified: true,
                },
                { transaction: t }
            );

            await verificationToken.update(
                {
                    verified_at: new Date(),
                },
                { transaction: t }
            );
        });

        return res.status(200).json({
            message: "Email successfully verified",
        });

    } catch (err) {
        console.error("confirmEmail error:", err);

        if (err.message === "INVALID_OR_EXPIRED_TOKEN") {
            return res.status(400).json({ error: "Invalid or expired token" });
        }

        if (err.message === "EMAIL_ALREADY_VERIFIED") {
            return res.status(400).json({ error: "Email already verified" });
        }

        return res.status(500).json({ error: "Server error" });
    }
};

exports.requestPasswordReset = async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ error: errors.array()[0].msg });
        }
        const { email, username } = req.body;
        await sequelize.transaction(async (t) => {
            const user = await Users.findOne({
                where: {
                    [Op.or]: [{ email }, { username }]
                },
                transaction: t
            });

            if (user) {
                const token = generateToken();
                const hash = hashToken(token);

                const expires_at = new Date(Date.now() + 1 * 60 * 60 * 1000); //This link expires in 1 hour.

                await PasswordResetTokens.create({
                    token_hash: hash,
                    expires_at,
                    used_at: null,
                    user_id: user.id_user,
                })

                await logAudit({
                    action: "PASSWORD_RESET_REQUESTED",
                    userId: user.id_user,
                    req
                });

                await sendResetPasswordEmail(user.email, token);
            }


        })

        return res.status(200).json({ message: "If account exists, email sent" });

    } catch (err) {
        console.error(" error:", err);
        return res.status(500).json({ error: "Server error" });
    }
}

exports.resetPasswordWithToken = async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ error: errors.array()[0].msg });
        }
        const { password } = req.body;
        const { token } = req.query;


        if (!token) {
            return res.status(400).json({ error: "Token is required" });
        }

        const token_hash = hashToken(token);

        await sequelize.transaction(async (t) => {
            const verificationToken = await PasswordResetTokens.findOne({
                where: {
                    token_hash,
                    used_at: null,
                    expires_at: { [Op.gt]: new Date() },
                },
                transaction: t,
            });
            if (!verificationToken) {
                throw new Error("INVALID_OR_EXPIRED_TOKEN");
            }

            const user = await Users.findByPk(
                verificationToken.user_id,
                { transaction: t }
            );

            if (!user) {
                throw new Error("USER_NOT_FOUND");
            }

            const password_hash = await argon2.hash(password);
            await UserCredentials.update(
                { password_hash },
                {
                    where: { user_id: user.id_user },
                    transaction: t,
                }
            );

            await verificationToken.update(
                {
                    used_at: new Date(),
                },
                { transaction: t }
            );

            await Sessions.update(
                { is_revoked: true },
                { where: { user_id: user.id_user }, transaction: t }
            );

            await logAudit({
                action: "PASSWORD_RESET_SUCCESS",
                userId: user.id_user,
                req
            });

        })

        return res.status(200).json({ message: "Password updated" });

    } catch (err) {
        console.error(" error:", err);
        return res.status(500).json({ error: "Server error" });
    }
}
exports.getActiveSessions = async (req, res) => {
    try {
        const id_user = req.user.id_user;
        const sessions = await Sessions.findAll(
            {
                where: {
                    user_id: id_user,
                    is_revoked: false,
                },
            });
        return res.status(200).json({
            sessions
        });

    } catch (err) {
        console.error("getActiveSessions error:", err);
        return res.status(500).json({ error: "Server error" });
    }
};
exports.deleteActiveSession = async (req, res) => {
    try {
        const id_user = req.user.id_user;
        const { id } = req.params;
        const session = await Sessions.update(
            { is_revoked: true },
            {
                where: {
                    id_session: id,
                    user_id: id_user,
                    is_revoked: false,
                },
            });
        return res.status(200).json({
            session
        });

    } catch (err) {
        console.error("getActiveSessions error:", err);
        return res.status(500).json({ error: "Server error" });
    }
};
exports.getCurrentUser = async (req, res) => {
    try {
        const user = await Users.findByPk(req.user.id_user, {
            attributes: [
                "id_user",
                "email",
                "username",
                "is_email_verified",
                "is_active",
                "created_at"
            ],
        });

        if (!user) {
            return res.status(404).json({ error: "USER_NOT_FOUND" });
        }

        return res.status(200).json({
            user,
            roles: req.user.roles,
        });

    } catch (err) {
        console.error("getMe error:", err);
        return res.status(500).json({ error: "Server error" });
    }
};


