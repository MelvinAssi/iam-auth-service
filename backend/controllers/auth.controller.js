

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

const { Users, Roles, UserRoles, UserCredentials, Sessions, LoginAttempts, EmailVerificationTokens, PasswordResetTokens, OAuthAccounts } = models


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
        await sequelize.transaction(async (t) => {
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
                ],
                transaction: t
            });

            if (!user) {
                throw new Error("EMAIL_OR_USERNAME_ERROR");  //maybe should include password too 
            }

            const role = await user.getRoles();
            console.log(role.map(r => r.name))
            const attempt = await LoginAttempts.create({
                ip_address: req.ip,
                success: false,
                user_id: user.id_user,
            })

            const isPasswordValid = await argon2.verify(
                user.credentials.password_hash,
                password
            );
            if (!isPasswordValid) {
                throw new Error("PASSWORD_ERROR");
            }
            await issueAuthTokens({ req, res, user, attempt });
        });
    } catch (err) {
        console.error("signIN error:", err);

        if (err.message === "EMAIL_OR_USERNAME_ERROR" || err.message === "PASSWORD_ERROR") {
            return res.status(400).json({
                error: "Email or username or password wrong"
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

        return issueAuthTokens(res, user, attempt = null, isNew);
    } catch (error) {
        console.error(error);
        res.status(401).json({ message: 'Erreur authentification Google' });
    }
};

exports.logoutUser = async (req, res) => {
    try {
        await req.session.update({ is_revoked: true });

        res.clearCookie("token");

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
            is_revoked: false
        }
    });

    if (!session) {
        return res.status(401).json({ message: "Invalid session" });
    }

    if (new Date() > session.expires_at) {
        await session.update({ is_revoked: true });
        return res.status(401).json({ message: "Session expired" });
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
        secure: true,
        sameSite: "None",
    });

    res.cookie("refresh_token", newRefreshToken, {
        httpOnly: true,
        secure: true,
        sameSite: "None",
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

            if (!user) {
                throw new Error("EMAIL_OR_USERNAME_ERROR");
            }
            const { token, hash } = generateToken();
            const expires_at = new Date(Date.now() + 1 * 60 * 60 * 1000); //This link expires in 1 hour.

            PasswordResetTokens.create({
                token_hash: hash,
                expires_at,
                used_at: null,
                user_id: user.id_user,
            })
            sendResetPasswordEmail(user.email, token);

        })

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

        })

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


const issueAuthTokens = async ({ req, res, user, attempt = null, isNew = false, }) => {
    const roles = await user.getRoles();
    const roleNames = roles.map(r => r.name);

    const accessToken = jwt.sign(
        {
            sub: user.id_user,
            roles: roleNames,
        },
        process.env.JWT_SECRET,
        { expiresIn: "15m" }
    );

    const refreshToken = generateToken();
    const refreshTokenHash = hashToken(refreshToken);

    /* if only one Sessions needed
    await Sessions.update(
        { is_revoked: true },
        {
            where: {
                user_id: user.id_user,
                is_revoked: false,
            },
        }
    );
    */
    await Sessions.create({
        refresh_token_hash: refreshTokenHash,
        ip_address: req.ip,
        user_agent: req.headers["user-agent"],
        is_revoked: false,
        expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
        user_id: user.id_user,
    });

    if (attempt) {
        await attempt.update({ success: true });
    }

    res.cookie("access_token", accessToken, {
        httpOnly: true,
        secure: true,
        sameSite: "None",
        maxAge: 15 * 60 * 1000,
    });

    res.cookie("refresh_token", refreshToken, {
        httpOnly: true,
        secure: true,
        sameSite: "None",
        maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return res.status(isNew ? 201 : 200).json({
        success: true,
        roles: roleNames,
        is_email_verified: user.is_email_verified,
    });
};

async function handleOAuth({ provider, providerId, email, info }) {
    let user;
    let isNew = false;

    await sequelize.transaction(async (t) => {

        user = await Users.findOne({
            where: { email },
            transaction: t,
        });

        if (!user) {
            user = await Users.create({
                email,
                username: info.firstname,
                is_active: true,
                is_email_verified: true
            }, { transaction: t });

            isNew = true;
        }

        const existingAccount = await OAuthAccounts.findOne({
            where: { provider, providerId },
            transaction: t
        });

        if (!existingAccount) {
            await OAuthAccounts.create({
                provider,
                providerId,
                user_id: user.id_user
            }, { transaction: t });
        }
    });

    return { user, isNew };
}
