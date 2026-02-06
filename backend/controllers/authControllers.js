const argon2 = require("argon2");
const jwt = require("jsonwebtoken");
const { validationResult } = require('express-validator');
const models = require("../models");
const { Op } = require("sequelize");
const { Users, Roles, UserRoles,UserCredentials } = models


exports.signUp = async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ error: errors.array()[0].msg });
        }

        const { email, username, password } = req.body;

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
        });

        return res.status(201).json({
            message: "User created successfully"
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
