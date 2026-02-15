const models = require("../models");
const { Users, Roles, UserRoles, Sessions } = models

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

    await logAudit({
        action: "USER_LOGIN_SUCCESS",
        userId: user.id_user,
        req
    });

    res.cookie("access_token", accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: process.env.NODE_ENV === "production" ? "None" : "Lax",
        maxAge: 15 * 60 * 1000,
    });

    res.cookie("refresh_token", refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: process.env.NODE_ENV === "production" ? "None" : "Lax",
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

        if (user && !user.is_active) {
            throw new Error("ACCOUNT_DISABLED");
        }

        if (!user) {
            user = await Users.create({
                email,
                username: info.firstname,
                is_active: true,
                is_email_verified: true
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

module.exports = {issueAuthTokens, handleOAuth };