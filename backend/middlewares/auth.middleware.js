const jwt = require("jsonwebtoken");
const { Sessions, Users } = require("../models");
const hashToken = require("../utils/hashToken");

module.exports = async (req, res, next) => {
    try {
        const accessToken = req.cookies.access_token;
        const refreshToken = req.cookies.refresh_token;

        if (!accessToken || !refreshToken) {
            return res.status(401).json({ message: "Missing tokens" });
        }

        const decoded = jwt.verify(accessToken, process.env.JWT_SECRET);

        const refreshTokenHash = hashToken(refreshToken);

        const session = await Sessions.findOne({
            where: {
                refresh_token_hash: refreshTokenHash,
                is_revoked: false
            },
            include: [{
                model: Users,
                as: "user"
            }]
        });

        if (!session) {
            return res.status(401).json({ message: "Invalid session" });
        }

        if (new Date() > session.expires_at) {
            await session.update({ is_revoked: true });
            return res.status(401).json({ message: "Session expired" });
        }

        req.user = {
            id_user: decoded.sub,
            roles: decoded.roles,
            email: session.user.email,
            is_email_verified: session.user.is_email_verified
        };

        req.session = session;

        next();

    } catch (err) {
        console.error("auth.middleware error:", err);
        return res.status(403).json({ message: "Invalid token" });
    }
};
