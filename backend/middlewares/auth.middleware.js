const jwt = require("jsonwebtoken");
const models = require("../models");
const { Session, Users } = models;

module.exports = async (req, res, next) => {
    try {
        const token = req.cookies.access_token;
        if (!token) {
            return res.status(401).json({ message: "Missing Token" });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const session = await Session.findOne({
            where: {
                refresh_token_hash: token,
                is_revoked: false
            },
            include: [
                {
                    model: Users,
                    as: "user",
                }
            ]
        });
        if (!session) {
            return res.status(401).json({ message: "Invalid or expired session" });
        }

        if (new Date() > session.expires_at) {
            await session.update({ is_revoked: true });
            return res.status(401).json({ message: "expired Session " });
        }

        req.user = {
            id_user: decoded.sub,
            role: decoded.role,
            email: session.user.email
        };

        req.session = session;

        next();

    } catch (err) {
        return res.status(403).json({ message: "Invalid Token " });
    }
};
