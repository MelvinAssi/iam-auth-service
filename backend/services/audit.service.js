const { AuditLogs } = require("../models");

async function logAudit({
    action,
    userId = null,
    req = null,
    targetType = null,
    targetId = null,
    metadata = null
}) {
    await AuditLogs.create({
        action,
        user_id: userId,
        target_type: targetType,
        target_id: targetId,
        metadata,
        ip_address: req?.ip,
        user_agent: req?.headers["user-agent"]
    });
}

module.exports = { logAudit };