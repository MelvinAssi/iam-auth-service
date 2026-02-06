'use strict';
const { Model, Sequelize } = require('sequelize');

module.exports = (sequelize, DataTypes) => {
    class AuditLogs extends Model {
        static associate(models) {
            AuditLogs.belongsTo(models.Users, {
                foreignKey: 'user_id',
                as: 'user',
                onDelete: 'SET NULL',
                onUpdate: 'CASCADE',
            });
        }
    }

    AuditLogs.init({
        id_audit_log: {
            type: DataTypes.UUID,
            defaultValue: Sequelize.literal('gen_random_uuid()'),
            primaryKey: true,
        },
        metadata: {
            type: DataTypes.JSONB,
            allowNull: true,
        },
        action: {
            type: DataTypes.TEXT,
            allowNull: false,
        },
        user_id: {
            type: DataTypes.UUID,
            allowNull: true,
            references: {
                model: 'users',
                key: 'id_user',
            },
        },
    }, {
        sequelize,
        modelName: 'AuditLogs',
        tableName: 'audit_logs',
        underscored: true,
        timestamps: true,
        createdAt: true,
        updatedAt: false,
    });

    return AuditLogs;
};
