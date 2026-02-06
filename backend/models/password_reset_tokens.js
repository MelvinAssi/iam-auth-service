'use strict';
const { Model, Sequelize } = require('sequelize');

module.exports = (sequelize, DataTypes) => {
    class PasswordResetTokens extends Model {
        static associate(models) {
            PasswordResetTokens.belongsTo(models.Users, {
                foreignKey: 'user_id',
                as: 'user',
                onDelete: 'CASCADE',
                onUpdate: 'CASCADE',
            });
        }
    }

    PasswordResetTokens.init({
        id_password_reset_token: {
            type: DataTypes.UUID,
            defaultValue: Sequelize.literal('gen_random_uuid()'),
            primaryKey: true,
        },
        token_hash: {
            type: DataTypes.TEXT,
            allowNull: false,
        },
        expires_at: {
            type: DataTypes.DATE,
            allowNull: false,
        },
        used_at: {
            type: DataTypes.DATE,
            allowNull: true,
        },
        user_id: {
            type: DataTypes.UUID,
            allowNull: false,
            references: {
                model: 'users',
                key: 'id_user',
            },
        },
    }, {
        sequelize,
        modelName: 'PasswordResetTokens',
        tableName: 'password_reset_tokens',
        timestamps: false,
    });

    return PasswordResetTokens;
};
