'use strict';
const { Model, Sequelize } = require('sequelize');

module.exports = (sequelize, DataTypes) => {
    class EmailVerificationTokens extends Model {
        static associate(models) {
            EmailVerificationTokens.belongsTo(models.Users, {
                foreignKey: 'user_id',
                as: 'user',
                onDelete: 'CASCADE',
                onUpdate: 'CASCADE',
            });
        }
    }

    EmailVerificationTokens.init({
        id_email_verification_token: {
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
        verified_at: {
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
        modelName: 'EmailVerificationTokens',
        tableName: 'email_verification_tokens',
        timestamps: false,
    });

    return EmailVerificationTokens;
};
