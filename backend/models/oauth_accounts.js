'use strict';
const { Model, Sequelize } = require('sequelize');

module.exports = (sequelize, DataTypes) => {
    class OAuthAccounts extends Model {
        static associate(models) {
            OAuthAccounts.belongsTo(models.Users, {
                foreignKey: 'user_id',
                as: 'user',
                onDelete: 'CASCADE',
                onUpdate: 'CASCADE',
            });
        }
    }

    OAuthAccounts.init({
        id_oauth_account: {
            type: DataTypes.UUID,
            defaultValue: Sequelize.literal('gen_random_uuid()'),
            primaryKey: true,
        },
        provider: {
            type: DataTypes.ENUM('GOOGLE', 'GITHUB', 'FACEBOOK', 'TWITTER'),
            allowNull: false,
        },
        provider_id: {
            type: DataTypes.STRING(50),
            allowNull: false,
        },
        email: {
            type: DataTypes.STRING(50),
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
        modelName: 'OAuthAccounts',
        tableName: 'oauth_accounts',
        underscored: true,
        timestamps: true,
        createdAt: true,
        updatedAt: false,
    });

    return OAuthAccounts;
};
