'use strict';
const { Model, Sequelize } = require('sequelize');

module.exports = (sequelize, DataTypes) => {
    class LoginAttempts extends Model {
        static associate(models) {
            LoginAttempts.belongsTo(models.Users, {
                foreignKey: 'user_id',
                as: 'user',
                onDelete: 'CASCADE',
                onUpdate: 'CASCADE',
            });
        }
    }

    LoginAttempts.init({
        id_login_attempt: {
            type: DataTypes.UUID,
            defaultValue: Sequelize.literal('gen_random_uuid()'),
            primaryKey: true,
        },
        ip_address: {
            type: DataTypes.TEXT,
            allowNull: true,
        },
        success: {
            type: DataTypes.BOOLEAN,
            allowNull: false,
        },
        identifier_attempted: {
            type: DataTypes.STRING(100),
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
        modelName: 'LoginAttempts',
        tableName: 'login_attempts',
        underscored: true,
        timestamps: true,
        createdAt: true,
        updatedAt: false,
    });

    return LoginAttempts;
};
