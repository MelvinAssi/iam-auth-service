'use strict';
const { Model, Sequelize } = require('sequelize');

module.exports = (sequelize, DataTypes) => {
    class UserCredentials extends Model {
        static associate(models) {
            UserCredentials.belongsTo(models.Users, {
                foreignKey: 'user_id',
                as: 'user',
                onDelete: 'CASCADE',
                onUpdate: 'CASCADE',
            });
        }
    }

    UserCredentials.init({
        id_user_credential: {
            type: DataTypes.UUID,
            defaultValue: Sequelize.literal('gen_random_uuid()'),
            primaryKey: true,
        },
        password_hash: {
            type: DataTypes.TEXT,
            allowNull: false,
        },
        password_algo: {
            type: DataTypes.TEXT,
            allowNull: false,
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
        modelName: 'UserCredentials',
        tableName: 'user_credentials',
        underscored: true,
        timestamps: true,
        createdAt: true,
        updatedAt: true,
    });

    return UserCredentials;
};
