'use strict';
const { Model, Sequelize } = require('sequelize');

module.exports = (sequelize, DataTypes) => {
    class Sessions extends Model {
        static associate(models) {
            Sessions.belongsTo(models.Users, {
                foreignKey: 'user_id',
                as: 'user',
                onDelete: 'CASCADE',
                onUpdate: 'CASCADE',
            });
        }
    }

    Sessions.init({
        id_session: {
            type: DataTypes.UUID,
            defaultValue: Sequelize.literal('gen_random_uuid()'),
            primaryKey: true,
        },
        refresh_token_hash: {
            type: DataTypes.TEXT,
            allowNull: false,
        },
        ip_address: {
            type: DataTypes.TEXT,
            allowNull: true,
        },
        user_agent: {
            type: DataTypes.TEXT,
            allowNull: true,
        },
        is_revoked: {
            type: DataTypes.BOOLEAN,
            defaultValue: false,
        },
        expires_at: {
            type: DataTypes.DATE,
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
        modelName: 'Sessions',
        tableName: 'sessions',
        underscored: true,
        timestamps: true,
        createdAt: true,
        updatedAt: false,
    });

    return Sessions;
};
