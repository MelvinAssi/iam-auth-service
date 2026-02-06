'use strict';
const { Model, Sequelize } = require('sequelize');

module.exports = (sequelize, DataTypes) => {
    class UserRoles extends Model {
        static associate(models) {
            UserRoles.belongsTo(models.Users, { foreignKey: 'user_id', as: 'user' });
            UserRoles.belongsTo(models.Roles, { foreignKey: 'role_id', as: 'role' });
        }
    }

    UserRoles.init({
        user_id: {
            type: DataTypes.UUID,
            allowNull: false,
            primaryKey: true,
            references: {
                model: 'users',
                key: 'id_user',
            },
        },
        role_id: {
            type: DataTypes.UUID,
            allowNull: false,
            primaryKey: true,
            references: {
                model: 'roles',
                key: 'id_role',
            },
        },
        assigned_by: {
            type: DataTypes.UUID,
            allowNull: true,
            references: {
                model: 'users',
                key: 'id_user',
            },
        },
        assigned_at: {
            type: DataTypes.DATE,
            allowNull: false,
            defaultValue: Sequelize.literal('NOW()'),
        },
    }, {
        sequelize,
        modelName: 'UserRoles',
        tableName: 'user_roles',
        timestamps: false,
    });

    return UserRoles;
};
