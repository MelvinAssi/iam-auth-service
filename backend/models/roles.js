'use strict';
const { Model, Sequelize } = require('sequelize');

module.exports = (sequelize, DataTypes) => {
    class Roles extends Model {
        static associate(models) {
            Roles.belongsToMany(models.Users, {
                through: models.UserRoles,
                foreignKey: 'role_id',
                otherKey: 'user_id',
                as: 'users',
            });
        }
    }

    Roles.init({
        id_role: {
            type: DataTypes.UUID,
            defaultValue: Sequelize.literal('gen_random_uuid()'),
            primaryKey: true,
        },
        name: {
            type: DataTypes.STRING(50),
            allowNull: false,
            unique: true,
        },
        description: {
            type: DataTypes.TEXT,
            allowNull: true,
        },
    }, {
        sequelize,
        modelName: 'Roles',
        tableName: 'roles',
        timestamps: false,
    });

    return Roles;
};
