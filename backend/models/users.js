'use strict';
const { Model, Sequelize } = require('sequelize');

module.exports = (sequelize, DataTypes) => {
  class Users extends Model {
    static associate(models) {

      Users.hasOne(models.UserCredentials, {
        foreignKey: 'user_id',
        as: 'credentials',
        onDelete: 'CASCADE',
        onUpdate: 'CASCADE',
      });

      Users.hasMany(models.Sessions, {
        foreignKey: 'user_id',
        as: 'sessions',
        onDelete: 'CASCADE',
        onUpdate: 'CASCADE',
      });

      Users.hasMany(models.PasswordResetTokens, {
        foreignKey: 'user_id',
        as: 'password_reset_tokens',
        onDelete: 'CASCADE',
        onUpdate: 'CASCADE',
      });

      Users.hasMany(models.EmailVerificationTokens, {
        foreignKey: 'user_id',
        as: 'email_verification_tokens',
        onDelete: 'CASCADE',
        onUpdate: 'CASCADE',
      });

      Users.hasMany(models.LoginAttempts, {
        foreignKey: 'user_id',
        as: 'login_attempts',
        onDelete: 'CASCADE',
        onUpdate: 'CASCADE',
      });

      Users.hasMany(models.OAuthAccounts, {
        foreignKey: 'user_id',
        as: 'oauth_accounts',
        onDelete: 'CASCADE',
        onUpdate: 'CASCADE',
      });

      Users.hasMany(models.AuditLogs, {
        foreignKey: 'user_id',
        as: 'audit_logs',
        onDelete: 'SET NULL',
        onUpdate: 'CASCADE',
      });

      Users.belongsToMany(models.Roles, {
        through: models.UserRoles,
        foreignKey: 'user_id',
        otherKey: 'role_id',
        as: 'roles',
      });
    }
  }

  Users.init({
    id_user: {
      type: DataTypes.UUID,
      defaultValue: Sequelize.literal('gen_random_uuid()'),
      primaryKey: true,
    },
    email: {
      type: DataTypes.STRING(100),
      allowNull: false,
      unique: true,
    },
    username: {
      type: DataTypes.STRING(100),
      allowNull: false,
      unique: true,
    },
    is_active: {
      type: DataTypes.BOOLEAN,
      defaultValue: true,
    },
    is_email_verified: {
      type: DataTypes.BOOLEAN,
      defaultValue: false,
    },
  }, {
    sequelize,
    modelName: 'Users',
    tableName: 'users',
    underscored: true,
    timestamps: true,
    createdAt: true,
    updatedAt: true,
    paranoid: true,
    deletedAt: true,
  });

  return Users;
};
