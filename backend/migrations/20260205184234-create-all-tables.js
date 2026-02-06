'use strict';

/** @type {import('sequelize-cli').Migration} */
module.exports = {
  async up(queryInterface, Sequelize) {

    /* ===================== USERS ===================== */
    await queryInterface.createTable('users', {
      id_user: {
        type: Sequelize.UUID,
        defaultValue: Sequelize.literal('gen_random_uuid()'),
        primaryKey: true,
      },
      email: {
        type: Sequelize.STRING(100),
        allowNull: false,
        unique: true,
      },
      username: {
        type: Sequelize.STRING(100),
        allowNull: false,
        unique: true,
      },
      is_active: {
        type: Sequelize.BOOLEAN,
        defaultValue: true,
      },
      is_email_verified: {
        type: Sequelize.BOOLEAN,
        defaultValue: false,
      },
      created_at: {
        type: Sequelize.DATE,
        defaultValue: Sequelize.literal('now()'),
      },
      updated_at: {
        type: Sequelize.DATE,
        defaultValue: Sequelize.literal('now()'),
      },
      deleted_at: {
        type: Sequelize.DATE,
        allowNull: true,
      },
    });

    /* ===================== ROLES ===================== */
    await queryInterface.createTable('roles', {
      id_role: {
        type: Sequelize.UUID,
        defaultValue: Sequelize.literal('gen_random_uuid()'),
        primaryKey: true,
      },
      name: {
        type: Sequelize.STRING(50),
        allowNull: false,
        unique: true,
      },
      description: Sequelize.TEXT,
    });

    /* ===================== USER CREDENTIALS ===================== */
    await queryInterface.createTable('user_credentials', {
      id_user_credential: {
        type: Sequelize.UUID,
        defaultValue: Sequelize.literal('gen_random_uuid()'),
        primaryKey: true,
      },
      password_hash: {
        type: Sequelize.TEXT,
        allowNull: false,
      },
      password_algo: {
        type: Sequelize.TEXT,
        allowNull: false,
      },
      user_id: {
        type: Sequelize.UUID,
        allowNull: false,
        references: { model: 'users', key: 'id_user' },
        onDelete: 'CASCADE',
        onUpdate: 'CASCADE',
      },
      created_at: {
        type: Sequelize.DATE,
        defaultValue: Sequelize.literal('now()'),
      },
      updated_at: {
        type: Sequelize.DATE,
        defaultValue: Sequelize.literal('now()'),
      },
    });

    await queryInterface.addConstraint('user_credentials', {
      fields: ['user_id'],
      type: 'unique',
      name: 'uniq_user_credentials_user',
    });

    /* ===================== SESSIONS ===================== */
    await queryInterface.createTable('sessions', {
      id_session: {
        type: Sequelize.UUID,
        defaultValue: Sequelize.literal('gen_random_uuid()'),
        primaryKey: true,
      },
      refresh_token_hash: {
        type: Sequelize.TEXT,
        allowNull: false,
        unique: true,
      },
      ip_address: Sequelize.TEXT,
      user_agent: Sequelize.TEXT,
      is_revoked: {
        type: Sequelize.BOOLEAN,
        defaultValue: false,
      },
      expires_at: {
        type: Sequelize.DATE,
        allowNull: false,
      },
      user_id: {
        type: Sequelize.UUID,
        allowNull: false,
        references: { model: 'users', key: 'id_user' },
        onDelete: 'CASCADE',
      },
      created_at: {
        type: Sequelize.DATE,
        defaultValue: Sequelize.literal('now()'),
      },
      updated_at: {
        type: Sequelize.DATE,
        defaultValue: Sequelize.literal('now()'),
      },
    });

    /* ===================== PASSWORD RESET TOKENS ===================== */
    await queryInterface.createTable('password_reset_tokens', {
      id_password_reset_token: {
        type: Sequelize.UUID,
        defaultValue: Sequelize.literal('gen_random_uuid()'),
        primaryKey: true,
      },
      token_hash: {
        type: Sequelize.TEXT,
        allowNull: false,
      },
      expires_at: {
        type: Sequelize.DATE,
        allowNull: false,
      },
      used_at: Sequelize.DATE,
      user_id: {
        type: Sequelize.UUID,
        allowNull: false,
        references: { model: 'users', key: 'id_user' },
        onDelete: 'CASCADE',
      },
    });

    /* ===================== EMAIL VERIFICATION TOKENS ===================== */
    await queryInterface.createTable('email_verification_tokens', {
      id_email_verification_token: {
        type: Sequelize.UUID,
        defaultValue: Sequelize.literal('gen_random_uuid()'),
        primaryKey: true,
      },
      token_hash: {
        type: Sequelize.TEXT,
        allowNull: false,
      },
      expires_at: {
        type: Sequelize.DATE,
        allowNull: false,
      },
      verified_at: Sequelize.DATE,
      user_id: {
        type: Sequelize.UUID,
        allowNull: false,
        references: { model: 'users', key: 'id_user' },
        onDelete: 'CASCADE',
      },
    });

    /* ===================== LOGIN ATTEMPTS ===================== */
    await queryInterface.createTable('login_attempts', {
      id_login_attempt: {
        type: Sequelize.UUID,
        defaultValue: Sequelize.literal('gen_random_uuid()'),
        primaryKey: true,
      },
      ip_address: Sequelize.TEXT,
      success: {
        type: Sequelize.BOOLEAN,
        allowNull: false,
      },
      created_at: {
        type: Sequelize.DATE,
        defaultValue: Sequelize.literal('now()'),
      },
      user_id: {
        type: Sequelize.UUID,
        allowNull: false,
        references: { model: 'users', key: 'id_user' },
        onDelete: 'CASCADE',
      },
    });

    /* ===================== OAUTH ACCOUNTS ===================== */
    await queryInterface.createTable('oauth_accounts', {
      id_oauth_account: {
        type: Sequelize.UUID,
        defaultValue: Sequelize.literal('gen_random_uuid()'),
        primaryKey: true,
      },
      provider: {
        type: Sequelize.STRING(30),
        allowNull: false,
      },
      provider_id: {
        type: Sequelize.STRING(50),
        allowNull: false,
      },
      email: Sequelize.STRING(50),
      created_at: {
        type: Sequelize.DATE,
        defaultValue: Sequelize.literal('now()'),
      },
      user_id: {
        type: Sequelize.UUID,
        allowNull: false,
        references: { model: 'users', key: 'id_user' },
        onDelete: 'CASCADE',
      },
    });

    await queryInterface.addConstraint('oauth_accounts', {
      fields: ['provider', 'provider_id'],
      type: 'unique',
      name: 'uniq_oauth_provider_provider_id',
    });

    /* ===================== AUDIT LOGS ===================== */
    await queryInterface.createTable('audit_logs', {
      id_audit_log: {
        type: Sequelize.UUID,
        defaultValue: Sequelize.literal('gen_random_uuid()'),
        primaryKey: true,
      },
      metadata: Sequelize.JSONB,
      action: {
        type: Sequelize.TEXT,
        allowNull: false,
      },
      created_at: {
        type: Sequelize.DATE,
        defaultValue: Sequelize.literal('now()'),
      },
      user_id: {
        type: Sequelize.UUID,
        references: { model: 'users', key: 'id_user' },
        onDelete: 'SET NULL',
      },
    });

    /* ===================== USER ROLES ===================== */
    await queryInterface.createTable('user_roles', {
      user_id: {
        type: Sequelize.UUID,
        primaryKey: true,
        references: { model: 'users', key: 'id_user' },
        onDelete: 'CASCADE',
      },
      role_id: {
        type: Sequelize.UUID,
        primaryKey: true,
        references: { model: 'roles', key: 'id_role' },
        onDelete: 'CASCADE',
      },
      assigned_by: Sequelize.UUID,
      assigned_at: {
        type: Sequelize.DATE,
        defaultValue: Sequelize.NOW,
      },
    });
  },

  async down(queryInterface) {
    await queryInterface.dropTable('user_roles');
    await queryInterface.dropTable('audit_logs');
    await queryInterface.dropTable('oauth_accounts');
    await queryInterface.dropTable('login_attempts');
    await queryInterface.dropTable('email_verification_tokens');
    await queryInterface.dropTable('password_reset_tokens');
    await queryInterface.dropTable('sessions');
    await queryInterface.dropTable('user_credentials');
    await queryInterface.dropTable('roles');
    await queryInterface.dropTable('users');
  },
};
