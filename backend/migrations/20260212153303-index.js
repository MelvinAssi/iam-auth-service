'use strict';

/** @type {import('sequelize-cli').Migration} */
module.exports = {
  async up(queryInterface, Sequelize) {
    // Password reset lookup
    await queryInterface.addIndex('password_reset_tokens', ['token_hash'], {
      name: 'ix_password_reset_token',
    });

    // Email verification lookup
    await queryInterface.addIndex('email_verification_tokens', ['token_hash'], {
      name: 'ix_email_verification_token',
    });

    // Active sessions per user
    await queryInterface.addIndex('sessions', ['user_id'], {
      name: 'ix_sessions_user_active',
      where: { is_revoked: false },
    });

    // Audit logs lookup by user
    await queryInterface.addIndex('audit_logs', ['user_id'], {
      name: 'ix_audit_logs_user',
    });

    // Audit logs lookup by target
    await queryInterface.addIndex('audit_logs', ['target_type', 'target_id'], {
      name: 'ix_audit_logs_target',
    });

  },

  async down(queryInterface, Sequelize) {
    await queryInterface.removeIndex('audit_logs', 'ix_audit_logs_target');
    await queryInterface.removeIndex('audit_logs', 'ix_audit_logs_user');
    await queryInterface.removeIndex('sessions', 'ix_sessions_user_active');
    await queryInterface.removeIndex('email_verification_tokens', 'ix_email_verification_token');
    await queryInterface.removeIndex('password_reset_tokens', 'ix_password_reset_token');
  }
};
