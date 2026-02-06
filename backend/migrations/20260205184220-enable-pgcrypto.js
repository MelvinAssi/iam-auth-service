'use strict';

/** @type {import('sequelize-cli').Migration} */

module.exports = {
  async up(queryInterface, Sequelize) {
    // Enable pgcrypto for gen_random_uuid()
    await queryInterface.sequelize.query("CREATE EXTENSION IF NOT EXISTS pgcrypto;");
  },

  async down(queryInterface, Sequelize) {
    // Be cautious: dropping extension might fail if other objects depend on it
    await queryInterface.sequelize.query("DROP EXTENSION IF EXISTS pgcrypto;");
  }
};
