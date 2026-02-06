'use strict';

module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.bulkInsert('roles', [
      { name: 'USER', description: 'Standard user' },
      { name: 'ADMIN', description: 'Administrator with all rights' },
      { name: 'AGENT', description: 'Agent with specific permissions' },
    ], {
      ignoreDuplicates: true, 
    });
  },

  async down(queryInterface, Sequelize) {
    await queryInterface.bulkDelete('roles', {
      name: ['USER', 'ADMIN', 'AGENT']
    });
  }
};
