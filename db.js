// db.js
const mysql = require('mysql2/promise');

// debug log so you can verify the settings in Log Stream:
console.log('▶️  DB connect →', {
  host:     process.env.MYSQL_HOST,
  user:     process.env.MYSQL_USER,
  database: process.env.MYSQL_DB,
  port:     process.env.MYSQL_PORT
});

const pool = mysql.createPool({
  host:     process.env.MYSQL_HOST,
  user:     process.env.MYSQL_USER,
  password: process.env.MYSQL_PASSWORD,
  database: process.env.MYSQL_DB,
  port:     Number(process.env.MYSQL_PORT) || 3306,
  ssl:      { rejectUnauthorized: false }
});

module.exports = pool;
