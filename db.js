// db.js  — light-weight wrapper around mysql2/promise
require('dotenv').config();
const mysql = require('mysql2/promise');

const pool = mysql.createPool({
  host:     process.env.MYSQL_HOST,
  user:     process.env.MYSQL_USER,
  password: process.env.MYSQL_PASSWORD,
  database: process.env.MYSQL_DB,
  waitForConnections: true,
  connectionLimit: 4,
  ssl: {                     // ← you got TLS working already
    rejectUnauthorized: true // use the Baltimore root if you like
  }
});

module.exports = pool;
