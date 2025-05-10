// db.js
require('dotenv').config();
const mysql = require('mysql2/promise');

const pool = mysql.createPool({
  host:     process.env.AZURE_MYSQL_HOST,
  user:     process.env.AZURE_MYSQL_USERNAME,
  password: process.env.AZURE_MYSQL_PASSWORD,
  database: process.env.AZURE_MYSQL_DBNAME,
  port:     parseInt(process.env.AZURE_MYSQL_PORT,10),
  ssl:      { rejectUnauthorized: true }
});


module.exports = pool;
