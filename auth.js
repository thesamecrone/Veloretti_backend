const pool = require('./db');
const bcrypt = require('bcrypt');

async function registerUser(email, password) {
  try {
    console.log("Attempting to register user with email:", email);
    
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const result = await pool.query(
      'INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING *', 
      [email, hashedPassword]
    );
    
    console.log("Registration successful for:", email);
    return result.rows[0];
    
  } catch (err) {
    console.error("Error in registerUser:", err.message);
    console.error("Full error object:", err);
    throw err; 
  }
}

module.exports = { registerUser };