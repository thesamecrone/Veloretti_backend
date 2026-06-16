const pool = require('./db');
const bcrypt = require('bcrypt');

async function registerUser(name, email, password) {
  try {
    console.log("Attempting to register user with email:", email);
    
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const result = await pool.query(
      'INSERT INTO users (name, email, password_hash) VALUES ($1, $2, $3) RETURNING *', 
      [name, email, hashedPassword]
    );
    
    console.log("Registration successful for:", email);
    return result.rows[0];
    
  } catch (err) {
    console.error("Error in registerUser:", err.message);
    throw err; 
  }
}

module.exports = { registerUser };