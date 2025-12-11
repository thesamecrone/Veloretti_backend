const pool = require('./db');

async function registerUser(name, email, passwordHash) {
    try {
        const result = await pool.query(
            'INSERT INTO users (name, email, password_hash) VALUES ($1, $2, $3) RETURNING *',
            [name, email, passwordHash]
        );
        return result.rows[0];
    } catch (err) {
        throw err;
    }
}

module.exports = { registerUser };

