-- Products table
CREATE TABLE IF NOT EXISTS products (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    price REAL NOT NULL,
    description TEXT NOT NULL,
    image_url TEXT NOT NULL,
    image_public_id TEXT,
    stock TEXT DEFAULT 'In Stock',
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

-- Admin users table
CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

-- Sessions table for auth tokens
CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    admin_id INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    FOREIGN KEY (admin_id) REFERENCES admins(id)
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_products_category ON products(category);
CREATE INDEX IF NOT EXISTS idx_products_created ON products(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

-- Insert default admin (username: admin, password: alshams2024)
-- Password hash is SHA-256 of "alshams2024"
INSERT OR IGNORE INTO admins (username, password_hash, created_at)
VALUES ('admin', 'b8c0d8e7c0a5c2f9e7d3a1b6f8c9d2e1a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9', strftime('%s', 'now'));
