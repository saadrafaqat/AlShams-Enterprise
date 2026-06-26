// ===================================
// AL SHAMS ENTERPRISES - BACKEND API
// Cloudflare Workers + D1 + Cloudinary
// ===================================

// CORS Headers
const corsHeaders = (origin = '*') => ({
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400',
});

// JSON Response Helper
const json = (data, status = 200, origin = '*') => {
    return new Response(JSON.stringify(data), {
        status,
        headers: {
            'Content-Type': 'application/json',
            ...corsHeaders(origin),
        },
    });
};

// Error Response Helper
const error = (message, status = 400, origin = '*') => {
    return json({ success: false, error: message }, status, origin);
};

// ===================================
// CRYPTO HELPERS
// ===================================

async function hashPassword(password) {
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

function generateToken() {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return Array.from(array).map(b => b.toString(16).padStart(2, '0')).join('');
}

function generateId(prefix = 'prod') {
    return `${prefix}_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
}

// ===================================
// AUTH MIDDLEWARE
// ===================================

async function verifyAuth(request, env) {
    const authHeader = request.headers.get('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return null;
    }

    const token = authHeader.substring(7);
    const now = Math.floor(Date.now() / 1000);

    const session = await env.DB.prepare(
        'SELECT * FROM sessions WHERE token = ? AND expires_at > ?'
    ).bind(token, now).first();

    if (!session) return null;

    const admin = await env.DB.prepare(
        'SELECT id, username FROM admins WHERE id = ?'
    ).bind(session.admin_id).first();

    return admin;
}

// ===================================
// CLOUDINARY UPLOAD
// ===================================

async function uploadToCloudinary(base64Image, env) {
    const cloudName = env.CLOUDINARY_CLOUD_NAME;
    const apiKey = env.CLOUDINARY_API_KEY;
    const apiSecret = env.CLOUDINARY_API_SECRET;

    if (!cloudName || !apiKey || !apiSecret) {
        throw new Error('Cloudinary credentials not configured');
    }

    const timestamp = Math.floor(Date.now() / 1000);
    const folder = 'alshams-products';

    // Create signature
    const paramsToSign = `folder=${folder}&timestamp=${timestamp}${apiSecret}`;
    const encoder = new TextEncoder();
    const data = encoder.encode(paramsToSign);
    const hashBuffer = await crypto.subtle.digest('SHA-1', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const signature = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

    // Prepare form data
    const formData = new FormData();
    formData.append('file', base64Image);
    formData.append('api_key', apiKey);
    formData.append('timestamp', timestamp.toString());
    formData.append('folder', folder);
    formData.append('signature', signature);

    const response = await fetch(
        `https://api.cloudinary.com/v1_1/${cloudName}/image/upload`,
        {
            method: 'POST',
            body: formData,
        }
    );

    if (!response.ok) {
        const errText = await response.text();
        throw new Error(`Cloudinary upload failed: ${errText}`);
    }

    const result = await response.json();
    return {
        url: result.secure_url,
        publicId: result.public_id,
    };
}

async function deleteFromCloudinary(publicId, env) {
    const cloudName = env.CLOUDINARY_CLOUD_NAME;
    const apiKey = env.CLOUDINARY_API_KEY;
    const apiSecret = env.CLOUDINARY_API_SECRET;

    const timestamp = Math.floor(Date.now() / 1000);
    const paramsToSign = `public_id=${publicId}&timestamp=${timestamp}${apiSecret}`;

    const encoder = new TextEncoder();
    const data = encoder.encode(paramsToSign);
    const hashBuffer = await crypto.subtle.digest('SHA-1', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const signature = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

    const formData = new FormData();
    formData.append('public_id', publicId);
    formData.append('api_key', apiKey);
    formData.append('timestamp', timestamp.toString());
    formData.append('signature', signature);

    try {
        await fetch(
            `https://api.cloudinary.com/v1_1/${cloudName}/image/destroy`,
            { method: 'POST', body: formData }
        );
    } catch (e) {
        console.error('Cloudinary delete failed:', e);
    }
}

// ===================================
// ROUTE HANDLERS
// ===================================

// POST /api/auth/login
async function handleLogin(request, env, origin) {
    try {
        const { username, password } = await request.json();

        if (!username || !password) {
            return error('Username and password required', 400, origin);
        }

        const passwordHash = await hashPassword(password);

        const admin = await env.DB.prepare(
            'SELECT * FROM admins WHERE username = ? AND password_hash = ?'
        ).bind(username, passwordHash).first();

        if (!admin) {
            return error('Invalid credentials', 401, origin);
        }

        // Create session (7 days)
        const token = generateToken();
        const now = Math.floor(Date.now() / 1000);
        const expiresAt = now + (7 * 24 * 60 * 60);

        await env.DB.prepare(
            'INSERT INTO sessions (token, admin_id, expires_at, created_at) VALUES (?, ?, ?, ?)'
        ).bind(token, admin.id, expiresAt, now).run();

        // Cleanup old sessions
        await env.DB.prepare(
            'DELETE FROM sessions WHERE expires_at < ?'
        ).bind(now).run();

        return json({
            success: true,
            token,
            user: { id: admin.id, username: admin.username },
        }, 200, origin);
    } catch (e) {
        return error(e.message, 500, origin);
    }
}

// POST /api/auth/logout
async function handleLogout(request, env, origin) {
    try {
        const authHeader = request.headers.get('Authorization');
        if (authHeader && authHeader.startsWith('Bearer ')) {
            const token = authHeader.substring(7);
            await env.DB.prepare('DELETE FROM sessions WHERE token = ?').bind(token).run();
        }
        return json({ success: true }, 200, origin);
    } catch (e) {
        return error(e.message, 500, origin);
    }
}

// GET /api/auth/verify
async function handleVerify(request, env, origin) {
    const admin = await verifyAuth(request, env);
    if (!admin) return error('Unauthorized', 401, origin);
    return json({ success: true, user: admin }, 200, origin);
}

// POST /api/auth/change-password
async function handleChangePassword(request, env, origin) {
    const admin = await verifyAuth(request, env);
    if (!admin) return error('Unauthorized', 401, origin);

    try {
        const { currentPassword, newPassword } = await request.json();

        if (!currentPassword || !newPassword) {
            return error('Current and new password required', 400, origin);
        }

        if (newPassword.length < 6) {
            return error('Password must be at least 6 characters', 400, origin);
        }

        const currentHash = await hashPassword(currentPassword);
        const existingAdmin = await env.DB.prepare(
            'SELECT * FROM admins WHERE id = ? AND password_hash = ?'
        ).bind(admin.id, currentHash).first();

        if (!existingAdmin) {
            return error('Current password is incorrect', 401, origin);
        }

        const newHash = await hashPassword(newPassword);
        await env.DB.prepare(
            'UPDATE admins SET password_hash = ? WHERE id = ?'
        ).bind(newHash, admin.id).run();

        return json({ success: true, message: 'Password updated' }, 200, origin);
    } catch (e) {
        return error(e.message, 500, origin);
    }
}

// GET /api/products (Public)
async function handleGetProducts(request, env, origin) {
    try {
        const url = new URL(request.url);
        const category = url.searchParams.get('category');
        const search = url.searchParams.get('search');
        const limit = parseInt(url.searchParams.get('limit') || '100');

        let query = 'SELECT * FROM products WHERE 1=1';
        const params = [];

        if (category) {
            query += ' AND category = ?';
            params.push(category);
        }

        if (search) {
            query += ' AND (name LIKE ? OR description LIKE ?)';
            params.push(`%${search}%`, `%${search}%`);
        }

        query += ' ORDER BY created_at DESC LIMIT ?';
        params.push(limit);

        const result = await env.DB.prepare(query).bind(...params).all();

        return json({
            success: true,
            products: result.results || [],
            count: result.results?.length || 0,
        }, 200, origin);
    } catch (e) {
        return error(e.message, 500, origin);
    }
}

// GET /api/products/:id (Public)
async function handleGetProduct(id, env, origin) {
    try {
        const product = await env.DB.prepare(
            'SELECT * FROM products WHERE id = ?'
        ).bind(id).first();

        if (!product) return error('Product not found', 404, origin);

        return json({ success: true, product }, 200, origin);
    } catch (e) {
        return error(e.message, 500, origin);
    }
}

// POST /api/products (Admin)
async function handleCreateProduct(request, env, origin) {
    const admin = await verifyAuth(request, env);
    if (!admin) return error('Unauthorized', 401, origin);

    try {
        const data = await request.json();
        const { name, category, price, description, image, stock } = data;

        if (!name || !category || !price || !description || !image) {
            return error('All fields are required', 400, origin);
        }

        // Upload image to Cloudinary if it's base64
        let imageUrl = image;
        let imagePublicId = null;

        if (image.startsWith('data:image')) {
            const uploaded = await uploadToCloudinary(image, env);
            imageUrl = uploaded.url;
            imagePublicId = uploaded.publicId;
        }

        const id = generateId('prod');
        const now = Math.floor(Date.now() / 1000);

        await env.DB.prepare(
            `INSERT INTO products (id, name, category, price, description, image_url, image_public_id, stock, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        ).bind(
            id, name, category, parseFloat(price), description,
            imageUrl, imagePublicId, stock || 'In Stock', now, now
        ).run();

        const product = await env.DB.prepare(
            'SELECT * FROM products WHERE id = ?'
        ).bind(id).first();

        return json({ success: true, product }, 201, origin);
    } catch (e) {
        return error(e.message, 500, origin);
    }
}

// PUT /api/products/:id (Admin)
async function handleUpdateProduct(id, request, env, origin) {
    const admin = await verifyAuth(request, env);
    if (!admin) return error('Unauthorized', 401, origin);

    try {
        const data = await request.json();
        const { name, category, price, description, image, stock } = data;

        const existing = await env.DB.prepare(
            'SELECT * FROM products WHERE id = ?'
        ).bind(id).first();

        if (!existing) return error('Product not found', 404, origin);

        let imageUrl = existing.image_url;
        let imagePublicId = existing.image_public_id;

        // If new image uploaded (base64), upload to Cloudinary
        if (image && image.startsWith('data:image')) {
            // Delete old image from Cloudinary
            if (existing.image_public_id) {
                await deleteFromCloudinary(existing.image_public_id, env);
            }
            const uploaded = await uploadToCloudinary(image, env);
            imageUrl = uploaded.url;
            imagePublicId = uploaded.publicId;
        } else if (image && image !== existing.image_url) {
            // External URL provided
            imageUrl = image;
            imagePublicId = null;
        }

        const now = Math.floor(Date.now() / 1000);

        await env.DB.prepare(
            `UPDATE products SET name = ?, category = ?, price = ?, description = ?,
             image_url = ?, image_public_id = ?, stock = ?, updated_at = ?
             WHERE id = ?`
        ).bind(
            name || existing.name,
            category || existing.category,
            price ? parseFloat(price) : existing.price,
            description || existing.description,
            imageUrl,
            imagePublicId,
            stock || existing.stock,
            now,
            id
        ).run();

        const updated = await env.DB.prepare(
            'SELECT * FROM products WHERE id = ?'
        ).bind(id).first();

        return json({ success: true, product: updated }, 200, origin);
    } catch (e) {
        return error(e.message, 500, origin);
    }
}

// DELETE /api/products/:id (Admin)
async function handleDeleteProduct(id, request, env, origin) {
    const admin = await verifyAuth(request, env);
    if (!admin) return error('Unauthorized', 401, origin);

    try {
        const product = await env.DB.prepare(
            'SELECT * FROM products WHERE id = ?'
        ).bind(id).first();

        if (!product) return error('Product not found', 404, origin);

        // Delete from Cloudinary
        if (product.image_public_id) {
            await deleteFromCloudinary(product.image_public_id, env);
        }

        await env.DB.prepare('DELETE FROM products WHERE id = ?').bind(id).run();

        return json({ success: true, message: 'Product deleted' }, 200, origin);
    } catch (e) {
        return error(e.message, 500, origin);
    }
}

// GET /api/stats (Admin)
async function handleStats(request, env, origin) {
    const admin = await verifyAuth(request, env);
    if (!admin) return error('Unauthorized', 401, origin);

    try {
        const total = await env.DB.prepare('SELECT COUNT(*) as count FROM products').first();
        const tools = await env.DB.prepare(
            'SELECT COUNT(*) as count FROM products WHERE category = ?'
        ).bind('Specialized Tools').first();
        const hardware = await env.DB.prepare(
            'SELECT COUNT(*) as count FROM products WHERE category = ?'
        ).bind('Industrial Hardware').first();
        const supplies = await env.DB.prepare(
            'SELECT COUNT(*) as count FROM products WHERE category = ?'
        ).bind('Essential Supplies').first();

        return json({
            success: true,
            stats: {
                total: total.count,
                tools: tools.count,
                hardware: hardware.count,
                supplies: supplies.count,
            },
        }, 200, origin);
    } catch (e) {
        return error(e.message, 500, origin);
    }
}

// ===================================
// MAIN ROUTER
// ===================================

export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        const path = url.pathname;
        const method = request.method;
        const origin = env.CORS_ORIGIN || '*';

        // Handle CORS preflight
        if (method === 'OPTIONS') {
            return new Response(null, { status: 204, headers: corsHeaders(origin) });
        }

        try {
            // Auth routes
            if (path === '/api/auth/login' && method === 'POST') {
                return await handleLogin(request, env, origin);
            }
            if (path === '/api/auth/logout' && method === 'POST') {
                return await handleLogout(request, env, origin);
            }
            if (path === '/api/auth/verify' && method === 'GET') {
                return await handleVerify(request, env, origin);
            }
            if (path === '/api/auth/change-password' && method === 'POST') {
                return await handleChangePassword(request, env, origin);
            }

            // Stats
            if (path === '/api/stats' && method === 'GET') {
                return await handleStats(request, env, origin);
            }

            // Products
            if (path === '/api/products' && method === 'GET') {
                return await handleGetProducts(request, env, origin);
            }
            if (path === '/api/products' && method === 'POST') {
                return await handleCreateProduct(request, env, origin);
            }

            // Product by ID
            const productMatch = path.match(/^\/api\/products\/([^\/]+)$/);
            if (productMatch) {
                const id = productMatch[1];
                if (method === 'GET') return await handleGetProduct(id, env, origin);
                if (method === 'PUT') return await handleUpdateProduct(id, request, env, origin);
                if (method === 'DELETE') return await handleDeleteProduct(id, request, env, origin);
            }

            // Health check
            if (path === '/' || path === '/api') {
                return json({
                    success: true,
                    message: 'Al Shams Enterprises API',
                    version: '1.0.0',
                }, 200, origin);
            }

            return error('Endpoint not found', 404, origin);
        } catch (e) {
            console.error('Worker error:', e);
            return error('Internal server error: ' + e.message, 500, origin);
        }
    },
};
