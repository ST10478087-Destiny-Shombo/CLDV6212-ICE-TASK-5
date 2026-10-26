const express = require('express');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

const JWT_SECRET = 'super-secret-key-change-me';
const NOTES_URL = 'http://localhost:3001';

/* ---------- IN-MEMORY USER STORE ----------
 * The User entity carries every field the microservices need:
 *  id, firstName, lastName, email, passwordHash, role, createdAt
 */
const users = [];
let nextUserId = 1;

/* ---------- AUTH ROUTES ---------- */
app.post('/auth/register', async (req, res) => {
    const { firstName, lastName, email, password, role } = req.body;
    if (!firstName || !lastName || !email || !password) {
        return res.status(400).json({ error: 'firstName, lastName, email, password are required' });
    }
    if (users.find(u => u.email === email)) {
        return res.status(409).json({ error: 'Email already registered' });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const user = {
        id: String(nextUserId++),
        firstName,
        lastName,
        email,
        passwordHash,
        role: role === 'admin' ? 'admin' : 'user', // default role
        createdAt: new Date().toISOString(),
    };
    users.push(user);
    res.status(201).json(sanitize(user));
});

app.post('/auth/login', async (req, res) => {
    const { email, password } = req.body;
    const user = users.find(u => u.email === email);
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

    // Only safe fields go inside the token
    const token = jwt.sign(
        { sub: user.id, email: user.email, role: user.role, firstName: user.firstName, lastName: user.lastName },
        JWT_SECRET,
        { expiresIn: '1h' }
    );
    res.json({ token, user: sanitize(user) });
});

/* ---------- AUTH MIDDLEWARE ---------- */
function authenticate(req, res, next) {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'Missing token' });

    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch {
        return res.status(401).json({ error: 'Invalid or expired token' });
    }
}

/* ---------- ROLE-BASED AUTHORIZATION ---------- */
function authorize(...roles) {
    return (req, res, next) => {
        if (!req.user || !roles.includes(req.user.role)) {
            return res.status(403).json({ error: 'Forbidden' });
        }
        next();
    };
}

/* ---------- PROXY TO NOTES SERVICE ---------- */
// The gateway injects trusted user info as headers
app.use('/notes', authenticate, async (req, res) => {
    try {
        const response = await axios({
            method: req.method,
            url: `${NOTES_URL}${req.originalUrl}`,
            data: req.body,
            headers: {
                'x-user-id': req.user.sub,
                'x-user-email': req.user.email,
                'x-user-role': req.user.role,
            },
        });
        res.status(response.status).json(response.data);
    } catch (err) {
        const status = err.response?.status || 500;
        res.status(status).json(err.response?.data || { error: 'Notes service unavailable' });
    }
});

/* ---------- ADMIN EXAMPLE ---------- */
app.get('/admin/users', authenticate, authorize('admin'), (req, res) => {
    res.json(users.map(sanitize));
});

function sanitize({ passwordHash, ...rest }) { return rest; }

app.listen(3000, () => console.log('API Gateway on http://localhost:3000'));