const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const app = express();
const PORT = 3000;
const JWT_SECRET = 'supersecretkey'; // temporary hardcoded secret

app.use(cors());
app.use(express.json());

// temporary "database"
const users = [];

// health check route
app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

// REGISTER route
app.post('/register', async (req, res) => {
  const { name, email, password } = req.body;

  // 1. basic validation
  if (!name || !email || !password) {
    return res
      .status(400)
      .json({ message: 'name, email, and password are required' });
  }

  // 2. check if email already exists
  const existing = users.find((u) => u.email === email);
  if (existing) {
    return res.status(409).json({ message: 'email already registered' });
  }

  // 3. hash the password
  const hashed = await bcrypt.hash(password, 10);

  // 4. create user object with hashed password
  const newUser = {
    id: users.length + 1,
    name,
    email,
    password: hashed, // store hash, not plain password
    createdAt: new Date().toISOString(),
  };

  users.push(newUser);

  // 5. return user info (without password)
  res.status(201).json({
    id: newUser.id,
    name: newUser.name,
    email: newUser.email,
    createdAt: newUser.createdAt,
  });
});

// LOGIN route
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res
      .status(400)
      .json({ message: 'email and password are required' });
  }

  const user = users.find((u) => u.email === email);
  if (!user) {
    return res.status(401).json({ message: 'invalid email or password' });
  }

  // compare plain password with stored hash
  const match = await bcrypt.compare(password, user.password);
  if (!match) {
    return res.status(401).json({ message: 'invalid email or password' });
  }

  // create JWT token
  const token = jwt.sign(
    { userId: user.id, email: user.email },
    JWT_SECRET,
    { expiresIn: '1h' }
  );

  res.json({
    message: 'login successful',
    token,
  });
});

// PROFILE route (requires JWT)
app.get('/profile', (req, res) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res
      .status(401)
      .json({ message: 'missing or invalid authorization header' });
  }

  const token = authHeader.split(' ')[1];

  try {
    const payload = jwt.verify(token, JWT_SECRET); // { userId, email }
    const user = users.find((u) => u.id === payload.userId);

    if (!user) {
      return res.status(404).json({ message: 'user not found' });
    }

    res.json({
      id: user.id,
      name: user.name,
      email: user.email,
      createdAt: user.createdAt,
    });
  } catch (err) {
    return res.status(401).json({ message: 'invalid or expired token' });
  }
});


app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
Add backend index.js
