// ======================= IMPORTS =======================
import bcrypt from "bcryptjs";
import cors from "cors";
import dotenv from "dotenv";
import express from "express";
import jwt from "jsonwebtoken";
import multer from "multer";
import mysql from "mysql2";
import path from "path";
dotenv.config();

// ==================== APP CONFIG =======================
const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET;

// Middleware
app.use(cors());
app.use(express.json());
app.use("/uploads", express.static("uploads"));

// =================== DATABASE CONNECTION ===============
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT,
});

db.connect((err) => {
  if (err) {
    console.error("❌ Database connection failed:", err);
    return;
  }
  console.log("✅ Connected to Railway MySQL");
});

// ================== FILE UPLOAD CONFIG =================
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, "uploads/"),
  filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname)),
});

const upload = multer({ storage });

// ================== AUTH MIDDLEWARE =====================
const authenticateToken = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "No token, access denied" });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: "Invalid token" });
    req.user = user;
    next();
  });
};

const isAdmin = (req, res, next) => {
  if (req.user.role !== "admin")
    return res.status(403).json({ message: "Admin only" });
  next();
};


app.post("/api/auth/register", async (req, res) => {
  const { username, email, password } = req.body;
  const hashed = await bcrypt.hash(password, 10);

  db.query(
    "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
    [username, email, hashed],
    (err) =>
      err
        ? res.status(400).json({ message: "User exists" })
        : res.json({ message: "Registered!" })
  );
});

app.post("/api/auth/login", (req, res) => {
  const { username, password } = req.body;

  db.query("SELECT * FROM users WHERE username=?", [username], async (err, rows) => {
    if (rows.length === 0) return res.status(400).json({ message: "User not found" });

    const user = rows[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ message: "Wrong password" });

    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: "1d" }
    );

    res.json({ token, user });
  });
});


app.get("/api/books", (req, res) => {
  db.query("SELECT * FROM books", (err, rows) =>
    err ? res.status(500).json({ message: "Error" }) : res.json(rows)
  );
});

app.post("/api/books", authenticateToken, isAdmin, upload.single("image"), (req, res) => {
  const { title, author, price, category, description, rating } = req.body;
  const image = req.file ? `/uploads/${req.file.filename}` : null;

  db.query(
    "INSERT INTO books (title,author,price,category,description,image,rating) VALUES (?,?,?,?,?,?,?)",
    [title, author, price, category, description, image, rating || 0],
    (err) => (err ? res.status(500).json({ message: "Error" }) : res.json({ message: "Added" }))
  );
});


app.post("/api/orders", authenticateToken, (req, res) => {
  const { items, totalAmount } = req.body;

  db.query(
    "INSERT INTO orders (user_id,total_amount) VALUES (?,?)",
    [req.user.id, totalAmount],
    (err, result) => {
      if (err) return res.status(500).json({ message: "Order error" });

      const orderId = result.insertId;
      const formatted = items.map((i) => [orderId, i.id, i.quantity, i.price]);

      db.query(
        "INSERT INTO order_items (order_id,book_id,quantity,price) VALUES ?",
        [formatted],
        () => res.json({ message: "Order placed", orderId })
      );
    }
  );
});


// Get single book
app.get('/api/books/:id', (req, res) => {
  db.query('SELECT * FROM books WHERE id = ?', [req.params.id], (err, results) => {
    if (err) return res.status(500).json({ message: 'Server error' });
    if (results.length === 0) return res.status(404).json({ message: 'Book not found' });
    res.json(results[0]);
  });
});

// Update book (Admin only)
app.put('/api/books/:id', authenticateToken, isAdmin, upload.single('image'), (req, res) => {
  const { title, author, price, category, description, rating } = req.body;
  const image = req.file ? `/uploads/${req.file.filename}` : req.body.image;

  db.query(
    'UPDATE books SET title=?, author=?, price=?, category=?, description=?, image=?, rating=? WHERE id=?',
    [title, author, price, category, description, image, rating, req.params.id],
    (err) => {
      if (err) return res.status(500).json({ message: 'Server error' });
      res.json({ message: 'Book updated successfully' });
    }
  );
});

// Delete book
app.delete('/api/books/:id', authenticateToken, isAdmin, (req, res) => {
  db.query('DELETE FROM books WHERE id = ?', [req.params.id], (err) => {
    if (err) return res.status(500).json({ message: 'Server error' });
    res.json({ message: 'Book deleted successfully' });
  });
});

// Get user orders
app.get('/api/orders', authenticateToken, (req, res) => {
  db.query('SELECT * FROM orders WHERE user_id = ?', [req.user.id], (err, results) => {
    if (err) return res.status(500).json({ message: 'Server error' });
    res.json(results);
  });
});

// Admin - Get all orders
app.get('/api/admin/orders', authenticateToken, isAdmin, (req, res) => {
  db.query(
    `SELECT o.*, u.username, u.email
     FROM orders o
     JOIN users u ON o.user_id = u.id
     ORDER BY o.created_at DESC`,
    (err, results) => {
      if (err) return res.status(500).json({ message: 'Server error' });
      res.json(results);
    }
  );
});

// Admin - Update order status
app.put('/api/admin/orders/:id/status', authenticateToken, isAdmin, (req, res) => {
  const { status } = req.body;

  db.query(
    'UPDATE orders SET status = ? WHERE id = ?',
    [status, req.params.id],
    (err) => {
      if (err) return res.status(500).json({ message: 'Server error' });
      res.json({ message: 'Order status updated' });
    }
  );
});

// Admin - View contact messages
app.get('/api/admin/contact-messages', authenticateToken, isAdmin, (req, res) => {
  db.query('SELECT * FROM contact_messages ORDER BY created_at DESC', (err, results) => {
    if (err) return res.status(500).json({ message: 'Server error' });
    res.json(results);
  });
});

// Admin - Delete contact message
app.delete('/api/admin/contact-messages/:id', authenticateToken, isAdmin, (req, res) => {
  db.query('DELETE FROM contact_messages WHERE id = ?', [req.params.id], (err) => {
    if (err) return res.status(500).json({ message: 'Server error' });
    res.json({ message: 'Message deleted successfully' });
  });
});



app.post("/api/contact", (req, res) => {
  const { name, email, message } = req.body;

  db.query(
    "INSERT INTO contact_messages(name,email,message) VALUES (?,?,?)",
    [name, email, message],
    (err) => (err ? res.status(500).json({ message: "Error" }) : res.json({ message: "Sent!" }))
  );
});


app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
