const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const path = require("path");
const { MongoClient } = require("mongodb");
const bodyParser = require("body-parser");
const cors = require("cors");
const { ObjectId } = require("mongodb");



const app = express();
const port = 3000;
const secretKey = "your_secret_key";

app.use(bodyParser.json());
app.use(cors());
app.use(express.static("public"));

const dbName = "employees_data";
const mongoURI = "mongodb+srv://Alikhan:ali24815@cluster0.abpuz.mongodb.net/employees_data";

let db;

async function connectDB() {
    try {
        const client = new MongoClient(mongoURI);
        await client.connect();
        console.log("✅ Connected to MongoDB Atlas");
        db = client.db(dbName);
        app.listen(port, () => console.log(`🚀 Server running on http://localhost:${port}`));
    } catch (err) {
        console.error("❌ Failed to connect to MongoDB:", err);
        process.exit(1);
    }
}
connectDB();

function getDB() {
    if (!db) throw new Error("❌ Database not initialized.");
    return db;
}

// Middleware for authentication
function authenticateToken(req, res, next) {
    const token = req.headers["authorization"];
    if (!token) return res.status(403).json({ message: "Access denied." });

    jwt.verify(token.split(" ")[1], secretKey, (err, user) => {
        if (err) return res.status(403).json({ message: "Invalid token." });
        req.user = user;
        next();
    });
}

// Serve registration page by default
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "public", "register.html")));

// Registration route
app.post("/register", async (req, res) => {
    try {
        const { name, email, password, status } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);

        await getDB().collection("users").insertOne({ name, email, password: hashedPassword, status });
        res.status(201).json({ message: "User registered successfully" });
    } catch (err) {
        res.status(500).json({ error: "Error registering user", details: err.message });
    }
});

// Login route
app.post("/login", async (req, res) => {
    try {
        const { email, password } = req.body;
        console.log("🔹 Получен запрос на вход:", req.body);

        // Находим пользователя в базе данных
        const user = await getDB().collection("users").findOne({ email });
        if (!user) {
            console.log("❌ Пользователь не найден");
            return res.status(400).json({ message: "Invalid email or password" });
        }

        // Проверяем пароль
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            console.log("❌ Неверный пароль");
            return res.status(400).json({ message: "Invalid email or password" });
        }

        // Генерируем настоящий JWT-токен
        const token = jwt.sign(
            { id: user._id, email: user.email, role: user.status }, 
            secretKey,
            { expiresIn: "1h" }
        );

        console.log("✅ Успешный вход:", user);
        res.json({ message: "Login successful", token, status: user.status });

    } catch (err) {
        console.error("⚠️ Ошибка при входе:", err);
        res.status(500).json({ error: "Error during login", details: err.message });
    }
});


// Protected route for Employee Management (Admin Only)
app.get("/admin", authenticateToken, (req, res) => {
    if (req.user.status !== "Admin") return res.status(403).json({ message: "Access denied." });
    res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Protected route for Users Info (User Only)
app.get("/users_info", authenticateToken, (req, res) => {
    if (req.user.status !== "User") return res.status(403).json({ message: "Access denied." });
    res.sendFile(path.join(__dirname, "public", "users_info.html"));
});


// Middleware для проверки роли администратора
function authenticateAdmin(req, res, next) {
    const authHeader = req.headers["authorization"];
    if (!authHeader?.startsWith("Bearer ")) {
        return res.status(403).json({ message: "Access denied. Token missing or invalid." });
    }

    const token = authHeader.split(" ")[1];
    jwt.verify(token, secretKey, async (err, user) => {
        if (err) return res.status(403).json({ message: "Invalid token." });

        const userData = await getDB().collection("users").findOne({ email: user.email });
        if (!userData) return res.status(404).json({ message: "User not found." });

        const userStatus = userData.status?.trim().toLowerCase();
        if (userStatus !== "admin") {
            return res.status(403).json({ message: "Admin access required." });
        }

        req.user = userData;
        next();
    });
}

// 🟢 Create (POST) - Добавить нового сотрудника (только админ)
app.post("/employees", authenticateAdmin, async (req, res) => {
    try {
        const newEmployee = req.body;
        const result = await getDB().collection("employees").insertOne(newEmployee);
        res.status(201).json({ message: "Employee added successfully", employee: result });
    } catch (err) {
        res.status(500).json({ error: "Error adding employee", details: err.message });
    }
});

// 🔵 Read (GET) - Получить сотрудников (доступно всем, но админ видит всех)
app.get("/employees", async (req, res) => {
    try {
        const { sortField = "name", sortOrder = "asc", search = "" } = req.query;
        const sort = { [sortField]: sortOrder === "asc" ? 1 : -1 };
        const query = search ? { name: new RegExp(search, "i") } : {};

        const employees = await getDB().collection("employees").find(query).sort(sort).toArray();
        res.status(200).json(employees);
    } catch (err) {
        res.status(500).json({ error: "Error fetching employees", details: err.message });
    }
});

// 🟡 Update (PUT) - Обновить информацию о сотруднике (только админ)
app.put("/employees/:id", authenticateAdmin, async (req, res) => {
    try {
        const id = req.params.id;
        const updatedData = req.body;

        console.log(`🔄 Попытка обновить сотрудника с ID: ${id}`);
        console.log("📦 Данные для обновления:", updatedData);

        const result = await getDB().collection("employees").updateOne(
            { _id: new ObjectId(id) },
            { $set: updatedData }
        );

        if (result.matchedCount === 0) {
            console.log("⚠️ Сотрудник не найден");
            return res.status(404).json({ message: "Employee not found" });
        }
        console.log("✅ Сотрудник успешно обновлен");
        res.status(200).json({ message: "Employee updated successfully" });

    } catch (err) {
        console.error("🚨 Ошибка обновления сотрудника:", err);
        res.status(500).json({ error: "Database error", details: err.message });
    }
});

// 🔴 Delete (DELETE) - Удалить сотрудника (только админ)
app.delete("/employees/:id", authenticateAdmin, async (req, res) => {
    try {
        const id = req.params.id;
        const result = await getDB().collection("employees").deleteOne({ _id: new ObjectId(id) });

        if (result.deletedCount === 0) {
            return res.status(404).json({ message: "Employee not found" });
        }
        res.status(200).json({ message: "Employee deleted successfully" });
    } catch (err) {
        res.status(500).json({ error: "Error deleting employee", details: err.message });
    }
});

