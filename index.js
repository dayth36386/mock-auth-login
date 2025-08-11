const express = require("express");
const swaggerJsdoc = require("swagger-jsdoc");
const swaggerUi = require("swagger-ui-express");

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000;

// เก็บจำนวนพยายาม login ที่ล้มเหลว
const failedLoginAttempts = {};
const lockTime = {}; // เก็บเวลาที่ล็อก

// ---------- Swagger Config ----------
const swaggerOptions = {
  definition: {
    openapi: "3.0.0",
    info: {
      title: "Mock Login API",
      version: "1.0.0",
      description: "API สำหรับทดสอบ Login พร้อมระบบล็อกบัญชีและ error format",
    },
  },
  apis: [__filename],
};

const swaggerSpec = swaggerJsdoc(swaggerOptions);
app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(swaggerSpec));

/**
 * @swagger
 * /login:
 *   post:
 *     summary: Login user
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - password
 *             properties:
 *               email:
 *                 type: string
 *                 example: test@gmail.com
 *               password:
 *                 type: string
 *                 example: test123
 *     responses:
 *       200:
 *         description: Login successful
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                 access_token:
 *                   type: string
 *                 user:
 *                   type: object
 *                   properties:
 *                     id:
 *                       type: integer
 *                     email:
 *                       type: string
 *                     name:
 *                       type: string
 *             example:
 *               message: Login successful
 *               access_token: jwt_access_token
 *               user:
 *                 id: 123
 *                 email: user@example.com
 *                 name: User Name
 *       400:
 *         description: Bad Request - Missing fields
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: common.invalid_request
 *                 errors:
 *                   type: object
 *                   additionalProperties:
 *                     type: string
 *             example:
 *               message: common.invalid_request
 *               errors:
 *                 email: "must have required property 'email'"
 *                 password: "must have required property 'password'"
 *       401:
 *         description: Invalid password
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *             example:
 *               message: login.invalid_password
 *       404:
 *         description: Email not found
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *             example:
 *               message: login.email_not_found
 *       423:
 *         description: Account locked due to 5 incorrect attempts
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *             example:
 *               message: login.5_incorrect_password
 */

// ---------- API Login ----------
app.post("/login", (req, res) => {
  const { email, password } = req.body;

  // ตรวจสอบว่าถูกล็อกอยู่ไหม
  if (lockTime[email]) {
    const lockedAt = lockTime[email];
    if (Date.now() - lockedAt < 15 * 60 * 1000) {
      return res.status(423).json({ message: "login.5_incorrect_password" });
    } else {
      delete failedLoginAttempts[email];
      delete lockTime[email];
    }
  }

  // Validate required fields
  const errors = {};
  if (!email) errors.email = "must have required property 'email'";
  if (!password) errors.password = "must have required property 'password'";
  if (Object.keys(errors).length > 0) {
    return res.status(400).json({
      message: "common.invalid_request",
      errors,
    });
  }

  // ตรวจสอบ email/password
  if (email !== "test@gmail.com") {
    return res.status(404).json({ message: "login.email_not_found" });
  }

  if (password !== "test123") {
    failedLoginAttempts[email] = (failedLoginAttempts[email] || 0) + 1;
    if (failedLoginAttempts[email] >= 5) {
      lockTime[email] = Date.now();
      return res.status(423).json({ message: "login.5_incorrect_password" });
    }
    return res.status(401).json({ message: "login.invalid_password" });
  }

  // สำเร็จ ล้างข้อมูลพยายามผิด
  failedLoginAttempts[email] = 0;
  delete lockTime[email];

  return res.json({
    message: "Login successful",
    access_token: "jwt_access_token",
    user: {
      id: 123,
      email: "test@gmail.com",
      name: "User Name",
    },
  });
});

/**
 * @swagger
 * /unlock:
 *   post:
 *     summary: Unlock account (admin only)
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *             properties:
 *               email:
 *                 type: string
 *                 example: test@gmail.com
 *     responses:
 *       200:
 *         description: Account unlocked
 *         content:
 *           application/json:
 *             example:
 *               message: Account test@gmail.com unlocked.
 *       400:
 *         description: Missing email
 *         content:
 *           application/json:
 *             example:
 *               message: common.invalid_request
 *               errors:
 *                 email: "must have required property 'email'"
 */

// ---------- API Unlock ----------
app.post("/unlock", (req, res) => {
  const { email } = req.body;
  if (!email) {
    return res.status(400).json({
      message: "common.invalid_request",
      errors: { email: "must have required property 'email'" },
    });
  }
  delete failedLoginAttempts[email];
  delete lockTime[email];
  return res.json({ message: `Account ${email} unlocked.` });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
