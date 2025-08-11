// index.js
const express = require("express");
const swaggerJsdoc = require("swagger-jsdoc");
const swaggerUi = require("swagger-ui-express");

const app = express();
app.use(express.json());

// เก็บสถานะล็อกและเวลาล็อกใน RAM
const failedLoginAttempts = {};
const lockTime = {};

const options = {
  definition: {
    openapi: "3.0.0",
    info: {
      title: "Mock Login API",
      version: "1.0.0",
      description: "Mock Login API with lockout feature",
    },
  },
  apis: ["./index.js"],
};

const specs = swaggerJsdoc(options);
app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(specs));

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
 *                 errors:
 *                   type: object
 *                   properties:
 *                     email:
 *                       type: array
 *                       items:
 *                         type: string
 *                     password:
 *                       type: array
 *                       items:
 *                         type: string
 *             example:
 *               message: invalid_request
 *               errors:
 *                 email: ["email_is_required"]
 *                 password: ["password_is_required"]
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
app.post("/login", (req, res) => {
  const { email, password } = req.body;

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

  // Auto unlock after 15 minutes
  if (lockTime[email]) {
    const lockedAt = lockTime[email];
    const now = Date.now();
    if (now - lockedAt > 15 * 60 * 1000) {
      // 15 mins
      delete failedLoginAttempts[email];
      delete lockTime[email];
    }
  }

  // Check if locked
  if (failedLoginAttempts[email] && failedLoginAttempts[email] >= 5) {
    return res.status(423).json({
      message: "login.5_incorrect_password",
    });
  }

  // Check email
  if (email !== "test@gmail.com") {
    return res.status(404).json({
      message: "login.email_not_found",
    });
  }

  // Check password
  if (password === "test123") {
    failedLoginAttempts[email] = 0;
    delete lockTime[email];
    return res.status(200).json({
      message: "Login successful",
      access_token: "jwt_access_token",
      user: {
        id: 123,
        email: "user@example.com",
        name: "User Name",
      },
    });
  } else {
    failedLoginAttempts[email] = (failedLoginAttempts[email] || 0) + 1;
    if (failedLoginAttempts[email] >= 5) {
      lockTime[email] = Date.now();
    }
    return res.status(401).json({
      message: "login.invalid_password",
    });
  }
});

/**
 * @swagger
 * /unlock:
 *   post:
 *     summary: Unlock user account (admin or user request)
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
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *             example:
 *               message: Account test@gmail.com unlocked.
 *       400:
 *         description: Missing email
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *             example:
 *               message: email_is_required
 */
app.post("/unlock", (req, res) => {
  const { email } = req.body;
  if (!email) {
    return res.status(400).json({ message: "email_is_required" });
  }
  delete failedLoginAttempts[email];
  delete lockTime[email];
  return res.json({ message: `Account ${email} unlocked.` });
});

const PORT = process.env.PORT || 666;
app.listen(PORT, () => {
  console.log(`Mock API running on http://localhost:${PORT}`);
  console.log(`Swagger docs at http://localhost:${PORT}/api-docs`);
});
