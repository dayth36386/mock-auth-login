// index.js
const express = require("express");
const swaggerJsdoc = require("swagger-jsdoc");
const swaggerUi = require("swagger-ui-express");

const app = express();
app.use(express.json());

const failedLoginAttempts = {};

const options = {
  definition: {
    openapi: "3.0.0",
    info: {
      title: "Mock Login API",
      version: "1.0.0",
      description: "A simple mock login API with lockout feature",
    },
  },
  apis: ["./index.js"], // ชี้ไปที่ไฟล์นี้สำหรับอ่าน swagger doc
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
 *         description: Bad Request - Missing required fields
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

  // เช็ค required fields
  const errors = {};
  if (!email) errors.email = ["email_is_required"];
  if (!password) errors.password = ["password_is_required"];
  if (Object.keys(errors).length > 0) {
    return res.status(400).json({
      message: "invalid_request",
      errors,
    });
  }

  // เช็ค email ถูกต้องหรือไม่
  if (email !== "test@gmail.com") {
    return res.status(404).json({
      message: "login.email_not_found",
    });
  }

  // เช็คล็อกถ้า login ผิดเกิน 5 ครั้ง
  if (failedLoginAttempts[email] && failedLoginAttempts[email] >= 5) {
    return res.status(423).json({
      message: "login.5_incorrect_password",
    });
  }

  // เช็ค password
  if (password === "test123") {
    failedLoginAttempts[email] = 0; // reset count
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
    if (!failedLoginAttempts[email]) {
      failedLoginAttempts[email] = 1;
    } else {
      failedLoginAttempts[email]++;
    }
    return res.status(401).json({
      message: "login.invalid_password",
    });
  }
});

const PORT = 666;
app.listen(PORT, () => {
  console.log(`Mock API running on http://localhost:${PORT}`);
  console.log(`Swagger docs at http://localhost:${PORT}/api-docs`);
});
