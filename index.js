const express = require("express");
const cors = require("cors");
const swaggerJsdoc = require("swagger-jsdoc");
const swaggerUi = require("swagger-ui-express");

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 4000;

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
      description: "API Mock",
    },
  },
  apis: [__filename],
};

const swaggerSpec = swaggerJsdoc(swaggerOptions);

// ฟังก์ชันแยก slug จาก hostname
function extractTenantSlug(hostname) {
  if (!hostname) return null;

  const parts = hostname.split(".");
  if (parts.length >= 2) {
    return parts[0]; // 'tenant1.localhost' => 'tenant1'
  }

  return null;
}

// Middleware: ดึง slug ใส่ใน req
app.use((req, res, next) => {
  const hostname = req.hostname; // เช่น tenant1.localhost
  const slug = extractTenantSlug(hostname);

  console.log("Hostname:", hostname);
  console.log("Tenant Slug:", slug);

  req.tenantSlug = slug;
  next();
});

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
app.post("/sso", (req, res) => {
  const { provider, token } = req.body;

  // ไม่มีตรวจจริง แค่ตอบ 200 ทุกกรณี
  return res.status(200).json({
    message: "login.success",
    access_token: "jwt_access_token",
    user: {
      id: 123,
      email: "user@example.com",
      name: "User Name",
    },
  });
});

app.post("/api/forgot-password", (req, res) => {
  console.log(req.body);

  const { email } = req.body;
  console.log(email);
  const mockEmail = [
    "test@gmail.com",
    "testuser01@example.com",
    "dummy.acc02@mailinator.com",
    "john.doe93@testmail.com",
    "qa.fake03@mockmail.net",
    "sample_user04@fakemail.org",
    "test.email05@tempmail.dev",
    "random.tester06@devnull.com",
    "emailtest07@trymail.io",
    "mockup08@testingmail.com",
    "fakemail09@nowhere.net",
  ];

  if (email == "") {
    return res.status(400).json({
      message: "common.invalid_request",
      error: { email: ["common.email_required"] },
    });
  }

  const findEmail = mockEmail.find((item) => item === email);
  if (findEmail) {
    return res.status(200).json({
      message: "forgot_password.email_sent",
    });
  }
  if (!findEmail) {
    return res.status(404).json({
      message: "forgot_password.email_not_found",
    });
  }
  return res.status(500).json({
    message: "common.internal_server_error",
  });
});

app.get("/api/tenant", (req, res) => {
  const tenantSlug = req.tenantSlug;
  const token = req.headers["authorization"];
  // if (!token) {
  //   res.status(401).json({
  //     error: 'Authentication Error',
  //     message: 'Authorization token is required',
  //   })
  // }
  if (!tenantSlug) {
    res.status(400).json({
      message: "common.invalid_request",
    });
  }
  const mockTenantConfigs = [
    {
      tenant: {
        id: "uuid-tenant-1",
        slug: "testtenant",
        name: "Test Tenant",
        configKeys: [
          "primary_color",
          "secondary_color",
          "logo_url",
          "login.microsoft",
          "login.google",
        ],
        createdAt: "2025-07-31T09:00:00.000Z",
        updatedAt: "2025-07-31T09:00:00.000Z",
      },
      locales: [
        {
          id: "uuid-locale-1",
          tenantId: "uuid-tenant-1",
          locale: "en",
          i18nConfig: {
            login: {
              google: "Sign in with Google",
              microsoft: "Sign in with Microsoft",
              invalid_password:
                "Incorrect password or Email Please verify and try again",
              email_not_found:
                "Email not found in the system Please double-check or contact your system administrator. {Data config}",
              "5_incorrect_password":
                "You have entered the wrong password 5 times The system has temporarily locked your account. Please contact the administrator to unlock it. {Data config}",
            },
          },
          isDefault: true,
          enabled: true,
          createdAt: "2025-07-31T09:00:00.000Z",
          updatedAt: "2025-07-31T09:00:00.000Z",
        },
        {
          id: "uuid-locale-2",
          tenantId: "uuid-tenant-1",
          locale: "th",
          i18nConfig: {
            login: {
              google: "เข้าสู่ระบบด้วย Google",
              microsoft: "เข้าสู่ระบบด้วย Microsoft",
              invalid_password: "รหัสผ่านไม่ถูกต้อง กรุณาตรวจสอบอีกครั้ง",
              email_not_found:
                "ไม่พบ Email นี้ในระบบ กรุณาตรวจสอบอีกครั้ง หรือติดต่อผู้ดูแลระบบ",
              "5_incorrect_password":
                "คุณใส่รหัสผ่านผิดติดต่อกัน 5 ครั้ง ระบบได้ทำการล็อคบัญชีชั่วคราว กรุณาติดต่อผู้ดูแลระบบเพื่อปลดล็อคบัญชี",
            },
          },
          isDefault: false,
          enabled: true,
          createdAt: "2025-07-31T09:00:00.000Z",
          updatedAt: "2025-07-31T09:00:00.000Z",
        },
      ],
      configs: {
        "login.microsoft": {
          id: "uuid-cfgv-3",
          tenantId: "uuid-tenant-1",
          locale: "th",
          configKey: "login.microsoft",
          configValue: "เข้าสู่ระบบด้วย Microsoft",
          frontend: true,
          enabled: true,
          createdAt: "2025-07-31T09:00:00.000Z",
          updatedAt: "2025-07-31T09:00:00.000Z",
          configRegistry: {
            id: "uuid-cfg-4",
            configKey: "login.microsoft",
            displayName: "Microsoft Login Text",
            configType: "string",
            description: "Text for Microsoft login button",
            defaultValue: "Sign in with Microsoft",
            isLocalizable: true,
            isSensitive: false,
            createdAt: "2025-07-31T09:00:00.000Z",
            updatedAt: "2025-07-31T09:00:00.000Z",
          },
        },
        "login.google": {
          id: "uuid-cfgv-4",
          tenantId: "uuid-tenant-1",
          locale: "th",
          configKey: "login.google",
          configValue: "เข้าสู่ระบบด้วย Google",
          frontend: true,
          enabled: true,
          createdAt: "2025-07-31T09:00:00.000Z",
          updatedAt: "2025-07-31T09:00:00.000Z",
          configRegistry: {
            id: "uuid-cfg-5",
            configKey: "login.google",
            displayName: "Google Login Text",
            configType: "string",
            description: "Text for Google login button",
            defaultValue: "Sign in with Google",
            isLocalizable: true,
            isSensitive: false,
            createdAt: "2025-07-31T09:00:00.000Z",
            updatedAt: "2025-07-31T09:00:00.000Z",
          },
        },
        primary_color: {
          id: "uuid-cfgv-5",
          tenantId: "uuid-tenant-1",
          locale: null,
          configKey: "primary_color",
          configValue: "#1976d2",
          frontend: true,
          enabled: true,
          createdAt: "2025-07-31T09:00:00.000Z",
          updatedAt: "2025-07-31T09:00:00.000Z",
          configRegistry: {
            id: "uuid-cfg-1",
            configKey: "primary_color",
            displayName: "Primary Color",
            configType: "color",
            description: "Main theme color",
            defaultValue: "#1976d2",
            isLocalizable: false,
            isSensitive: false,
            createdAt: "2025-07-31T09:00:00.000Z",
            updatedAt: "2025-07-31T09:00:00.000Z",
          },
        },
        secondary_color: {
          id: "uuid-cfgv-6",
          tenantId: "uuid-tenant-1",
          locale: null,
          configKey: "secondary_color",
          configValue: "#ff9800",
          frontend: true,
          enabled: true,
          createdAt: "2025-07-31T09:00:00.000Z",
          updatedAt: "2025-07-31T09:00:00.000Z",
          configRegistry: {
            id: "uuid-cfg-2",
            configKey: "secondary_color",
            displayName: "Secondary Color",
            configType: "color",
            description: "Accent theme color",
            defaultValue: "#ff9800",
            isLocalizable: false,
            isSensitive: false,
            createdAt: "2025-07-31T09:00:00.000Z",
            updatedAt: "2025-07-31T09:00:00.000Z",
          },
        },
      },
      ssoProviders: [
        {
          id: "uuid-sso-2",
          tenantId: "uuid-tenant-1",
          provider: "keycloak-google",
          clientId: "xyz789",
          clientSecret: "***",
          config: {
            scope: "openid email profile",
          },
          enabled: true,
          i18nKey: "login.google",
          url: "https://accounts.google.com/o/oauth2/v2/auth",
          createdAt: "2025-07-31T09:00:00.000Z",
          updatedAt: "2025-07-31T09:00:00.000Z",
        },
        {
          id: "uuid-sso-1",
          tenantId: "uuid-tenant-1",
          provider: "keycloak.microsoft",
          clientId: "abc123",
          clientSecret: "***",
          config: {
            scope: "openid email profile",
          },
          enabled: true,
          i18nKey: "login.microsoft",
          url: "https://dev-auth.tcctech.app/realms/sphera/protocol/openid-connect/auth?client_id=sphera&response_type=code&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&kc_idp_hint=microsoft2",
          createdAt: "2025-07-31T09:00:00.000Z",
          updatedAt: "2025-07-31T09:00:00.000Z",
        },
      ],
      programs: [
        {
          id: "uuid-prog-1",
          tenantId: "uuid-tenant-1",
          parentMenu: "dashboard",
          iconUrl: "https://image.com/test.png",
          name: "Demo Program 1",
          description: "For demonstration",
          endpointPath: "/",
          createdAt: "2025-07-31T09:00:00.000Z",
          updatedAt: "2025-07-31T09:00:00.000Z",
        },
        {
          id: "uuid-prog-2",
          tenantId: "uuid-tenant-2",
          parentMenu: "dashboard",
          iconUrl: "https://image.com/test.png",
          name: "Demo Program 2",
          description: "For demonstration",
          endpointPath: "/",
          createdAt: "2025-07-31T09:00:00.000Z",
          updatedAt: "2025-07-31T09:00:00.000Z",
        },
        {
          id: "uuid-prog-3",
          tenantId: "uuid-tenant-3",
          parentMenu: "data entry",
          iconUrl: "https://image.com/test.png",
          name: "Demo Program 1",
          description: "For demonstration",
          endpointPath: "/",
          createdAt: "2025-07-31T09:00:00.000Z",
          updatedAt: "2025-07-31T09:00:00.000Z",
        },
        {
          id: "uuid-prog-4",
          tenantId: "uuid-tenant-4",
          parentMenu: "data entry",
          iconUrl: "https://image.com/test.png",
          name: "Demo Program 2",
          description: "For demonstration",
          endpointPath: "/",
          createdAt: "2025-07-31T09:00:00.000Z",
          updatedAt: "2025-07-31T09:00:00.000Z",
        },
      ],
    },
  ];
  const findTenant = mockTenantConfigs.find(
    (item) => item.tenant.slug === tenantSlug
  );
  if (!findTenant) {
    res.status(404).json({
      message: "tenant.not_found",
    });
  }
  if (findTenant) {
    res.status(200).json({
      ...findTenant,
    });
  }

  res.status(500).json({
    message: "common.internal_server_error",
  });
});

const { v4: uuidv4 } = require("uuid");

// สร้าง mock user data 150 รายการ
const users = Array.from({ length: 150 }, (_, i) => ({
  id: `uuid-user-${i + 1}`,
  username: `user${i + 1}`,
  email: `user${i + 1}@example.com`,
  firstname: `First${i + 1}`,
  lastname: `Last${i + 1}`,
  type: "standard",
  passwordPolicy: "default",
  isPasswordSendEmail: Math.random() < 0.5, // random true/false
  isDenyPasswordChange: Math.random() < 0.5, // random true/false
  tenantId: `uuid-tenant-${i + 1}`,
  tenantLocaleId: `th`,
  timezoneId: `uuid-tz-${i + 1}`,
  decimalSeparatorId: `decimal_point`,
  currencyId: `uuid-currency-${i + 1}`,
  company: `Company ${i + 1}`,
  street: `${i + 1} Main Street`,
  city: "Bangkok",
  countryId: `uuid-country-${i + 1}`,
  poBox: `1000${i + 1}`,
  phone: `66123456${String(78 + i).padStart(2, "0")}`,
  fax: `66987654${String(21 + i).padStart(2, "0")}`,
  mobile: `66888888${String(88 + i).padStart(2, "0")}`,
  additionalInformation: "VIP user",
  isActive: Math.random() < 0.5, // random true/false
  isLocked: Math.random() < 0.5, // random true/false
  failedLoginAttempts: 0,
  lastFailedLogin_at: new Date().toISOString(),
  lastLoginAt: new Date().toISOString(),
  createdAt: new Date().toISOString(),
  updatedAt: new Date().toISOString(),
  deletedAt: null,
  createdBy: { id: "uuid-admin", username: "admin" },
  updatedBy: { id: "uuid-admin", username: "admin" },
  deletedBy: null,
}));

// ---------- User CRUD ----------

// GET all users with pagination
// app.get("/v1/api/users/", (req, res) => {
//   const page = parseInt(req.query.page) || 1;
//   const pageSize = parseInt(req.query.pageSize) || 10;
//   const start = (page - 1) * pageSize;
//   const end = start + pageSize;
//   res.json({
//     data: users.slice(start, end),
//     pagination: {
//       page,
//       pageSize,
//       totalItems: users.length,
//       totalPages: Math.ceil(users.length / pageSize),
//     },
//   });
// });

/**
 * @swagger
 * /v1/api/users/:
 *   get:
 *     summary: Get all users (with optional search)
 *     parameters:
 *       - in: query
 *         name: search
 *         schema:
 *           type: string
 *           example: '{"AND":[{"firstname":"John"},{"email":{"contains":"example.com"}}]}'
 *         description: JSON string for filtering users. Supports AND/OR and contains.
 *     responses:
 *       200:
 *         description: List of users matching search criteria
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 data:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       id:
 *                         type: string
 *                       username:
 *                         type: string
 *                       email:
 *                         type: string
 *                       firstname:
 *                         type: string
 *                       lastname:
 *                         type: string
 *                       type:
 *                         type: string
 *                       isActive:
 *                         type: boolean
 *                       createdAt:
 *                         type: string
 *                       updatedAt:
 *                         type: string
 */

app.get("/v1/api/users/", (req, res) => {
  let filteredUsers = users;

  if (req.query.search) {
    try {
      // Decode JSON query parameter
      const search = JSON.parse(req.query.search);

      const evaluateCondition = (user, condition) => {
        if (condition.AND) {
          return condition.AND.every((c) => evaluateCondition(user, c));
        } else if (condition.OR) {
          return condition.OR.some((c) => evaluateCondition(user, c));
        } else {
          // Single field condition
          const key = Object.keys(condition)[0];
          const value = condition[key];
          if (typeof value === "object" && value.contains) {
            return (user[key] || "").includes(value.contains);
          } else {
            return user[key] === value;
          }
        }
      };

      filteredUsers = users.filter((user) => evaluateCondition(user, search));
    } catch (error) {
      return res.status(400).json({ message: "Invalid search format" });
    }
  }

  res.json({ data: filteredUsers });
});

// GET user by id (return all fields)
app.get("/v1/api/users/:id", (req, res) => {
  const user = users.find((u) => u.id === req.params.id);
  if (!user) return res.status(404).json({ message: "user.not_found" });
  res.json(user);
});

/**
 * @swagger
 * /v1/api/users:
 *   post:
 *     summary: Create a new user
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *               firstname:
 *                 type: string
 *               lastname:
 *                 type: string
 *               type:
 *                 type: string
 *               isActive:
 *                 type: boolean
 *             example:
 *               email: user151@example.com
 *               firstname: John
 *               lastname: Doe
 *               type: standard
 *               isActive: true
 *     responses:
 *       201:
 *         description: User created successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 id:
 *                   type: string
 *                 email:
 *                   type: string
 *                 firstname:
 *                   type: string
 *                 lastname:
 *                   type: string
 *                 type:
 *                   type: string
 *                 isActive:
 *                   type: boolean
 *                 createdAt:
 *                   type: string
 *                 updatedAt:
 *                   type: string
 *             example:
 *               id: uuid-user-151
 *               email: user151@example.com
 *               firstname: John
 *               lastname: Doe
 *               type: standard
 *               isActive: true
 *               createdAt: "2025-08-14T02:23:43Z"
 *               updatedAt: "2025-08-14T02:23:43Z"
 */
// POST create new user
app.post("/v1/api/users", (req, res) => {
  const newUser = {
    id: uuidv4(),
    ...req.body,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
  users.push(newUser);
  res.status(201).json(newUser);
});

// PUT update user
/**
 * @swagger
 * /v1/api/users/{id}:
 *   put:
 *     summary: Update user by ID
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *           example: uuid-user-1
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *               firstname:
 *                 type: string
 *               lastname:
 *                 type: string
 *               type:
 *                 type: string
 *               isActive:
 *                 type: boolean
 *             example:
 *               email: user1@example.com
 *               firstname: First1
 *               lastname: Last1
 *               type: standard
 *               isActive: true
 *     responses:
 *       200:
 *         description: User updated successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 id:
 *                   type: string
 *                 email:
 *                   type: string
 *                 firstname:
 *                   type: string
 *                 lastname:
 *                   type: string
 *                 type:
 *                   type: string
 *                 isActive:
 *                   type: boolean
 *                 createdAt:
 *                   type: string
 *                 updatedAt:
 *                   type: string
 *             example:
 *               id: uuid-user-1
 *               email: user1@example.com
 *               firstname: First1
 *               lastname: Last1
 *               type: standard
 *               isActive: true
 *               createdAt: "2025-08-14T02:23:43Z"
 *               updatedAt: "2025-08-14T02:23:43Z"
 *       404:
 *         description: User not found
 *         content:
 *           application/json:
 *             example:
 *               message: user.not_found
 */
app.put("/v1/api/users/:id", (req, res) => {
  const index = users.findIndex((u) => u.id === req.params.id);
  if (index === -1) return res.status(404).json({ message: "user.not_found" });
  users[index] = {
    ...users[index],
    ...req.body,
    updatedAt: new Date().toISOString(),
  };
  res.json(users[index]);
});

/**
 * @swagger
 * /v1/api/users/{id}:
 *   delete:
 *     summary: Delete user by ID
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *           example: uuid-user-1
 *     responses:
 *       200:
 *         description: User deleted successfully
 *         content:
 *           application/json:
 *             example:
 *               message: user.deleted
 *       404:
 *         description: User not found
 *         content:
 *           application/json:
 *             example:
 *               message: user.not_found
 */
app.delete("/v1/api/users/:id", (req, res) => {
  const index = users.findIndex((u) => u.id === req.params.id);
  if (index === -1) return res.status(404).json({ message: "user.not_found" });
  users.splice(index, 1);
  res.json({
    message: "user.deleted",
  });
});
/**
 * @swagger
 *   post:
 *     summary: Create a new user
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *               firstname:
 *                 type: string
 *               lastname:
 *                 type: string
 *               type:
 *                 type: string
 *               isActive:
 *                 type: boolean
 *             example:
 *               email: user151@example.com
 *               firstname: John
 *               lastname: Doe
 *               type: standard
 *               isActive: true
 *     responses:
 *       201:
 *         description: User created successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 id:
 *                   type: string
 *                 email:
 *                   type: string
 *                 firstname:
 *                   type: string
 *                 lastname:
 *                   type: string
 *                 type:
 *                   type: string
 *                 isActive:
 *                   type: boolean
 *                 createdAt:
 *                   type: string
 *                 updatedAt:
 *                   type: string
 */

/**
 * @swagger
 * /v1/api/users/{id}:
 *   get:
 *     summary: Get user by ID
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *           example: uuid-user-1
 *     responses:
 *       200:
 *         description: User found
 *         content:
 *           application/json:
 *             example:
 *               id: uuid-user-1
 *               username: user1
 *               email: user1@example.com
 *               firstname: First1
 *               lastname: Last1
 *               type: standard
 *               isActive: true
 *               createdAt: "2025-08-14T02:23:43Z"
 *               updatedAt: "2025-08-14T02:23:43Z"
 *       404:
 *         description: User not found
 *         content:
 *           application/json:
 *             example:
 *               message: user.not_found
 */

/**
 * @swagger
 * /v1/api/users/username/{username}:
 *   get:
 *     summary: Get user by username
 *     parameters:
 *       - in: path
 *         name: username
 *         required: true
 *         schema:
 *           type: string
 *           example: user10
 *     responses:
 *       200:
 *         description: User found
 *         content:
 *           application/json:
 *             example:
 *               id: uuid-user-10
 *               username: user10
 *               email: user10@example.com
 *               firstname: First10
 *               lastname: Last10
 *               type: standard
 *               isActive: true
 *               createdAt: "2025-08-14T02:23:43Z"
 *               updatedAt: "2025-08-14T02:23:43Z"
 *       404:
 *         description: User not found
 *         content:
 *           application/json:
 *             example:
 *               message: user.not_found
 */

// ---------- GET user by username ----------
app.get("/v1/api/users/username/:username", (req, res) => {
  const { username } = req.params;
  const user = users.find((u) => u.username === username);
  if (!user) return res.status(404).json({ message: "user.not_found" });
  res.json(user);
});

/**
 * @swagger
 * /v1/api/users/email/{email}:
 *   get:
 *     summary: Get user by email
 *     parameters:
 *       - in: path
 *         name: email
 *         required: true
 *         schema:
 *           type: string
 *           example: user10@example.com
 *     responses:
 *       200:
 *         description: User found
 *         content:
 *           application/json:
 *             example:
 *               id: uuid-user-10
 *               username: user10
 *               email: user10@example.com
 *               firstname: First10
 *               lastname: Last10
 *               type: standard
 *               isActive: true
 *               createdAt: "2025-08-14T02:23:43Z"
 *               updatedAt: "2025-08-14T02:23:43Z"
 *       404:
 *         description: User not found
 *         content:
 *           application/json:
 *             example:
 *               message: user.not_found
 */

// ---------- GET user by email ----------
app.get("/v1/api/users/email/:email", (req, res) => {
  const { email } = req.params;
  const user = users.find((u) => u.email === email);
  if (!user) return res.status(404).json({ message: "user.not_found" });
  res.json(user);
});

// ---------- PATCH update isActive status ----------
/**
 * @swagger
 * /v1/api/users/{id}/active:
 *   patch:
 *     summary: Update user's isActive status
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *           example: uuid-user-1
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               isActive:
 *                 type: boolean
 *             example:
 *               isActive: false
 *     responses:
 *       200:
 *         description: User status updated
 *         content:
 *           application/json:
 *             example:
 *               id: uuid-user-1
 *               isActive: false
 *               message: user.status_updated
 *       404:
 *         description: User not found
 *         content:
 *           application/json:
 *             example:
 *               message: user.not_found
 */
app.patch("/v1/api/users/:id/active", (req, res) => {
  const { id } = req.params;
  const { isActive } = req.body;

  const user = users.find((u) => u.id === id);
  if (!user) {
    return res.status(404).json({ message: "user.not_found" });
  }

  user.isActive = isActive;
  user.updatedAt = new Date().toISOString();

  res.status(200).json({
    id: user.id,
    isActive: user.isActive,
    message: "user.status_updated",
  });
});

// --- Mock Data 150 row ---
const sites = [];
for (let i = 1; i <= 150; i++) {
  const parent_id = i === 1 ? null : Math.floor(Math.random() * (i - 1)) + 1;
  const hierarchyLevel = parent_id ? 2 : 1;
  const path = parent_id
    ? `${parent_id.toString().padStart(4, "0")}/${i
        .toString()
        .padStart(4, "0")}`
    : i.toString().padStart(4, "0");

  sites.push({
    id: i,
    parent_id,
    site_id: i,
    sortingLevel: Math.ceil(Math.random() * 3),
    hierarchyLevel,
    path,
    name: `Site Name ${i}`,
    startTerm: "2025-08-19",
    endTerm: "2025-08-19",
    tags: [],
    acquirable: Math.random() > 0.5,
    status: "active",
    fiscalPeriod: `collection_period_${Math.ceil(Math.random() * 5)}`,
    countryID: 123,
    postalCode: 10000 + i,
    city: "Bangkok",
    province: "Bangkok",
    createdAt: "2025-08-08 00:00:00",
    totalRevisions: 1,
  });
}

/**
 * @swagger
 * /sites/site-list:
 *   get:
 *     summary: Get all sites
 *     responses:
 *       200:
 *         description: List of sites
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 $ref: '#/components/schemas/Site'
 *   post:
 *     summary: Create new site
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/Site'
 *     responses:
 *       201:
 *         description: Site created
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Site'
 *
 * /sites/{id}:
 *   get:
 *     summary: Get site by id
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Site found
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Site'
 *       404:
 *         description: Site not found
 *         content:
 *           application/json:
 *             example:
 *               message: Site not found
 *   put:
 *     summary: Update site by id
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/Site'
 *     responses:
 *       200:
 *         description: Site updated
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Site'
 *       404:
 *         description: Site not found
 *         content:
 *           application/json:
 *             example:
 *               message: Site not found
 *   delete:
 *     summary: Delete site by id
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Site deleted
 *         content:
 *           application/json:
 *             example:
 *               message: Site deleted
 *               site:
 *                 id: 1
 *                 name: Site Name 1
 *       404:
 *         description: Site not found
 *         content:
 *           application/json:
 *             example:
 *               message: Site not found
 *
 * components:
 *   schemas:
 *     Site:
 *       type: object
 *       properties:
 *         id:
 *           type: integer
 *         parent_id:
 *           type: integer
 *           nullable: true
 *         site_id:
 *           type: integer
 *         sortingLevel:
 *           type: integer
 *         hierarchyLevel:
 *           type: integer
 *         path:
 *           type: string
 *         name:
 *           type: string
 *         startTerm:
 *           type: string
 *         endTerm:
 *           type: string
 *         tags:
 *           type: array
 *           items:
 *             type: string
 *         acquirable:
 *           type: boolean
 *         status:
 *           type: string
 *         fiscalPeriod:
 *           type: string
 *         countryID:
 *           type: integer
 *         postalCode:
 *           type: integer
 *         city:
 *           type: string
 *         province:
 *           type: string
 *         createdAt:
 *           type: string
 *         totalRevisions:
 *           type: integer
 */

// --- CRUD Routes ---

// Get all sites
app.get("/sites/site-list", (req, res) => {
  res.json(sites);
});

// Get single site by id
app.get("/sites/:id", (req, res) => {
  const site = sites.find((s) => s.id === parseInt(req.params.id));
  if (!site) return res.status(404).json({ message: "Site not found" });
  res.json(site);
});

// Create new site
app.post("/sites", (req, res) => {
  const newId = sites.length ? sites[sites.length - 1].id + 1 : 1;
  const newSite = {
    id: newId,
    site_id: newId,
    hierarchyLevel: req.body.parent_id ? 2 : 1,
    path: req.body.parent_id
      ? `${req.body.parent_id.toString().padStart(4, "0")}/${newId
          .toString()
          .padStart(4, "0")}`
      : newId.toString().padStart(4, "0"),
    totalRevisions: 1,
    ...req.body,
  };
  sites.push(newSite);
  res.status(201).json(newSite);
});

// Update site by id
app.put("/sites/:id", (req, res) => {
  const index = sites.findIndex((s) => s.id === parseInt(req.params.id));
  if (index === -1) return res.status(404).json({ message: "Site not found" });

  const updatedSite = { ...sites[index], ...req.body };
  sites[index] = updatedSite;
  res.json(updatedSite);
});

// Delete site by id
app.delete("/sites/:id", (req, res) => {
  const index = sites.findIndex((s) => s.id === parseInt(req.params.id));
  if (index === -1) return res.status(404).json({ message: "Site not found" });

  const deleted = sites.splice(index, 1);
  res.json({ message: "Site deleted", site: deleted[0] });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
