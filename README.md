# Securing-NodeJS-Applications
A comprehensive guide on securing Node.js applications, aligned with OWASP WSTG and industry best practices.

![Securing-NodeJS-Applications](images/cover.png)

# Introduction

If you've been working with Node.js, you know how it enables fast, scalable web application development. Its event-driven, non-blocking I/O model is ideal for building efficient, real-time applications. However, in the rush to develop new features and deploy code quickly, security can sometimes become a secondary consideration. Balancing feature development with security is a common challenge.

This is where the **OWASP Web Security Testing Guide (WSTG)** becomes invaluable. If you’re unfamiliar, **OWASP** (Open Web Application Security Project) is a nonprofit organization dedicated to improving software security. Their WSTG is a comprehensive resource filled with insights on identifying common web vulnerabilities.

In this blog post, I’ll highlight some typical Node.js vulnerabilities as outlined by the OWASP WSTG. I'll show vulnerable code snippets for each category and, more importantly, walk you through how to fix them. Whether you're a seasoned Node.js professional or just starting with backend development, this guide will help you build more secure and robust applications.

Let’s dive into the world of Node.js security.

# **Overview of OWASP WSTG Categories**

Before we jump into code examples, let's look at key categories from the **OWASP Web Security Testing Guide (WSTG)** and how they relate to Node.js applications.

### **1. Information Gathering**

*Know what’s out there.*

This step involves collecting information useful to an attacker, such as server details, application entry points, and technologies used. Even small details can help piece together an attack. In Node.js applications, default settings or exposed metadata can inadvertently reveal critical details.

### **2. Configuration and Deployment Management Testing**

*Don’t leave the back door open.*

This category checks that servers and applications are configured securely. Misconfigurations like default passwords, unnecessary services, or improper file permissions can make it easy for attackers to gain access. Node.js applications need careful configuration to avoid exposing sensitive information or functionality.

### **3. Identity Management Testing**

*Who gets to be who?*

This category focuses on how user identities are created and managed. Weak registration processes or poorly defined roles can lead to unauthorized access. Ensuring robust identity management in Node.js applications helps prevent privilege escalation and unauthorized actions.

### **4. Authentication Testing**

*Are you really who you say you are?*

This involves ensuring that only legitimate users can log in. Flaws in authentication mechanisms can allow attackers to bypass login screens altogether. Proper authentication practices are essential in Node.js applications to verify user identities securely.

### **5. Authorization Testing**

*Just because you’re in doesn’t mean you can do anything.*

Even after logging in, users should only have access to what they’re permitted to. Testing ensures that users can’t escalate their privileges or access restricted areas. Implementing strict authorization checks in Node.js applications prevents unauthorized access to resources.

### **6. Session Management Testing**

*Keep track of who’s who—securely.*

Sessions link users to their activities on the server. Poor session management can lead to issues like session hijacking, where an attacker takes over a user’s session. Secure session handling in Node.js is crucial for maintaining user integrity.

### **7. Input Validation Testing**

*Never trust user input—seriously.*

This is about ensuring all user-supplied data is validated and sanitized. It helps prevent attacks like SQL injection and Cross-Site Scripting (XSS). Node.js applications must implement robust input validation to safeguard against injection attacks.

### **8. Error Handling**

*Don’t spill secrets when things go wrong.*

Proper error handling ensures that error messages don’t reveal sensitive information that could aid an attacker. In Node.js, unhandled exceptions or detailed error messages can expose application internals.

### **9. Weak Cryptography**

*Encryption done right.*

Using strong, up-to-date encryption methods is crucial. Weak cryptography can expose sensitive data if an attacker intercepts it. Node.js applications should use secure cryptographic practices to protect data at rest and in transit.

### **10. Business Logic Testing**

*Does the app make sense?*

This involves checking that the application behaves as intended and that attackers can’t exploit logical flaws to manipulate processes. Ensuring that business logic is correctly implemented in Node.js prevents misuse of application functionality.

### **11. Client-side Testing**

*The front end matters too.*

We need to test client-side code for vulnerabilities like DOM-based XSS or insecure storage, which can compromise user data. Node.js applications often include client-side JavaScript that requires careful security considerations.

### **12. API Testing**

*Secure the gateways.*

APIs often expose backend functionalities. Testing ensures they don’t provide attackers with direct access to sensitive operations or data. Securing APIs in Node.js is essential to prevent unauthorized access and data breaches.

---

Understanding these areas helps us identify vulnerabilities in our Node.js applications and figure out how to fix them. In the following sections, we'll explore each category in detail, providing examples and best practices to enhance your application's security.

# Information Gathering (WSTG-INFO)

**Information Gathering** is often the first step an attacker takes to learn more about your application. The more information they can collect, the easier it becomes for them to identify and exploit vulnerabilities.

## Typical Express.js Server Configuration and Fingerprinting

By default, Express.js includes settings that can inadvertently reveal information about your server. A common example is the `X-Powered-By` HTTP header, which indicates that your application is using Express.

In the following setup, every HTTP response includes the `X-Powered-By: Express` header:

```jsx
const express = require('express');
const app = express();

// Your routes here

app.listen(3000, () => {
  console.log('Server is running on port 3000');
});

```

**Why This Is a Problem**

- **Fingerprinting**: Attackers can use this header to determine the technologies you're using. Knowing you're running Express allows them to tailor attacks to known vulnerabilities in specific versions of Express or Node.js.

**Mitigation**

You can disable this header to make it harder for attackers to fingerprint your server:

```jsx
const express = require('express');
const app = express();

// Disable the X-Powered-By header
app.disable('x-powered-by');

// Your routes here

app.listen(3000, () => {
  console.log('Server is running on port 3000');
});

```

**Enhanced Mitigation with Helmet**

A better approach is to use the `helmet` middleware, which sets various HTTP headers to improve your app's security:

```jsx
const express = require('express');
const helmet = require('helmet');
const app = express();

// Use Helmet to secure headers
app.use(helmet());

// Your routes here

app.listen(3000, () => {
  console.log('Server is running on port 3000');
});

```

**Why Use Helmet?**

- **Comprehensive Security Headers**: Helmet sets multiple HTTP headers that help protect your app from well-known web vulnerabilities.
- **Ease of Use**: With just one line, you enhance your application's security posture significantly.

---

## API Fuzzing and Unprotected Documentation Endpoints

Attackers often use **API fuzzing** to discover hidden endpoints by sending a high volume of requests with different inputs. If you have an unprotected API documentation endpoint like `/api/docs`, you may inadvertently provide attackers with a roadmap to your API.

Imagine you've set up Swagger UI for API documentation:

```jsx
const express = require('express');
const app = express();

const swaggerUi = require('swagger-ui-express');
const swaggerDocument = require('./swagger.json');

// Expose API docs publicly
app.use('/api/docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));

// Your routes here

app.listen(3000, () => {
  console.log('Server is running on port 3000');
});

```

**Why This Is a Problem**

- **Information Disclosure**: Exposing `/api/docs` publicly reveals detailed information about your API endpoints, request parameters, and expected responses.
- **Facilitates Targeted Attacks**: Attackers can use this information to craft specific attacks against your endpoints, such as parameter manipulation or injection attacks.

**Mitigation**

Restrict access to your API documentation:

- **Serve Documentation Only in Non-Production Environments**
    
    ```jsx
    if (process.env.NODE_ENV !== 'production') {
      const swaggerUi = require('swagger-ui-express');
      const swaggerDocument = require('./swagger.json');
    
      app.use('/api/docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));
    }
    
    ```
    
- **Protect Documentation with Authentication**
    
    Alternatively, require authentication to access the documentation:
    
    ```jsx
    const express = require('express');
    const basicAuth = require('express-basic-auth');
    const app = express();
    
    const swaggerUi = require('swagger-ui-express');
    const swaggerDocument = require('./swagger.json');
    
    // Set up basic authentication for the docs
    app.use(
      '/api/docs',
      basicAuth({
        users: { admin: 'password' },
        challenge: true,
      }),
      swaggerUi.serve,
      swaggerUi.setup(swaggerDocument)
    );
    
    // Your routes here
    
    app.listen(3000, () => {
      console.log('Server is running on port 3000');
    });
    
    ```
    

**Preventing API Fuzzing**

While you cannot completely prevent someone from attempting to fuzz your API, you can make it less effective:

- **Implement Rate Limiting**
    
    Limit the number of requests a user can make within a specific time frame to mitigate brute-force and fuzzing attacks:
    
    ```jsx
    const rateLimit = require('express-rate-limit');
    
    const limiter = rateLimit({
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 100, // Limit each IP to 100 requests per window
      standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
      legacyHeaders: false, // Disable the `X-RateLimit-*` headers
    });
    
    // Apply the rate limiting middleware to all requests
    app.use(limiter);
    
    ```
    

**Why This Helps**

- **Throttling Malicious Activity**: Rate limiting reduces the effectiveness of automated attacks by slowing down the rate at which an attacker can send requests.
- **Protecting Server Resources**: It helps prevent resource exhaustion, ensuring your API remains available to legitimate users.

# Configuration and Deployment Management Testing (WSTG-CONF)

Configuration and deployment management are critical aspects of application security. Misconfigurations can serve as open doors for attackers. Below are common issues in Node.js applications and how to address them.

## Running in Development Mode in Production

Running your application in development mode on a production server can expose detailed error messages and stack traces.

```jsx
// app.js
const express = require('express');
const app = express();

// Error handling middleware
app.use((err, req, res, next) => {
  res.status(500).send(err.stack); // Sends stack trace to the client
});

// Your routes here

app.listen(3000);

```

**Why This Is a Problem**

- **Information Leakage**: Detailed error messages and stack traces can reveal sensitive information about your application's structure, dependencies, and file paths.
- **Facilitates Exploitation**: Attackers can use this information to identify potential vulnerabilities and craft targeted attacks.

**Mitigation**

Set `NODE_ENV` to `'production'` and use generic error messages in production:

```jsx
// app.js
const express = require('express');
const app = express();

// Your routes here

// Error handling middleware
if (app.get('env') === 'production') {
  // Production error handler
  app.use((err, req, res, next) => {
    // Log the error internally
    console.error(err);
    res.status(500).send('An unexpected error occurred.');
  });
} else {
  // Development error handler (with stack trace)
  app.use((err, req, res, next) => {
    res.status(500).send(`<pre>${err.stack}</pre>`);
  });
}

app.listen(3000);

```

**Best Practices**

- **Set Environment Variables Correctly**: Ensure that `NODE_ENV` is set to `'production'` in your production environment.
- **Internal Logging**: Log errors internally for debugging purposes without exposing details to the end-user.

---

## Using Default or Weak Credentials

Using default or weak credentials, such as a simple secret key for signing JSON Web Tokens (JWTs), is a common security mistake.

```jsx
const express = require('express');
const jwt = require('jsonwebtoken');
const app = express();

// Weak secret key
const SECRET_KEY = 'secret';

app.post('/login', (req, res) => {
  // Authenticate user (authentication logic not shown)
  const userId = req.body.userId;

  // Sign the JWT with a weak secret
  const token = jwt.sign({ userId }, SECRET_KEY);
  res.json({ token });
});

app.get('/protected', (req, res) => {
  const token = req.headers['authorization'];

  try {
    // Verify the token using the weak secret
    const decoded = jwt.verify(token, SECRET_KEY);
    res.send('Access granted to protected data');
  } catch (err) {
    res.status(401).send('Unauthorized');
  }
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});

```

**Why This Is a Problem**

- **Weak Secret Key**: Using a simple or common string like `'secret'` makes it easy for attackers to guess or brute-force the key.
- **Hard-Coded Secrets**: Storing secrets directly in your code increases the risk of exposure if your codebase is compromised.
- **Token Forgery**: Attackers who know your secret key can forge valid JWTs, gaining unauthorized access to protected resources.

**Mitigation**

- **Use a Strong, Secure Secret Key**
    - Generate a long, random string as your secret key.
    - Use a secure random generator to create the key.
- **Store Secrets Securely**
    - Use environment variables to store secret keys.
    - In production, use a secrets management tool or service.

**Implementation**

```jsx
// Secure secret key from environment variables
const SECRET_KEY = process.env.JWT_SECRET;

if (!SECRET_KEY) {
  throw new Error('JWT_SECRET environment variable is not set.');
}

app.post('/login', (req, res) => {
  // Authenticate user
  const userId = req.body.userId;

  // Sign the JWT with the secure secret
  const token = jwt.sign({ userId }, SECRET_KEY, { expiresIn: '1h' });
  res.json({ token });
});

```

**Best Practices**

- **Environment Variables**: Do not commit secrets to version control. Use environment variables or configuration files that are not checked into source control.
- **Rotate Secrets**: Implement a process to rotate secrets periodically.
- **Validate Configuration**: Ensure that all required environment variables are set during application startup.

---

## Missing Security Headers

Not setting essential HTTP security headers can leave your application vulnerable to various attacks such as Cross-Site Scripting (XSS), Clickjacking, and MIME-type sniffing.

**Potential Risks**

- **XSS Attacks**: Without a Content Security Policy (CSP), your application is more susceptible to XSS attacks.
- **Clickjacking**: Without the `X-Frame-Options` header, attackers can embed your site in iframes to trick users into performing unintended actions.
- **MIME Sniffing**: Without the `X-Content-Type-Options` header, browsers may interpret files as a different MIME type, leading to security risks.
- **Insecure Connections**: Without the `Strict-Transport-Security` header, browsers may not enforce HTTPS connections, exposing data to man-in-the-middle attacks.

**Mitigation**

Use the `helmet` middleware to set these headers appropriately:

```jsx
const express = require('express');
const helmet = require('helmet');
const app = express();

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", 'trusted-cdn.com'],
        objectSrc: ["'none'"],
        upgradeInsecureRequests: [],
      },
    },
    frameguard: { action: 'deny' },
    referrerPolicy: { policy: 'no-referrer' },
    hsts: {
      maxAge: 31536000, // 1 year in seconds
      includeSubDomains: true,
      preload: true,
    },
    xssFilter: true,
    noSniff: true,
  })
);

// Your routes here

app.listen(3000, () => {
  console.log('Server is running on port 3000');
});

```

**Explanation of Key Headers**

- **Content Security Policy (CSP)**: Restricts the sources from which the browser can load resources, mitigating XSS and data injection attacks.
- **X-Frame-Options (`frameguard`)**: Protects against Clickjacking by controlling whether your site can be embedded in iframes.
- **Strict-Transport-Security (`hsts`)**: Instructs browsers to only use HTTPS for all future requests to your domain.
- **Referrer-Policy**: Controls how much referrer information is included with requests, protecting user privacy.
- **X-XSS-Protection (`xssFilter`)**: Enables the Cross-site scripting (XSS) filter built into most browsers.
- **X-Content-Type-Options (`noSniff`)**: Prevents browsers from MIME-sniffing a response away from the declared content type.

**Best Practices**

- **Customize Helmet Configuration**: Adjust Helmet settings to fit your application's specific needs, allowing trusted sources where necessary.
- **Regularly Review Security Headers**: Stay updated on recommended security headers and their configurations.
- **Test Your Headers**: Use tools like [securityheaders.com](https://securityheaders.com/) to test your application's HTTP headers for compliance and effectiveness.

# Identity Management Testing (WSTG-IDNT)

Identity management focuses on how user identities are created, managed, and secured within your application. Flaws in this area can lead to unauthorized access and compromised accounts.

## Weak Username Policies and Account Enumeration

Allowing weak usernames or revealing information about user accounts can make it easier for attackers to breach your system.

### **Vulnerable Code Example**

```jsx
// User registration route
app.post('/register', async (req, res) => {
  const { username, password } = req.body;

  // No validation on username
  const user = new User({ username, password });
  await user.save();
  res.send('User registered successfully');
});
```

**Issues:**

- **No Username Validation**: The application accepts any username, including common or easily guessable ones such as "admin" or "user123".
- **Account Enumeration Risk**: If error messages differ when a username is taken, attackers can discover valid usernames.

Similarly, insecure password reset functionality can reveal too much information, which can be exploited.

### **Vulnerable Password Reset Route**

```jsx
// Password reset route
app.post('/reset-password', async (req, res) => {
  const { email } = req.body;

  const user = await User.findOne({ email });
  if (!user) {
    res.status(404).send('Email not found');
  } else {
    // Send reset email (implementation not shown)
    res.send('Password reset email sent');
  }
});
```

**Issue:**

- **Information Disclosure**: Revealing whether an email exists in the system allows attackers to enumerate valid email addresses.

### **Mitigation Strategies**

1. **Implement Username Validation and Use Generic Error Messages**
    
    Enforce strong username policies and avoid disclosing whether a username is available.
    
    ```jsx
    const { body, validationResult } = require('express-validator');
    const bcrypt = require('bcrypt');
    
    // User registration route with validation
    app.post(
      '/register',
      [
        body('username')
          .isAlphanumeric()
          .isLength({ min: 5 })
          .withMessage('Username must be at least 5 alphanumeric characters'),
        body('password')
          .isStrongPassword()
          .withMessage('Password must be strong'),
      ],
      async (req, res) => {
        // Handle validation results
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
          return res.status(400).send('Invalid input');
        }
    
        const { username, password } = req.body;
    
        // Check if username is taken
        const existingUser = await User.findOne({ username });
        if (existingUser) {
          // Send generic error message
          return res.status(400).send('Registration failed');
        }
    
        // Hash the password and create new user
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ username, password: hashedPassword });
        await user.save();
        res.send('User registered successfully');
      }
    );
    ```
    
    **Explanation:**
    
    - **Username Validation**: Ensures usernames meet defined criteria, reducing the risk of weak or easily guessable usernames.
    - **Generic Error Messages**: Prevents attackers from determining if a username is available, mitigating account enumeration risks.
2. **Provide Uniform Responses in Password Reset Functionality**
    
    Always respond with the same message regardless of whether the email exists.
    
    ```jsx
    // Secure password reset route
    app.post('/reset-password', async (req, res) => {
      const { email } = req.body;
    
      // Always respond with the same message
      res.send('If an account exists for this email, a password reset link has been sent.');
    
      // Proceed without revealing if the email exists
      const user = await User.findOne({ email });
      if (user) {
        // Send reset email (implementation not shown)
      }
    });
    ```
    
    **Explanation:**
    
    - **Uniform Responses**: Prevents attackers from using password reset responses to verify if an email is registered.
    - **Privacy Protection**: Enhances user privacy by not disclosing account existence.

# Authentication Testing (WSTG-ATHN)

Authentication testing focuses on verifying users' identities securely. Weaknesses in authentication mechanisms can lead to unauthorized access.

## Password and 2FA Brute-Force Attacks

Attackers may attempt to guess user passwords or two-factor authentication (2FA) codes by trying numerous combinations—a technique known as brute-force attacking.

### **Vulnerable Login Route**

```jsx
// Login route without protections
app.post('/login', async (req, res) => {
  const { username, password, twoFactorCode } = req.body;

  // Find the user
  const user = await User.findOne({ username });
  if (!user) {
    return res.status(401).send('Invalid username or password');
  }

  // Check the password
  const passwordMatch = await bcrypt.compare(password, user.password);
  if (!passwordMatch) {
    return res.status(401).send('Invalid username or password');
  }

  // If 2FA is enabled, verify the code
  if (user.isTwoFactorEnabled) {
    if (twoFactorCode !== user.twoFactorCode) {
      return res.status(401).send('Invalid 2FA code');
    }
  }

  // Generate a session or token
  res.send('Login successful');
});
```

**Issues:**

- **No Rate Limiting or Lockout Mechanism**: Attackers can attempt unlimited login attempts without restriction.
- **Weak 2FA Verification**: Using static or predictable 2FA codes makes them easier to guess.

### **Mitigation Strategies**

1. **Implement Rate Limiting**
    
    Limit the number of login attempts from a single IP address within a specific time frame.
    
    ```jsx
    const rateLimit = require('express-rate-limit');
    
    // Apply rate limiting to login route
    const loginLimiter = rateLimit({
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 5, // Limit each IP to 5 login attempts per window
      message: 'Too many login attempts. Please try again later.',
    });
    
    app.post('/login', loginLimiter, async (req, res) => {
      // Existing login logic
    });
    ```
    
    **Explanation:**
    
    - **Rate Limiting**: Reduces the risk of brute-force attacks by limiting login attempts.
2. **Use CAPTCHA After Failed Attempts**
    
    Introduce a CAPTCHA after a certain number of failed login attempts to verify that a human is interacting with the application.
    
    ```jsx
    // Middleware to check if CAPTCHA is needed
    function checkCaptcha(req, res, next) {
      if (req.session.loginAttempts >= 3) {
        // Verify CAPTCHA (implementation depends on the CAPTCHA service used)
        const captchaValid = verifyCaptcha(req.body.captchaToken);
        if (!captchaValid) {
          return res.status(400).send('CAPTCHA verification failed');
        }
      }
      next();
    }
    
    app.post('/login', loginLimiter, checkCaptcha, async (req, res) => {
      // Existing login logic
    });
    ```
    
    **Explanation:**
    
    - **CAPTCHA Implementation**: Helps distinguish between human users and automated scripts.
3. **Use Time-Based One-Time Passwords (TOTP) for 2FA**
    
    Enhance 2FA by using time-based one-time passwords instead of static codes.
    
    ```jsx
    const speakeasy = require('speakeasy');
    
    // When enabling 2FA for a user
    app.post('/enable-2fa', async (req, res) => {
      const secret = speakeasy.generateSecret();
      // Save secret.base32 in the user's record
      req.user.twoFactorSecret = secret.base32;
      await req.user.save();
      res.send({ otpauthUrl: secret.otpauth_url });
    });
    
    // Verify 2FA code during login
    if (user.isTwoFactorEnabled) {
      const tokenValidates = speakeasy.totp.verify({
        secret: user.twoFactorSecret,
        encoding: 'base32',
        token: req.body.twoFactorCode,
      });
      if (!tokenValidates) {
        return res.status(401).send('Invalid 2FA code');
      }
    }
    ```
    
    **Explanation:**
    
    - **Dynamic Codes**: TOTP generates time-based codes that are valid for a short period, enhancing security.
    - **Industry Standard**: Aligns with best practices for 2FA implementation.

## Weak Password Policy

Allowing users to choose weak passwords like "123456" or "password" increases the risk of unauthorized access.

### **Mitigation**

Enforce password complexity requirements using validation.

```jsx
const { body, validationResult } = require('express-validator');

app.post(
  '/register',
  body('password')
    .isStrongPassword({
      minLength: 8,
      minLowercase: 1,
      minUppercase: 1,
      minNumbers: 1,
      minSymbols: 1,
    })
    .withMessage(
      'Password must be at least 8 characters long and include uppercase, lowercase, number, and symbol'
    ),
  async (req, res) => {
    // Handle validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).send('Invalid password');
    }

    // Proceed with registration
  }
);
```

**Explanation:**

- **Password Complexity Enforcement**: Requires users to choose strong passwords, reducing the risk of compromise.

Additionally, check if the chosen password has been compromised in known data breaches using services like [Have I Been Pwned (HIBP)](https://haveibeenpwned.com/).

```jsx
const crypto = require('crypto');
const axios = require('axios');

// Function to check if the password has been pwned
async function isPasswordPwned(password) {
  // Hash the password using SHA-1
  const sha1Hash = crypto.createHash('sha1').update(password).digest('hex').toUpperCase();

  // Split the hash into prefix (first 5 chars) and suffix
  const prefix = sha1Hash.slice(0, 5);
  const suffix = sha1Hash.slice(5);

  // API URL with the prefix
  const url = `https://api.pwnedpasswords.com/range/${prefix}`;

  try {
    // Make a GET request to the HIBP API
    const response = await axios.get(url);
    const hashes = response.data.split('\\r\\n');

    // Check if the suffix exists in the returned hashes
    for (const line of hashes) {
      const [hashSuffix] = line.split(':');
      if (hashSuffix === suffix) {
        return true; // Password has been pwned
      }
    }

    return false; // Password is safe
  } catch (error) {
    console.error('Error checking password against HIBP:', error);
    // Decide how to handle errors (e.g., block registration or allow)
    return false;
  }
}

// Registration route with HIBP check
app.post('/register', async (req, res) => {
  const { username, password } = req.body;

  // Validate username and password (omitted for brevity)

  // Check if the password has been pwned
  const passwordPwned = await isPasswordPwned(password);
  if (passwordPwned) {
    return res
      .status(400)
      .send('This password has been compromised in a data breach. Please choose a different password.');
  }

  // Proceed with registration
  const hashedPassword = await bcrypt.hash(password, 10);
  const user = new User({ username, password: hashedPassword });
  await user.save();

  res.send('Registration successful');
});
```

**Explanation:**

- **Password Breach Check**: Prevents users from using passwords that have been exposed in data breaches.
- **Privacy Preservation**: Uses partial hashes to maintain user privacy when checking with the API.

## Weak Password Change and Reset Mechanisms

Insecure password reset mechanisms can be exploited to gain unauthorized access.

### **Vulnerable Password Reset Implementation**

```jsx
// Password reset without token expiration
app.post('/reset-password', async (req, res) => {
  const { email } = req.body;

  // Generate reset token
  const resetToken = crypto.randomBytes(20).toString('hex');

  // Save token to user record without expiration
  const user = await User.findOne({ email });
  if (user) {
    user.resetToken = resetToken;
    await user.save();
    // Send email with reset link
    sendResetEmail(user.email, `https://example.com/reset-password/${resetToken}`);
  }

  res.send('If your email is registered, you will receive a password reset link.');
});
```

**Issues:**

- **No Token Expiration**: Reset tokens remain valid indefinitely.
- **Predictable Tokens**: Using insufficiently random tokens increases the risk of token guessing.

### **Mitigation Strategies**

1. **Use Secure, Expiring Tokens**
    
    Generate cryptographically secure tokens and set an expiration time.
    
    ```jsx
    const crypto = require('crypto');
    
    // Generate a secure token with expiration
    app.post('/reset-password', async (req, res) => {
      const { email } = req.body;
    
      // Find the user
      const user = await User.findOne({ email });
      if (user) {
        // Generate secure token
        const resetToken = crypto.randomBytes(32).toString('hex');
        const tokenHash = crypto.createHash('sha256').update(resetToken).digest('hex');
    
        // Set token and expiration (e.g., 1 hour)
        user.resetToken = tokenHash;
        user.resetTokenExpires = Date.now() + 3600000; // 1 hour
        await user.save();
    
        // Send email with the plain reset token
        sendResetEmail(user.email, `https://example.com/reset-password/${resetToken}`);
      }
    
      res.send('If your email is registered, you will receive a password reset link.');
    });
    
    // Verify the token during password reset
    app.post('/reset-password/:token', async (req, res) => {
      const resetToken = req.params.token;
      const tokenHash = crypto.createHash('sha256').update(resetToken).digest('hex');
    
      // Find user with matching token and valid expiration
      const user = await User.findOne({
        resetToken: tokenHash,
        resetTokenExpires: { $gt: Date.now() },
      });
    
      if (!user) {
        return res.status(400).send('Invalid or expired token');
      }
    
      // Reset the password
      user.password = await bcrypt.hash(req.body.newPassword, 10);
      user.resetToken = undefined;
      user.resetTokenExpires = undefined;
      await user.save();
    
      res.send('Password has been reset successfully');
    });
    ```
    
    **Explanation:**
    
    - **Token Security**: Uses cryptographically secure random tokens.
    - **Token Expiration**: Limits the validity period of tokens to reduce the window of opportunity for attackers.
    - **Token Hashing**: Stores a hash of the token in the database to prevent token theft from database leaks.
2. **Notify Users of Password Changes**
    
    Send an email notification when a password is changed.
    
    ```jsx
    // After password reset
    sendNotificationEmail(user.email, 'Your password has been changed');
    ```
    
    **Explanation:**
    
    - **User Awareness**: Alerts users to unauthorized password changes, enabling them to take immediate action.

## Weak Lockout Mechanisms

Poorly implemented lockout mechanisms can either allow brute-force attacks or cause denial of service.

**Issues:**

- **No Lockout**: Attackers can attempt unlimited logins.
- **Permanent Lockout**: Users may be permanently locked out after failed attempts, leading to denial of service.

### **Mitigation Strategies**

1. **Implement Temporary Account Lockouts**
    
    Lock accounts temporarily after several failed attempts.
    
    ```jsx
    // During login attempt
    if (user.loginAttempts >= 5) {
      // Lock account for an exponential time
      const lockTime = Math.min(Math.pow(2, user.loginAttempts - 5) * 1000, MAX_LOCK_TIME);
      user.lockUntil = Date.now() + lockTime;
      await user.save();
    }
    ```
    
    **Explanation:**
    
    - **Temporary Lockout**: Prevents brute-force attacks while minimizing impact on legitimate users.
    - **Exponential Backoff**: Increases lockout duration with each subsequent failure.
2. **Avoid Account Enumeration**
    
    Provide generic error messages during authentication processes.
    
    ```jsx
    // Instead of specific messages, use a generic one
    return res.status(401).send('Invalid credentials');
    ```
    
    **Explanation:**
    
    - **Generic Responses**: Prevent attackers from determining if a username or password is incorrect, reducing account enumeration risks.

# Authorization Testing (WSTG-ATHZ)

**Authorization Testing** ensures that users can only access resources and perform actions they are permitted to. Even after a user is authenticated, we need to verify that they do not exceed their privileges. Let's examine some common pitfalls and how to address them.

## Identity Validation Before Actions

A common mistake is not validating a user's identity before performing actions on their behalf. For example, fetching a resource by its ID without verifying that the requesting user is authorized to access it.

### **Vulnerable Code Example**

```jsx
// Fetch a user's order without checking ownership
app.get('/orders/:orderId', async (req, res) => {
  const order = await Order.findById(req.params.orderId);
  if (!order) {
    return res.status(404).send('Order not found');
  }
  res.json(order);
});
```

**Issue:**

- **Lack of Authorization Check**: Any authenticated user can access any order by changing the `orderId` in the URL, potentially accessing other users' orders.

### **Mitigation**

Validate that the order belongs to the requesting user. Ensure the user is authenticated and fetch the order only if it belongs to them.

```jsx
// Middleware to verify authentication
function isAuthenticated(req, res, next) {
  // Assume user ID is stored in req.user.id after authentication
  if (req.user && req.user.id) {
    next();
  } else {
    res.status(401).send('Unauthorized');
  }
}

app.get('/orders/:orderId', isAuthenticated, async (req, res) => {
  const order = await Order.findOne({ _id: req.params.orderId, userId: req.user.id });
  if (!order) {
    return res.status(404).send('Order not found or access denied');
  }
  res.json(order);
});
```

**Explanation:**

- **Ownership Verification**: By checking `userId: req.user.id`, we ensure that the order belongs to the authenticated user.
- **Access Control**: Prevents users from accessing resources that are not theirs.

---

## Horizontal and Vertical Privilege Escalation

### **Horizontal Privilege Escalation**

Occurs when a user accesses resources or functions of another user with the same permission level.

### **Vulnerable Code Example**

```jsx
app.get('/users/:userId/profile', isAuthenticated, async (req, res) => {
  const user = await User.findById(req.params.userId);
  if (!user) {
    return res.status(404).send('User not found');
  }
  res.json(user.profile);
});
```

**Issue:**

- **Unauthorized Access**: A user can change the `userId` parameter to access another user's profile.

### **Vertical Privilege Escalation**

Occurs when a user gains higher-level privileges than intended.

### **Vulnerable Code Example**

```jsx
app.post('/admin/create-user', isAuthenticated, async (req, res) => {
  // Logic to create a new user
  res.send('User created');
});
```

**Issue:**

- **Privilege Escalation**: A regular user can access admin functionalities without proper authorization checks.

### **Mitigation**

### **Restrict Access to User Profiles**

Ensure users can only access their own profile unless they have elevated permissions.

```jsx
app.get('/users/:userId/profile', isAuthenticated, async (req, res) => {
  if (req.user.id !== req.params.userId && req.user.role !== 'admin') {
    return res.status(403).send('Forbidden');
  }
  const user = await User.findById(req.params.userId);
  if (!user) {
    return res.status(404).send('User not found');
  }
  res.json(user.profile);
});
```

**Explanation:**

- **Access Control Check**: Compares `req.user.id` with `req.params.userId` to ensure the user is accessing their own profile.
- **Role-Based Access**: Allows users with the 'admin' role to access other profiles if appropriate.

### **Restrict Access to Admin Routes**

Ensure that only users with admin privileges can access admin routes.

```jsx
function isAdmin(req, res, next) {
  if (req.user && req.user.role === 'admin') {
    next();
  } else {
    res.status(403).send('Forbidden');
  }
}

app.post('/admin/create-user', isAuthenticated, isAdmin, async (req, res) => {
  // Logic to create a new user
  res.send('User created');
});
```

**Explanation:**

- **Middleware Chain**: Uses `isAuthenticated` and `isAdmin` middleware to verify the user's role.
- **Prevents Unauthorized Access**: Blocks users without admin privileges from accessing admin functionalities.

---

## Insecure Direct Object References (IDOR)

IDOR vulnerabilities occur when an application provides direct access to objects based on user-supplied input without proper authorization checks.

### **Vulnerable Code Example**

```jsx
app.get('/invoices/:invoiceNumber', isAuthenticated, async (req, res) => {
  const invoice = await Invoice.findOne({ invoiceNumber: req.params.invoiceNumber });
  if (!invoice) {
    return res.status(404).send('Invoice not found');
  }
  res.json(invoice);
});
```

**Issue:**

- **Unauthorized Access**: Any authenticated user can access any invoice if they know the `invoiceNumber`.

### **Mitigation**

Assign unique identifiers that are hard to guess and ensure the user is authorized to access the resource.

```jsx
app.get('/invoices/:invoiceId', isAuthenticated, async (req, res) => {
  const invoice = await Invoice.findOne({ _id: req.params.invoiceId, userId: req.user.id });
  if (!invoice) {
    return res.status(404).send('Invoice not found or access denied');
  }
  res.json(invoice);
});
```

**Explanation:**

- **Authorization Check**: Includes `userId: req.user.id` in the query to ensure the invoice belongs to the user.
- **Use of Secure Identifiers**: Using MongoDB's `_id` field, which is not easily guessable.

---

By carefully implementing authorization checks and validating user permissions, you significantly reduce the risk of unauthorized access in your application. Always verify that users have the right to perform an action before executing it.

# Session Management Testing (WSTG-SESS)

Session management is critical for maintaining the security of user interactions with your application. JSON Web Tokens (JWTs) are commonly used in Node.js applications for authentication and session management. While JWTs offer convenience, improper implementation can lead to serious security issues.

## Tokens Without Expiration Time

### **Vulnerable Code Example**

```jsx
const jwt = require('jsonwebtoken');

// Generating a token without expiration
function generateToken(user) {
  const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET);
  return token;
}
```

**Issue:**

- **No Expiration**: The token remains valid indefinitely unless manually revoked.
- **Security Risk**: If the token is leaked or stolen, an attacker can access protected resources without time constraints.

### **Mitigation**

Always set an expiration time when generating JWTs.

```jsx
// Generating a token with expiration
function generateToken(user) {
  const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, {
    expiresIn: '1h', // Token expires in 1 hour
  });
  return token;
}
```

**Explanation:**

- **Limited Validity**: Setting `expiresIn` ensures tokens are valid only for a specified duration.
- **Risk Reduction**: Limits the window during which a compromised token can be used.

## Weak JWT Secrets

### **Vulnerable Code Example**

```jsx
// Using a weak, hard-coded secret
const jwtSecret = 'secret';

function generateToken(user) {
  const token = jwt.sign({ userId: user.id }, jwtSecret, { expiresIn: '1h' });
  return token;
}
```

**Issue:**

- **Predictable Secret**: Using a common or weak secret like 'secret' makes it easy for attackers to guess.
- **Token Forgery**: Attackers can create valid tokens and gain unauthorized access.

### **Mitigation**

Use a strong, randomly generated secret key stored securely.

```jsx
// Using a strong secret from environment variables
const jwtSecret = process.env.JWT_SECRET;

function generateToken(user) {
  const token = jwt.sign({ userId: user.id }, jwtSecret, { expiresIn: '1h' });
  return token;
}
```

**Generating a Strong Secret:**

Generate a long, random string using the Node.js crypto module:

```bash
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
```

**Explanation:**

- **Strong Secret**: A long, random string makes it practically impossible to guess the secret.
- **Secure Storage**: Using environment variables or a secrets management service to store the secret securely.

---

## Insecure Token Storage

### **Vulnerable Code Example**

```jsx
// Storing token in localStorage on the client side
localStorage.setItem('token', token);
```

**Issue:**

- **XSS Vulnerability**: Tokens stored in `localStorage` can be accessed by JavaScript, making them vulnerable to cross-site scripting (XSS) attacks.
- **Token Theft**: If an attacker injects malicious scripts, they can steal the token and impersonate the user.

### **Mitigation**

Store tokens in HTTP-only cookies.

```jsx
// On the server side, set the token in an HTTP-only cookie
res.cookie('token', token, {
  httpOnly: true,     // Not accessible via JavaScript
  secure: true,       // Only send cookie over HTTPS
  sameSite: 'Strict', // Helps prevent CSRF
});
```

**Explanation:**

- **HTTP-only Cookies**: Not accessible via JavaScript, mitigating XSS risks.
- **Secure Flag**: Ensures the cookie is sent only over HTTPS.
- **SameSite Attribute**: Controls when cookies are sent, helping prevent CSRF attacks.

---

## Lack of Token Revocation Mechanism

### **Issue**

Tokens remain valid until they expire, and there's no way to invalidate them server-side upon user logout or if a token is compromised.

**Consequences:**

- **No Immediate Revocation**: If a token is stolen, the attacker can use it until it expires.
- **Persistent Access**: Cannot immediately terminate a session.

### **Mitigation**

Implement a token blacklist or token versioning.

### **Using a Token Blacklist**

```jsx
const tokenBlacklist = new Set();

// On logout
app.post('/logout', (req, res) => {
  const token = req.cookies.token;
  tokenBlacklist.add(token);
  res.clearCookie('token');
  res.send('Logged out successfully');
});

// Middleware to check if token is blacklisted
function checkBlacklist(req, res, next) {
  const token = req.cookies.token;
  if (tokenBlacklist.has(token)) {
    return res.status(401).send('Token has been revoked');
  }
  next();
}

// Use the middleware for protected routes
app.use(checkBlacklist);
```

**Explanation:**

- **Blacklist Mechanism**: Keeps track of invalidated tokens.
- **Token Verification**: Middleware checks if the token is revoked before proceeding.

### **Considerations**

- **Scalability**: In-memory storage like a Set may not be suitable for distributed systems. Use a shared data store like Redis.
- **Performance**: Ensure that the blacklist lookup does not become a performance bottleneck.

---

## Including Sensitive Information in Token Payload

### **Vulnerable Code Example**

```jsx
// Token payload includes sensitive information
const token = jwt.sign(
  {
    userId: user.id,
    email: user.email,
    secretCode: user.secretCode, // Sensitive data
    role: user.role,
  },
  jwtSecret,
  { expiresIn: '1h' }
);
```

**Issue:**

- **Data Exposure**: JWT payloads are base64-encoded but not encrypted. Including sensitive data can expose it if the token is intercepted.

### **Mitigation**

Include only essential information in the token payload.

```jsx
// Minimal token payload
const token = jwt.sign(
  {
    userId: user.id,
    role: user.role,
  },
  jwtSecret,
  { expiresIn: '1h' }
);
```

**Explanation:**

- **Principle of Least Privilege**: Include only necessary information.
- **Data Minimization**: Reduces the risk of sensitive data exposure.

---

## Vulnerability to Cross-Site Request Forgery (CSRF)

Many developers believe that using JWTs eliminates the risk of CSRF attacks, especially when tokens are stored in client-side storage like `localStorage` or `sessionStorage`. However, CSRF vulnerabilities can still exist, particularly when JWTs are stored in cookies.

### **Why CSRF Can Still Occur with JWTs**

- **JWTs Stored in Cookies**: If the JWT is stored in a cookie, it will be sent automatically with every request to your domain.
- **Automatic Inclusion**: Browsers include cookies with requests, regardless of the origin.
- **State-Changing Requests**: Attackers can trick users into making unintended requests that the server processes as authenticated actions.

### **Example Scenario**

1. **User Authentication**: The user logs in, and the server sets a JWT in an HTTP-only cookie.
    
    ```jsx
    // Server-side: Setting the JWT in a cookie
    res.cookie('token', token, {
      httpOnly: true,
      secure: true,
      sameSite: 'Lax', // Controls cross-site requests
    });
    ```
    
2. **User Visits Malicious Site**: The user visits a malicious site while still authenticated.
3. **Forged Request**: The malicious site initiates a request to your application.
    
    ```html
    <!-- Malicious site's HTML -->
    <img src="<https://your-app.com/api/transfer-funds?amount=1000&toAccount=attackerAccount>" />
    
    ```
    
4. **Automatic Cookie Inclusion**: The browser includes the JWT cookie with the request.
5. **Server Processes Request**: The server validates the JWT and performs the action.

### **Mitigation Strategies**

1. **Use the `SameSite` Cookie Attribute**
    
    Set the `SameSite` attribute to `Strict` or `Lax` to control when cookies are sent.
    
    ```jsx
    res.cookie('token', token, {
      httpOnly: true,
      secure: true,
      sameSite: 'Strict', // Cookie sent only for same-site requests
    });
    ```
    
    **Explanation:**
    
    - **Strict Mode**: Prevents the cookie from being sent with cross-site requests entirely.
    - **Lax Mode**: Allows the cookie to be sent with top-level navigations but not with embedded content.
2. **Implement CSRF Tokens**
    
    Use CSRF tokens to verify the authenticity of state-changing requests.
    
    ```jsx
    const csrf = require('csurf');
    const cookieParser = require('cookie-parser');
    
    app.use(cookieParser());
    app.use(csrf({ cookie: true }));
    
    // In your routes
    app.get('/form', (req, res) => {
      res.render('form', { csrfToken: req.csrfToken() });
    });
    
    app.post('/process', (req, res) => {
      res.send('Data is being processed');
    });
    ```
    
    **Explanation:**
    
    - **CSRF Middleware**: Generates a unique token for each session.
    - **Token Verification**: The server verifies the token with each state-changing request.

### **Note on Storing JWTs**

- **Local Storage vs. Cookies**: Storing JWTs in local storage avoids CSRF but is vulnerable to XSS attacks.
- **HTTP-only Cookies**: Storing JWTs in HTTP-only cookies protects against XSS but requires CSRF protection.

# Input Validation Testing (WSTG-INPV)

Input validation is crucial for ensuring that all user-supplied data is properly validated, sanitized, and securely handled. Improper input validation can lead to various attacks such as SQL Injection, Cross-Site Scripting (XSS), and others. In this section, we will explore different aspects of input validation, discuss the importance of strict input validation schemes for each route, and highlight best practices such as triggering errors when unnecessary parameters are provided.

## Validate All User Input

It is imperative to never trust user input. Always validate and sanitize data coming from all possible sources, including:

- **Forms and APIs**
- **Query Parameters**
- **Headers and Cookies**
- **File Uploads**

Implementing comprehensive validation helps prevent malicious data from entering your system.

**Example using `express-validator`:**

```jsx
const { body, validationResult } = require('express-validator');

app.post(
  '/register',
  [
    body('username')
      .isAlphanumeric()
      .withMessage('Username must be alphanumeric'),
    body('email')
      .isEmail()
      .withMessage('Enter a valid email address'),
    body('password')
      .isLength({ min: 8 })
      .withMessage('Password must be at least 8 characters long'),
  ],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    // Proceed with registration
  }
);
```

**Explanation:**

- **Validation Middleware**: The `express-validator` library provides middleware for validating and sanitizing user input.
- **Custom Messages**: Providing specific error messages helps users correct their input.
- **Error Handling**: Always check for validation errors before processing the request.

## Sanitize and Escape Input

Sanitizing and escaping user input prevents injection attacks by removing or neutralizing malicious code.

**Example using `sanitize-html`:**

```jsx
const sanitizeHtml = require('sanitize-html');

app.post('/comment', (req, res) => {
  const sanitizedComment = sanitizeHtml(req.body.comment);
  // Save sanitizedComment to the database
  res.send('Comment submitted successfully');
});
```

**Explanation:**

- **Input Sanitization**: `sanitize-html` removes HTML tags and attributes that could be used for XSS attacks.
- **Data Integrity**: Ensures that only safe content is stored and displayed.

## Use Whitelisting Over Blacklisting

Defining exactly what is acceptable (whitelisting) is more secure than filtering out known bad input (blacklisting), as attackers may find ways around blacklists.

```jsx
const allowedRoles = ['admin', 'user', 'guest'];

body('role')
  .isIn(allowedRoles)
  .withMessage('Invalid user role');
```

**Explanation:**

- **Whitelisting**: Only allows predefined acceptable values.
- **Preventing Invalid Data**: Ensures that only recognized roles are assigned, preventing unauthorized access levels.

## Implement Parameterized Queries

Protect against SQL/NoSQL injection by using parameterized queries or Object-Relational Mapping (ORM) methods that handle input sanitization.

**Example using Mongoose (for MongoDB):**

```jsx
app.get('/user/:id', async (req, res) => {
  try {
    const user = await User.findById(req.params.id); // Mongoose handles input sanitization
    if (!user) {
      return res.status(404).send('User not found');
    }
    res.json(user);
  } catch (error) {
    res.status(500).send('An error occurred');
  }
});
```

**Explanation:**

- **Parameterized Queries**: By using methods like `findById`, input is properly handled, preventing injection attacks.
- **Error Handling**: Wrap database operations in try-catch blocks to handle exceptions gracefully.

## Handle File Uploads Securely

When accepting file uploads, validate file types and sizes, and store files securely to prevent malicious files from compromising your system.

**Example using `multer`:**

```jsx
const multer = require('multer');
const path = require('path');

const storage = multer.diskStorage({
  destination: 'uploads/',
  filename: (req, file, cb) => {
    // Use a unique filename to prevent overwriting
    cb(null, Date.now() + path.extname(file.originalname));
  },
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 1024 * 1024 }, // 1MB limit
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['image/png', 'image/jpeg', 'image/gif'];
    if (!allowedTypes.includes(file.mimetype)) {
      return cb(new Error('Only images are allowed'));
    }
    cb(null, true);
  },
});

app.post('/upload', upload.single('avatar'), (req, res) => {
  res.send('File uploaded successfully');
});
```

**Explanation:**

- **File Type Validation**: Only allows specific MIME types.
- **File Size Limit**: Prevents denial-of-service attacks by limiting file size.
- **Unique Filenames**: Avoids overwriting existing files and potential file path manipulation.

## Reject Unnecessary Parameters

Accepting extra parameters can introduce security risks. If unnecessary parameters are provided, respond with an error to enforce strict API contracts.

```jsx
function validateParams(allowedParams) {
  return (req, res, next) => {
    const extras = Object.keys(req.body).filter(
      key => !allowedParams.includes(key)
    );
    if (extras.length) {
      return res.status(400).send(`Unexpected parameters: ${extras.join(', ')}`);
    }
    next();
  };
}

app.post('/update', validateParams(['name', 'email']), (req, res) => {
  // Update logic
  res.send('User updated successfully');
});
```

**Explanation:**

- **Parameter Validation**: Ensures only expected parameters are processed.
- **Security**: Prevents attackers from exploiting unexpected parameters to manipulate data or system behavior.

## Common Vulnerabilities and How to Mitigate Them

### SQL/NoSQL Injection

- **Issue**: Malicious input alters database queries, potentially exposing or modifying sensitive data.
- **Mitigation**: Use ORM libraries or parameterized queries that properly handle input sanitization and prevent injection.

### Cross-Site Scripting (XSS)

- **Issue**: Attackers inject malicious scripts into web pages viewed by other users.
- **Mitigation**: Sanitize user input and encode output. Use templating engines that automatically escape variables, such as EJS, Pug, or Handlebars.

### Command Injection

- **Issue**: User input is used in system commands, allowing attackers to execute arbitrary commands on the server.
- **Mitigation**: Avoid executing system commands with user input. If necessary, validate and sanitize input thoroughly, and use safe APIs like `child_process.execFile` instead of `exec`.

### Unvalidated Redirects and Forwards

- **Issue**: Open redirects can be used in phishing attacks to trick users into visiting malicious sites.
- **Mitigation**: Validate URLs and use relative paths where possible. If redirects are necessary, maintain a whitelist of allowed URLs.

# Testing for Error Handling (WSTG-ERRH)

Proper error handling is crucial for both application security and user experience. It ensures that your application fails gracefully without exposing sensitive information that could be leveraged by attackers. Below are key considerations and best practices for error handling in Node.js applications.

## Use a Global Error Handler

Implement a centralized error-handling middleware to catch unhandled errors and prevent them from crashing your application.

```jsx
// Global error handler
app.use((err, req, res, next) => {
  // Log the error details internally
  console.error('Unhandled error:', err);

  // Send a generic error response to the client
  res.status(500).send('An unexpected error occurred');
});
```

**Explanation:**

- **Error Logging**: Internally log the error for debugging purposes without exposing details to the user.
- **Generic Error Messages**: Avoid revealing implementation details or stack traces in error responses.

## Handle Promise Rejections and Exceptions

Ensure that all asynchronous code has proper error handling to prevent unhandled promise rejections or exceptions that could crash the server.

### Common Mistake

```jsx
app.get('/data', (req, res) => {
  fetchDataFromAPI() // Returns a promise
    .then((data) => res.json(data));
  // Missing .catch() block to handle errors
});
```

**Issue:**

- If the promise rejects, the error is unhandled, potentially crashing the server.

### Correct Approach

Always handle promise rejections:

```jsx
app.get('/data', (req, res) => {
  fetchDataFromAPI()
    .then((data) => res.json(data))
    .catch((error) => {
      console.error('Error fetching data:', error);
      res.status(500).send('Failed to retrieve data');
    });
});
```

Or use async/await with try-catch blocks:

```jsx
app.get('/user/:id', async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).send('User not found');
    }
    res.json(user);
  } catch (error) {
    console.error('Error fetching user:', error);
    res.status(500).send('An unexpected error occurred');
  }
});
```

**Explanation:**

- **Error Handling in Promises**: Always include a `.catch()` method to handle rejections.
- **Try-Catch Blocks**: In async functions, use try-catch to handle exceptions.

## Use an Async Handler Wrapper

To reduce boilerplate code, you can use a wrapper function that handles exceptions in async route handlers.

**Example using `express-async-handler`:**

```jsx
const asyncHandler = require('express-async-handler');

app.get(
  '/user/:id',
  asyncHandler(async (req, res) => {
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).send('User not found');
    }
    res.json(user);
  })
);
```

**Explanation:**

- **Async Handler Middleware**: Automatically catches errors and passes them to the global error handler.
- **Cleaner Code**: Reduces repetitive try-catch blocks in route handlers.

## Avoid Exposing Sensitive Information

Never expose stack traces or detailed error messages to the client, as they may reveal sensitive information about your application's internals.

```jsx
// Vulnerable error response
app.use((err, req, res, next) => {
  res.status(500).send(err.stack); // Exposes stack trace
});
```

**Mitigation:**

- Send generic error messages to the client.
- Log detailed errors on the server side.

## Validate Input to Prevent Errors

Many runtime errors occur due to invalid input. Implement comprehensive input validation to prevent these errors from occurring.

```jsx
app.post(
  '/submit',
  [
    body('email').isEmail(),
    body('age').isInt({ min: 0 }),
  ],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    // Proceed with processing
  }
);
```

**Explanation:**

- **Preventative Measures**: Validating input reduces the likelihood of errors caused by unexpected data types or formats.
- **User Feedback**: Provides immediate feedback to users, improving user experience.

## Handle Uncaught Exceptions

Set up handlers for uncaught exceptions and unhandled promise rejections to prevent the application from crashing.

```jsx
process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
  // Consider exiting the process after handling
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
  // Consider exiting the process after handling
});
```

**Explanation:**

- **Global Exception Handling**: Captures errors that are not caught elsewhere.
- **Graceful Shutdown**: Allows the application to perform cleanup before exiting.

# Testing for Weak Cryptography (WSTG-CRYP)

Cryptography is essential for securing sensitive data in your Node.js applications. However, improper use of cryptographic functions can introduce vulnerabilities that compromise data confidentiality and integrity. In this section, we will explore common cryptographic weaknesses and provide best practices for addressing them.

## Insecure Use of the `crypto` Module

Improper use of the Node.js `crypto` module can lead to weak encryption or hashing mechanisms.

### **Vulnerable Code Example**

```jsx
const crypto = require('crypto');

// Insecure password hashing using SHA-1
function hashPassword(password) {
  return crypto.createHash('sha1').update(password).digest('hex');
}
```

**Why This Is a Problem**

- **Weak Algorithms**: SHA-1 and MD5 are considered insecure for hashing passwords due to vulnerabilities like collision attacks.
- **Lack of Salting and Iterations**: Simple hashes without salts or multiple iterations are susceptible to rainbow table attacks and can be cracked relatively easily.

### **Mitigation**

Use a dedicated password hashing library designed for security. Libraries like `bcrypt` incorporate salting and multiple iterations, making them resistant to brute-force and rainbow table attacks.

```jsx
const bcrypt = require('bcrypt');

// Secure password hashing with bcrypt
async function hashPassword(password) {
  const saltRounds = 12;
  return await bcrypt.hash(password, saltRounds);
}
```

**Best Practices**

- **Use Established Libraries**: Employ well-vetted cryptographic libraries for hashing and encryption.
- **Regular Updates**: Keep cryptographic libraries up-to-date to benefit from the latest security improvements.

## Hardcoding Secret Keys and Credentials

Storing secret keys, API keys, or credentials directly in your code is a critical security risk. If the codebase is ever exposed, these secrets can be compromised.

### **Vulnerable Code Example**

```jsx
// Hardcoded API key
const apiKey = '1234567890abcdef';

// Using the API key in a function
function callExternalService() {
  // Use the apiKey here
}
```

**Why This Is a Problem**

- **Exposure Risk**: Hardcoded secrets can be inadvertently exposed through code repositories or logs.
- **Difficult Rotation**: Updating or rotating secrets becomes cumbersome, increasing the risk of using outdated or compromised keys.

### **Mitigation**

Store secrets in environment variables or use a secrets management service.

```jsx
// Load API key from environment variables
const apiKey = process.env.API_KEY;

if (!apiKey) {
  throw new Error('API_KEY is not defined in environment variables');
}
```

**Best Practices**

- **Environment Variables**: Use environment variables for configuration, keeping secrets out of your codebase.
- **Secrets Management Services**: In production, utilize services like AWS Secrets Manager, Azure Key Vault, or HashiCorp Vault for secure secret storage and rotation.
- **Avoid Version Control**: Ensure that secret files like `.env` are not checked into version control systems.

---

## Insecure Random Number Generation

Using non-cryptographically secure random number generators for tokens, session identifiers, or security codes can lead to predictable values.

### **Vulnerable Code Example**

```jsx
// Insecure token generation using Math.random()
function generateToken() {
  return Math.random().toString(36).substring(2);
}
```

**Why This Is a Problem**

- **Predictable Output**: `Math.random()` is not designed for cryptographic purposes and can produce predictable results.
- **Token Guessing**: Attackers can exploit the predictability to guess tokens, leading to unauthorized access.

### **Mitigation**

Use `crypto.randomBytes()` or `crypto.randomInt()` for generating cryptographically secure random values.

```jsx
const crypto = require('crypto');

// Secure token generation
function generateToken() {
  return crypto.randomBytes(32).toString('hex'); // Generates a 256-bit token
}
```

**Explanation**

- **Cryptographically Secure**: `crypto.randomBytes()` provides high-quality random data suitable for security-sensitive applications.
- **Sufficient Entropy**: Using a 256-bit token significantly reduces the probability of token collisions or successful brute-force attacks.

---

## Storing Sensitive Data Without Encryption

Saving personal data, credentials, or sensitive information in plaintext in the database exposes it to potential breaches.

### **Vulnerable Code Example**

```jsx
// Storing plaintext sensitive data
const user = new User({
  username: req.body.username,
  password: req.body.password, // Plaintext password
  email: req.body.email,
});

await user.save();
```

**Why This Is a Problem**

- **Data Breach Exposure**: If the database is compromised, all sensitive data is accessible in cleartext.
- **Regulatory Non-Compliance**: Violates data protection regulations like GDPR or HIPAA, leading to legal consequences.

### **Mitigation**

Encrypt sensitive data before storing it, and securely hash passwords.

```jsx
const crypto = require('crypto');
const bcrypt = require('bcrypt');

// Encryption function for sensitive fields
function encrypt(text) {
  const algorithm = 'aes-256-cbc';
  const key = Buffer.from(process.env.ENCRYPTION_KEY, 'hex');
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(algorithm, key, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return iv.toString('hex') + ':' + encrypted;
}

// Storing encrypted data and securely hashed password
async function createUser(req, res) {
  const encryptedEmail = encrypt(req.body.email);
  const hashedPassword = await bcrypt.hash(req.body.password, 12);

  const user = new User({
    username: req.body.username,
    password: hashedPassword,
    email: encryptedEmail,
  });

  await user.save();
  res.send('User created successfully.');
}
```

**Best Practices**

- **Field-Level Encryption**: Encrypt sensitive fields individually, using strong encryption algorithms like AES-256.
- **Secure Key Management**: Store encryption keys securely, and rotate them periodically.
- **Hash Passwords**: Never store passwords in plaintext; use secure hashing algorithms with salting and multiple iterations.

---

## Weak Password Reset Implementations

Creating password reset tokens that are predictable, reusable, or do not expire can be exploited by attackers to gain unauthorized access.

### **Vulnerable Code Example**

```jsx
// Weak reset token generation
const resetToken = `${user.id}${Date.now()}`;

// Sending reset link
sendResetEmail(user.email, `https://example.com/reset/${resetToken}`);
```

**Why This Is a Problem**

- **Predictable Tokens**: Combining user ID and timestamp creates tokens that can be guessed or replicated by attackers.
- **No Expiration**: Tokens without an expiration remain valid indefinitely, increasing the window of opportunity for exploitation.
- **Token Reuse**: If tokens are not invalidated after use, they can be reused maliciously.

### **Mitigation**

Use secure, random tokens with expiration times, and ensure they are invalidated after use.

```jsx
const crypto = require('crypto');

// Generate secure reset token
function generateResetToken() {
  return crypto.randomBytes(32).toString('hex'); // 256-bit token
}

// Request password reset
app.post('/reset-password', async (req, res) => {
  const user = await User.findOne({ email: req.body.email });
  if (user) {
    const resetToken = generateResetToken();
    user.resetPasswordToken = crypto.createHash('sha256').update(resetToken).digest('hex');
    user.resetPasswordExpires = Date.now() + 3600000; // Token valid for 1 hour
    await user.save();

    // Send reset email with the plain token
    sendResetEmail(user.email, `https://example.com/reset/${resetToken}`);
  }
  res.send('If your email is registered, you will receive a password reset link.');
});

// Verify reset token and reset password
app.post('/reset/:token', async (req, res) => {
  const hashedToken = crypto.createHash('sha256').update(req.params.token).digest('hex');
  const user = await User.findOne({
    resetPasswordToken: hashedToken,
    resetPasswordExpires: { $gt: Date.now() },
  });
  if (!user) {
    return res.status(400).send('Invalid or expired token.');
  }
  user.password = await bcrypt.hash(req.body.password, 12);
  user.resetPasswordToken = undefined;
  user.resetPasswordExpires = undefined;
  await user.save();
  res.send('Password has been reset successfully.');
});
```

**Best Practices**

- **Secure Token Generation**: Use cryptographically secure random tokens.
- **Token Hashing**: Store a hash of the token in the database to prevent token theft from database leaks.
- **Token Expiration**: Set an expiration time to limit the token's validity period.
- **Single Use Tokens**: Invalidate the token after it's used to prevent reuse.

---

## Exposing Cryptographic Secrets in Logs

Logging sensitive information such as encryption keys, tokens, or passwords can lead to their exposure.

### **Vulnerable Code Example**

```jsx
console.log(`User ${user.id} logged in with token: ${token}`);
```

**Why This Is a Problem**

- **Log Access**: Logs may be accessible to unauthorized personnel or through log management systems.
- **Data Leakage**: Sensitive information in logs can be exploited if the logging system is compromised.

### **Mitigation**

Avoid logging sensitive data and implement proper logging practices.

```jsx
console.log(`User ${user.id} logged in successfully.`);
```

**Best Practices**

- **Sanitize Logs**: Ensure logs do not contain sensitive or personally identifiable information.
- **Secure Log Storage**: Protect log files with appropriate permissions and access controls.
- **Monitoring and Auditing**: Regularly review logs for suspicious activities while maintaining compliance with data protection regulations.

---

By carefully implementing cryptography and adhering to best practices, you can significantly enhance the security of your Node.js applications. Always use strong, up-to-date algorithms, manage keys securely, and ensure that sensitive data is properly encrypted both at rest and in transit.

# Business Logic Testing (WSTG-BUSL)

Business logic vulnerabilities are flaws in the design and implementation of an application that allow attackers to manipulate legitimate functionality to achieve unintended outcomes. These vulnerabilities arise from the way the application handles data and processes, often slipping past automated scanners because they require an understanding of the application's logic.

In this section, we will explore common business logic vulnerabilities in Node.js applications, provide practical examples, and discuss how to prevent them.

## Abuse of Bulk Operations Leading to Denial of Service

Attackers may exploit bulk operations to overwhelm the system, causing performance degradation or crashes.

### **Vulnerable Code Example**

```jsx
// Route to export data without restrictions
app.get('/export-data', async (req, res) => {
  const data = await Data.find(); // Fetches all records without limits
  res.json(data);
});
```

**Issue**

- **Unrestricted Data Retrieval**: Allowing users to fetch all data at once can lead to excessive memory usage and server strain.
- **Denial of Service (DoS)**: Attackers can exploit this to overload the server, causing legitimate requests to fail.

### **Mitigation**

Implement pagination and enforce limits on data retrieval to prevent resource exhaustion.

```jsx
// Secure route to export data with pagination and limits
app.get('/export-data', async (req, res) => {
  const { page = 1, limit = 100 } = req.query;

  // Enforce maximum limit to prevent excessive data retrieval
  const maxLimit = 1000;
  const safeLimit = Math.min(parseInt(limit), maxLimit);

  const data = await Data.find()
    .skip((page - 1) * safeLimit)
    .limit(safeLimit);

  res.json(data);
});
```

**Best Practices**

- **Input Validation**: Validate and sanitize query parameters.
- **Rate Limiting**: Implement rate limiting to prevent abuse of endpoints.
- **Monitoring**: Keep an eye on system metrics to detect unusual activity.

---

## Account Takeover Through Logic Flaws

Attackers may exploit weaknesses in account linking or merging functionalities to gain unauthorized access to other users' accounts.

### **Vulnerable Code Example**

```jsx
// Route to link social media account without proper verification
app.post('/link-account', async (req, res) => {
  const { socialMediaId } = req.body;

  // Link account without verifying ownership
  await User.updateOne({ _id: req.user.id }, { socialMediaId });

  res.send('Account linked successfully.');
});
```

**Issue**

- **No Ownership Verification**: The application does not verify that the user actually owns the social media account they are linking.
- **Account Takeover**: Attackers can link their account to another user's social media ID, gaining unauthorized access.

### **Mitigation**

Implement verification steps to confirm ownership of the social media account before linking it.

```jsx
// Secure route to link social media account with verification
app.post('/link-account', async (req, res) => {
  const { socialMediaToken } = req.body;

  // Verify token with the social media API to confirm ownership
  const socialMediaId = await verifySocialMediaToken(socialMediaToken);
  if (!socialMediaId) {
    return res.status(400).send('Invalid social media token.');
  }

  // Check if the social media account is already linked
  const existingUser = await User.findOne({ socialMediaId });
  if (existingUser) {
    return res.status(400).send('Social media account already linked to another user.');
  }

  // Link the social media account to the authenticated user
  await User.updateOne({ _id: req.user.id }, { socialMediaId });

  res.send('Social media account linked successfully.');
});
```

**Best Practices**

- **Ownership Verification**: Always verify ownership of external accounts through secure tokens or APIs.
- **Uniqueness Constraints**: Ensure that each social media account can only be linked to a single user.
- **Error Handling**: Provide informative yet secure error messages to guide users without revealing sensitive information.

---

## Privilege Escalation via Faulty Email Domain Validation

Applications that grant elevated privileges based on email domains must ensure proper validation to prevent attackers from exploiting this mechanism.

### **Vulnerable Code Example**

```jsx
// Route to register a new user with flawed email validation
app.post('/register', async (req, res) => {
  const { email, password } = req.body;

  // Incorrect validation: checks if email contains '@company.com' anywhere
  if (email.includes('@company.com')) {
    // Assign admin role
    const user = new User({
      email,
      password: await hashPassword(password),
      role: 'admin',
    });
    await user.save();
  } else {
    // Assign regular user role
    const user = new User({
      email,
      password: await hashPassword(password),
      role: 'user',
    });
    await user.save();
  }

  res.send('Registration successful.');
});
```

**Issue**

- **Improper Email Validation**: An attacker can use an email like `admin@company.com@attacker.com` to bypass the check.
- **Unauthorized Privilege Escalation**: Attackers gain admin privileges without legitimate authorization.

### **Mitigation**

Implement proper email validation to ensure that only the domain part of the email is used for privilege assignment.

```jsx
// Secure route to register a new user with proper email domain validation
app.post('/register', async (req, res) => {
  const { email, password } = req.body;

  // Validate the email format
  const emailRegex = /^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).send('Invalid email address.');
  }

  // Extract and normalize the domain from the email
  const emailDomain = email.split('@')[1].toLowerCase();

  // Check if the email domain matches exactly 'company.com'
  if (emailDomain === 'company.com') {
    // Assign admin role
    const user = new User({
      email,
      password: await hashPassword(password),
      role: 'admin',
    });
    await user.save();
  } else {
    // Assign regular user role
    const user = new User({
      email,
      password: await hashPassword(password),
      role: 'user',
    });
    await user.save();
  }

  res.send('Registration successful.');
});
```

**Best Practices**

- **Strict Email Validation**: Use robust regex patterns or validation libraries to validate email addresses.
- **Domain Verification**: Ensure that domain comparisons are exact and case-insensitive.
- **Additional Verification Steps**: Consider sending a verification email to the address to confirm ownership before assigning elevated privileges.

# Client-side Testing (WSTG-CLNT)

Client-side testing focuses on identifying vulnerabilities that can be exploited within the user's browser. These vulnerabilities can lead to unauthorized access, data theft, or manipulation of client-side logic. It's crucial to understand these risks and implement measures to mitigate them effectively.

## Cross-Site Scripting (XSS)

Cross-Site Scripting (XSS) is one of the most common client-side vulnerabilities. It occurs when an attacker injects malicious scripts into webpages viewed by other users. There are three main types of XSS attacks: Stored XSS, Reflected XSS, and DOM-based XSS.

### **Example of Reflected XSS**

Consider a simple Express.js route that renders user input without proper sanitization:

```jsx
app.get('/search', (req, res) => {
  const query = req.query.q;
  res.send(`<h1>Search Results for "${query}"</h1>`);
});
```

**Issue:**

- **Unsanitized Input**: The `query` parameter is directly inserted into the HTML response without any sanitization, allowing attackers to inject malicious scripts.

An attacker could craft a URL like:

```
<http://localhost:3000/search?q=><script>alert('XSS')</script>

```

When a user visits this URL, the script tag is rendered and executed in the user's browser.

### **Mitigation Strategies**

1. **Sanitize User Input**
    
    Use libraries to sanitize input and prevent script injection.
    
    ```jsx
    const escape = require('escape-html');
    
    app.get('/search', (req, res) => {
      const query = escape(req.query.q);
      res.send(`<h1>Search Results for "${query}"</h1>`);
    });
    ```
    
2. **Use Templating Engines with Auto-Escaping**
    
    Use a templating engine like EJS, Pug, or Handlebars that automatically escapes output.
    
    ```jsx
    // Using EJS
    app.set('view engine', 'ejs');
    
    app.get('/search', (req, res) => {
      const query = req.query.q;
      res.render('search', { query });
    });
    ```
    
    **In `search.ejs` template:**
    
    ```html
    <h1>Search Results for "<%= query %>"</h1> 
    ```
    
    EJS escapes special characters by default, preventing XSS attacks.
    
3. **Content Security Policy (CSP)**
    
    Implement CSP headers to restrict sources of executable scripts.
    
    ```jsx
    const helmet = require('helmet');
    app.use(
      helmet.contentSecurityPolicy({
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'"],
          objectSrc: ["'none'"],
          upgradeInsecureRequests: [],
        },
      })
    );
    ```
    

**Explanation:**

- **Auto-Escaping**: Templating engines escape user input, rendering it harmless.
- **CSP**: Adds an extra layer of security by restricting script sources.

---

## Clickjacking

Clickjacking involves tricking users into clicking on something different from what they perceive, potentially leading to unauthorized actions.

### **Example Scenario**

An attacker embeds your website in an invisible iframe and overlays it with their own content. When users interact with the page, they unknowingly perform actions on your site.

### **Mitigation Strategies**

1. **Set X-Frame-Options Header**
    
    Prevent your site from being embedded in iframes.
    
    ```jsx
    app.use(helmet.frameguard({ action: 'deny' }));
    ```
    
2. **Use Content Security Policy**
    
    Specify that your site should not be framed.
    
    ```jsx
    app.use(
      helmet.contentSecurityPolicy({
        directives: {
          frameAncestors: ["'none'"],
        },
      })
    );
    ```
    

**Explanation:**

- **X-Frame-Options**: Instructs the browser not to allow framing of your content.
- **CSP `frame-ancestors`**: Defines valid sources that can embed your content.

---

## DOM-based Vulnerabilities

DOM-based vulnerabilities occur when client-side scripts manipulate the DOM based on untrusted input, potentially leading to XSS attacks.

### **Example of Insecure DOM Manipulation**

```jsx
// In client-side JavaScript
const userInput = location.search.substring(1);
document.getElementById('output').innerHTML = userInput;
```

**Issue:**

- **Unsanitized Input**: Directly inserting user-controlled input into the DOM using `innerHTML` can execute malicious scripts.

### **Mitigation Strategies**

1. **Use `textContent` or `innerText`**
    
    ```jsx
    const params = new URLSearchParams(window.location.search);
    const userInput = params.get('input');
    document.getElementById('output').textContent = userInput;
    ```
    
    - **`textContent`** safely inserts text without parsing HTML.
2. **Sanitize Input**
    
    Use a client-side sanitization library.
    
    ```jsx
    const DOMPurify = require('dompurify');
    
    const userInput = location.search.substring(1);
    const sanitizedInput = DOMPurify.sanitize(userInput);
    document.getElementById('output').innerHTML = sanitizedInput;
    ```
    

**Explanation:**

- **Avoid `innerHTML` with Untrusted Data**: Prevents execution of injected scripts.
- **Sanitization**: Removes or neutralizes malicious content.

---

## Insecure Use of `eval()`

Using `eval()` or similar functions with untrusted input can execute arbitrary code, leading to serious security issues.

### **Example of Dangerous `eval()` Use**

```jsx
app.get('/calculate', (req, res) => {
  const expression = req.query.expression;
  const result = eval(expression);
  res.send(`Result: ${result}`);
});
```

**Issue:**

- **Code Execution**: An attacker can execute arbitrary code on your server.

Example attack:

```
/calculate?expression=process.exit()
```

### **Mitigation Strategies**

1. **Avoid `eval()`**
    
    Do not use `eval()` on untrusted input.
    
2. **Use Safe Evaluation Libraries**
    
    Use libraries that safely evaluate expressions.
    
    ```jsx
    const { evaluate } = require('mathjs');
    
    app.get('/calculate', (req, res) => {
      const expression = req.query.expression;
      try {
        const result = evaluate(expression);
        res.send(`Result: ${result}`);
      } catch (error) {
        res.status(400).send('Invalid expression');
      }
    });
    ```
    

**Explanation:**

- **Safe Parsing**: Libraries like `mathjs` parse and evaluate mathematical expressions securely.
- **Error Handling**: Catch exceptions to prevent crashes and provide user feedback.

---

## Exposing Sensitive Data in Client-side Code

Including secrets such as API keys in client-side code exposes them to anyone who inspects your website's source code.

### **Example of Exposed API Key**

```jsx
// In client-side JavaScript
const apiKey = 'YOUR_SECRET_API_KEY';

fetch(`https://api.example.com/data?apiKey=${apiKey}`)
  .then(response => response.json())
  .then(data => {
    // Process data
  });
```

**Issue:**

- **API Key Exposure**: Attackers can use the exposed API key to access or manipulate your backend services.

### **Mitigation Strategies**

1. **Move API Calls to Server-side**
    
    Handle API requests on the server, keeping secrets secure.
    
    ```jsx
    // Client-side code
    fetch('/api/data')
      .then(response => response.json())
      .then(data => {
        // Process data
      });
    
    ```
    
    ```jsx
    // Server-side code
    app.get('/api/data', async (req, res) => {
      try {
        const response = await fetch(`https://api.example.com/data?apiKey=${process.env.API_KEY}`);
        const data = await response.json();
        res.json(data);
      } catch (error) {
        res.status(500).send('Error fetching data');
      }
    });
    ```
    
2. **Use Environment Variables**
    
    Store secrets in environment variables, not in code.
    

**Explanation:**

- **Server-side Protection**: Keeps API keys hidden from the client.
- **Secure Storage**: Environment variables prevent secrets from being exposed in version control.

---

## Implement Content Security Policy (CSP)

A Content Security Policy helps mitigate XSS attacks by restricting the sources from which content can be loaded.

### **Setting Up CSP with Helmet**

```jsx
const helmet = require('helmet');

app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", 'trusted-cdn.com'],
      styleSrc: ["'self'", 'trusted-cdn.com'],
      imgSrc: ["'self'", 'images.com'],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: [],
    },
  })
);
```

**Explanation:**

- **Restricts Sources**: Defines allowed content sources for scripts, styles, images, etc.
- **Blocks Unauthorized Content**: Prevents loading of malicious scripts from untrusted sources.

---

## Additional Best Practices

- **Use HTTPS Everywhere**: Encrypt communication to prevent man-in-the-middle attacks.
- **Input Validation**: Validate and sanitize all user input on both client and server sides.
- **Keep Libraries Updated**: Regularly update client-side libraries to patch known vulnerabilities.
- **Avoid Inline Scripts**: Use external script files to adhere to CSP rules.

---

# API Testing (WSTG-APIT)

API testing focuses on identifying vulnerabilities in your application's API endpoints. APIs often expose sensitive data and functionality, making them attractive targets for attackers. Ensuring the security of your APIs is crucial for protecting your application's integrity and user data.

## GraphQL-Specific Vulnerabilities

GraphQL APIs introduce unique challenges and potential vulnerabilities, including:

- **Introspection Enabled in Production**
- **Unrestricted Query Depth Leading to Denial of Service**
- **Authorization Bypass**

### **GraphQL Introspection Enabled**

GraphQL's introspection feature allows clients to query the schema for types and fields, which is helpful during development. However, leaving introspection enabled in production can expose sensitive schema information to attackers.

### **Issue**

An attacker can send an introspection query:

```graphql
{
  __schema {
    types {
      name
      fields {
        name
      }
    }
  }
}
```

This reveals detailed information about your API's schema, aiding attackers in crafting targeted attacks.

### **Mitigation Strategies**

1. **Disable Introspection in Production**
    
    ```jsx
    const { ApolloServer } = require('apollo-server');
    
    const server = new ApolloServer({
      typeDefs,
      resolvers,
      introspection: process.env.NODE_ENV !== 'production',
    });
    ```
    
2. **Use Whitelisting**
    
    Only allow specific queries and mutations.
    
3. **Schema Stitching**
    
    Expose only necessary parts of the schema.
    

**Explanation:**

- **Restricting Introspection**: Prevents attackers from discovering your API's structure.
- **Environment-Based Configuration**: Disables introspection based on the environment.

---

### **Unrestricted Query Depth Leading to Denial of Service**

GraphQL allows clients to construct complex queries. Without limitations, attackers can create deeply nested queries that consume excessive server resources.

### **Issue**

Example of a malicious query:

```graphql
query {
  user(id: "1") {
    friends {
      friends {
        friends {
          # ...continues indefinitely
        }
      }
    }
  }
}
```

- **Resource Exhaustion**: Server CPU and memory are overwhelmed.
- **Service Disruption**: Legitimate users experience slow responses or outages.

### **Mitigation Strategies**

1. **Limit Query Depth**
    
    Use `graphql-depth-limit`:
    
    ```jsx
    const depthLimit = require('graphql-depth-limit');
    
    const server = new ApolloServer({
      typeDefs,
      resolvers,
      validationRules: [depthLimit(5)],
    }); 
    ```
    
2. **Complexity Analysis**
    
    Use `graphql-validation-complexity`:
    
    ```jsx
    const { createComplexityLimitRule } = require('graphql-validation-complexity');
    
    const complexityLimitRule = createComplexityLimitRule(1000);
    
    const server = new ApolloServer({
      typeDefs,
      resolvers,
      validationRules: [complexityLimitRule],
    });
    ```
    

**Explanation:**

- **Query Depth Limiting**: Prevents overly deep queries that can cause stack overflows.
- **Complexity Limiting**: Assigns a cost to queries and blocks those exceeding a threshold.

---

### **Authorization Bypass**

Improper implementation of authorization checks can allow users to access or manipulate data they shouldn't.

### **Vulnerable Code Example**

```jsx
const resolvers = {
  Query: {
    user: async (_, { id }) => {
      return await User.findById(id);
    },
  },
};
```

**Issue:**

- **No Authorization Check**: Any authenticated user can access any user's data by specifying their `id`.

### **Mitigation Strategies**

1. **Implement Authorization Checks**
    
    ```jsx
    const { AuthenticationError, ForbiddenError } = require('apollo-server');
    
    const resolvers = {
      Query: {
        user: async (_, { id }, { user }) => {
          if (!user) {
            throw new AuthenticationError('You must be logged in');
          }
          if (user.id !== id && user.role !== 'admin') {
            throw new ForbiddenError('Not authorized');
          }
          return await User.findById(id);
        },
      },
    };
    ```
    
2. **Use Middleware**
    
    Apply authentication and authorization logic through middleware.
    

**Explanation:**

- **Context-Based Security**: Access the authenticated user from the context and enforce permissions.
- **Error Handling**: Provide appropriate error messages without revealing sensitive information.

---

## Excessive Data Exposure

APIs may return more data than necessary, revealing sensitive information.

### **Vulnerable Code Example**

```jsx
app.get('/api/users/:id', async (req, res) => {
  const user = await User.findById(req.params.id);
  res.json(user);
});
```

**Issue:**

- **Sensitive Data Exposure**: Returns all user fields, including password hashes or tokens.

### **Mitigation Strategies**

1. **Explicitly Select Fields**
    
    ```jsx
    app.get('/api/users/:id', async (req, res) => {
      const user = await User.findById(req.params.id).select('username email');
      res.json(user);
    });
    ```
    
2. **Use DTOs (Data Transfer Objects)**
    
    Map database models to DTOs that contain only necessary fields.
    

**Explanation:**

- **Field Selection**: Limits data exposure to only what is needed.
- **Data Mapping**: Separates internal data structures from API responses.

---

## Mass Assignment Vulnerabilities

Allowing users to update object properties directly can lead to unauthorized modifications.

### **Vulnerable Code Example**

```jsx
app.put('/api/users/:id', async (req, res) => {
  const updatedUser = await User.findByIdAndUpdate(req.params.id, req.body, { new: true });
  res.json(updatedUser);
});
```

**Issue:**

- **Uncontrolled Updates**: Users can modify protected fields like `role`, `password`, or `isAdmin`.

### **Mitigation Strategies**

1. **Whitelist Allowed Fields**
    
    ```jsx
    app.put('/api/users/:id', async (req, res) => {
      const allowedUpdates = ['email', 'username'];
      const updates = {};
      for (const key of allowedUpdates) {
        if (req.body.hasOwnProperty(key)) {
          updates[key] = req.body[key];
        }
      }
      const updatedUser = await User.findByIdAndUpdate(req.params.id, updates, { new: true });
      res.json(updatedUser);
    });
    ```
    
2. **Use Mongoose Schema Options**
    
    Set `select: false` on sensitive fields and use `Schema.methods` for updates.
    

**Explanation:**

- **Controlled Updates**: Ensures only intended fields are updated.
- **Security**: Prevents unauthorized changes to critical fields.

---

## Lack of Rate Limiting

APIs without rate limiting are vulnerable to brute-force attacks, resource exhaustion, and abuse.

### **Mitigation Strategies**

1. **Implement Rate Limiting**
    
    Use middleware to limit the number of requests per IP address.
    
    ```jsx
    const rateLimit = require('express-rate-limit');
    
    const apiLimiter = rateLimit({
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 100, // Limit each IP to 100 requests per windowMs
      message: 'Too many requests from this IP, please try again later.',
    });
    
    app.use('/api/', apiLimiter);
    ```
    
2. **Use API Gateways or WAFs**
    
    Employ API gateways or Web Application Firewalls that provide rate limiting and DDoS protection.
    

**Explanation:**

- **Prevents Abuse**: Controls the flow of incoming requests to protect resources.
- **Improves Stability**: Helps maintain service availability during high traffic.

---

## Inadequate Input Validation

Failing to validate input can lead to injection attacks and other vulnerabilities.

### **Mitigation Strategies**

1. **Validate and Sanitize Input**
    
    Use validation libraries like `Joi` or `express-validator`.
    
    ```jsx
    const { body, validationResult } = require('express-validator');
    
    app.post('/api/users', [
      body('email').isEmail(),
      body('username').isAlphanumeric().isLength({ min: 3 }),
    ], (req, res) => {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
      }
      // Proceed with creating the user
    });
    ```
    
2. **Use Parameterized Queries**
    
    Prevent SQL/NoSQL injection by using parameterized queries or ORM methods.
    

**Explanation:**

- **Input Validation**: Ensures data integrity and security.
- **Injection Prevention**: Protects against injection attacks by handling input safely.

---

## Insufficient Logging and Monitoring

Without proper logging and monitoring, attacks may go unnoticed.

### **Mitigation Strategies**

1. **Implement Logging**
    
    Log important events, errors, and security-related information.
    
    ```jsx
    const winston = require('winston');
    
    const logger = winston.createLogger({
      level: 'info',
      format: winston.format.json(),
      transports: [
        new winston.transports.File({ filename: 'combined.log' }),
      ],
    });
    
    app.use((req, res, next) => {
      logger.info(`${req.method} ${req.url}`);
      next();
    });
    ```
    
2. **Set Up Monitoring and Alerts**
    
    Use monitoring tools to track application performance and security events.
    

**Explanation:**

- **Proactive Detection**: Allows for early detection and response to security incidents.
- **Compliance**: Helps meet regulatory requirements for logging.

# Conclusion

Securing web applications requires a comprehensive approach that addresses multiple layers of potential vulnerabilities. Throughout this guide, we've explored critical areas of web security, aligning with the OWASP Web Security Testing Guide (WSTG):

**Key Takeaways:**

- **Defense in Depth**: Security should be implemented at every layer, from input validation to session management.
- **Regular Updates and Patching**: Keep dependencies and libraries up-to-date to mitigate known vulnerabilities.
- **Least Privilege Principle**: Users and services should have the minimum level of access required to perform their functions.
- **Secure Defaults**: Configure systems to be secure out of the box, requiring explicit changes to reduce security.
- **Continuous Monitoring and Testing**: Regularly perform security assessments and update practices based on new threats.
- **Education and Awareness**: Ensure that development teams are knowledgeable about security best practices and emerging threats.

By staying informed and continuously applying best practices, you contribute to a more secure web ecosystem. Remember that security is an ongoing process that evolves with emerging threats and technologies. Regularly revisiting and updating your security measures is essential to protect your applications and users effectively.

# About
This guide was authored by [**Alex Rozhniatovskyi**](https://www.linkedin.com/in/oleksii-rozhniatovskyi/), the CTO of **Sekurno**. With over 7 years of experience in development and cybersecurity, Alex is an AWS Open-source Contributor dedicated to advancing secure coding practices. His expertise bridges the gap between software development and security, providing valuable insights into protecting modern web applications.

[Sekurno](https://sekurno.com) is a leading cybersecurity company specializing in **Penetration Testing** and **Application Security**. At Sekurno Cybersecurity, we dedicate all our efforts to reducing risks to the highest extent, ensuring High-Risk Industries and Enterprise-SaaS businesses stand resilient against any threat. You can contact us by scheduling a meeting at the website (https://sekurno.com) or by writing to us at team@sekurno.com.

<img src="images/sekurno.png" width="140px" height="140px">

# Further Reading

To deepen your understanding of web application security and stay updated on best practices, consider exploring the following resources:

- **OWASP Web Security Testing Guide (WSTG)**: Comprehensive guide covering a wide range of web security testing methodologies. [OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/)
- **Node.js Security Guide**: Best practices and recommendations for securing Node.js applications. [Node.js Security Guide](https://nodejs.org/en/docs/guides/security/)
- **Express.js Security Tips**: Guidelines for enhancing security in Express applications. [Express Security Best Practices](https://expressjs.com/en/advanced/best-practice-security.html)
- **GraphQL Security Best Practices**: Strategies for securing GraphQL APIs. [Apollo GraphQL Security](https://www.apollographql.com/docs/apollo-server/security/security/)
- **Cheat Sheets by OWASP**: Practical guides on various security topics, including authentication, authorization, input validation, and more. [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)