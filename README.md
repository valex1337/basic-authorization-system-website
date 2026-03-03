 
# basic-authorization-system-website

# SecureAuth Node Logic

This project is a security-focused authentication system built with Node.js and Express. It serves as a practical implementation of defensive programming to mitigate common web vulnerabilities.

## Technical Details
The application is built on the **Node.js** runtime using the **Express** web framework to manage routing and HTTP request handling. Data persistence is managed by a lightweight **SQLite3** database, where all user interactions are performed using parameterized queries to ensure complete immunity against SQL injection attacks. 



Account security is handled by the **Bcrypt** library, which performs robust password hashing with salt, while session management is implemented through **JSON Web Tokens (JWT)**. To prevent automated brute-force attacks, the system integrates **Express-Rate-Limit** middleware to restrict request frequency. System configurations, such as the server port and secret keys, are decoupled from the source code and loaded via **Dotenv**, preventing sensitive data leaks during version control.



## Security Features
* **Brute-Force Mitigation:** IP-based rate limiting (5 attempts per 15 minutes).
* **Anti-Enumeration:** Unified error responses for failed logins to hide user existence.
* **Credential Safety:** Industry-standard hashing and salting for all passwords.
* **Environment Protection:** Use of .env files for sensitive configuration.

## Setup
1. Run `npm install` to download dependencies.
2. Create a `.env` file based on the `cfg.env` template.
3. Run `node server.js` to start the application.

Development Context
This project was developed as part of a portfolio for future studies in cybersecurity. The development process involved using AI tools for initial prototyping and debugging, followed by manual adjustments to implement specific security patches and logical improvements.
