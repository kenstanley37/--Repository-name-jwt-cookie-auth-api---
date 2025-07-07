# JWT Cookie Auth API (.NET 9)

A secure Web API built with .NET 9 using JWT authentication stored in HttpOnly cookies and refresh tokens. Designed for modern frontends like Angular or React.

## 🔐 Features

- Login with JWT issued in HttpOnly cookie
- Refresh token support
- Secure cookie handling with CORS
- Swagger UI at `/swagger`
- GitHub Actions CI/CD with Docker publishing

## 🚀 Getting Started

Clone & configure:

```bash
git clone https://github.com/kenstanley37/jwt-cookie-auth-api.git
cd jwt-cookie-auth-api/api
cp appsettings.example.json appsettings.json