# JWT Cookie Auth API (.NET 9)

A secure .NET 9 Web API using JWT authentication stored in HttpOnly cookies and refresh tokens. Built for modern single-page apps like Angular.

## 🔐 Features

- Login issues a short-lived JWT (access token) and long-lived refresh token
- Tokens stored in secure HttpOnly cookies
- Protected endpoints via [Authorize]
- Refresh endpoint for silent re-authentication
- Logout clears both cookies
- Swagger UI available at `/swagger`

## 🚀 Getting Started

Clone the repo and set up your secrets:

```bash
git clone https://github.com/your-username/jwt-cookie-auth-api.git
cd jwt-cookie-auth-api
cp appsettings.example.json appsettings.json


![Build](https://github.com/kenstanley37/jwt-cookie-auth-api/actions/workflows/dotnet.yml/badge.svg)