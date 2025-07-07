# JWT Cookie Auth API (.NET 9)

A secure .NET 9 Web API using JWT authentication stored in HttpOnly cookies. Ideal for SPAs and modern frontend frameworks.

## Features
- JWT token issued via login endpoint
- Token stored in HttpOnly cookie
- Protected routes using [Authorize]
- Logout endpoint clears cookie

## Getting Started
```bash
dotnet restore
dotnet run
