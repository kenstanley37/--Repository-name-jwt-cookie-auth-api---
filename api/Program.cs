using api.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace api
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // 1) Add MVC controllers
            builder.Services.AddControllers();

            // 2) Guarded configuration reads
            var jwtKey = builder.Configuration["Jwt:Key"]
                                ?? throw new InvalidOperationException("Jwt:Key is not configured");
            var issuer = builder.Configuration["Jwt:Issuer"]
                                ?? throw new InvalidOperationException("Jwt:Issuer is not configured");
            var audience = builder.Configuration["Jwt:Audience"]
                                ?? throw new InvalidOperationException("Jwt:Audience is not configured");
            var expiresText = builder.Configuration["Jwt:ExpiresInMinutes"]
                                ?? throw new InvalidOperationException("Jwt:ExpiresInMinutes is not configured");

            // 3) Pre-compute key bytes once
            var keyBytes = Encoding.UTF8.GetBytes(jwtKey);
            var signingKey = new SymmetricSecurityKey(keyBytes);

            // 4) Configure Authentication & JWT Bearer
            builder.Services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddJwtBearer(options =>
            {
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = signingKey,
                    ValidateIssuer = true,
                    ValidIssuer = issuer,
                    ValidateAudience = true,
                    ValidAudience = audience,
                    ValidateLifetime = true
                };

                options.Events = new JwtBearerEvents
                {
                    OnMessageReceived = context =>
                    {
                        context.Token = context.Request.Cookies["jwt"];
                        return Task.CompletedTask;
                    }
                };
            });

            // 5) In-memory refresh token store
            builder.Services.AddSingleton<List<RefreshToken>>();

            // 6) OpenAPI / Swagger
            builder.Services.AddOpenApi();
            builder.Services.AddEndpointsApiExplorer();
            builder.Services.AddSwaggerGen();

            var app = builder.Build();

            // 7) Middleware pipeline
            if (app.Environment.IsDevelopment())
            {
                app.MapOpenApi();
            }

            app.UseHttpsRedirection();

            // IMPORTANT: Authentication must come before Authorization
            app.UseAuthentication();
            app.UseAuthorization();

            app.MapControllers();
            app.Run();
        }
    }
}