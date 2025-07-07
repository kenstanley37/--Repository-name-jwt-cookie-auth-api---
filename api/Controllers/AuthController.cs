using api.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;


namespace api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration _config;
        private readonly List<RefreshToken> _refreshTokens;

        public AuthController(IConfiguration config, List<RefreshToken> refreshTokens)
        {
            _config = config;
            _refreshTokens = refreshTokens;
        }

        [HttpPost("login")]
        public IActionResult Login([FromBody] LoginModel model)
        {
            if (model.Username == "admin" && model.Password == "password")
            {
                // Guard and fetch config values
                var keyText = _config["Jwt:Key"]
                    ?? throw new InvalidOperationException("Jwt:Key not configured");
                var issuer = _config["Jwt:Issuer"]
                    ?? throw new InvalidOperationException("Jwt:Issuer not configured");
                var audience = _config["Jwt:Audience"]
                    ?? throw new InvalidOperationException("Jwt:Audience not configured");
                var expiresText = _config["Jwt:ExpiresInMinutes"]
                    ?? throw new InvalidOperationException("Jwt:ExpiresInMinutes not configured");

                var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(keyText));
                var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

                var claims = new[] { new Claim(ClaimTypes.Name, model.Username) };
                var expiresIn = TimeSpan.FromMinutes(double.Parse(expiresText));

                var jwtToken = new JwtSecurityToken(
                    issuer: issuer,
                    audience: audience,
                    claims: claims,
                    expires: DateTime.UtcNow.Add(expiresIn),
                    signingCredentials: creds);

                var tokenString = new JwtSecurityTokenHandler().WriteToken(jwtToken);

                // Set cookies
                Response.Cookies.Append("jwt", tokenString, new CookieOptions
                {
                    HttpOnly = true,
                    Secure = true,
                    SameSite = SameSiteMode.Strict,
                    Expires = DateTimeOffset.UtcNow.Add(expiresIn)
                });

                var refreshToken = new RefreshToken
                {
                    Token = Guid.NewGuid().ToString(),
                    Username = model.Username,
                    Expires = DateTime.UtcNow.AddDays(7),
                    IsRevoked = false
                };
                _refreshTokens.Add(refreshToken);

                Response.Cookies.Append("refreshToken", refreshToken.Token, new CookieOptions
                {
                    HttpOnly = true,
                    Secure = true,
                    SameSite = SameSiteMode.Strict,
                    Expires = refreshToken.Expires
                });

                return Ok(new { message = "Logged in" });
            }

            return Unauthorized();
        }

        [HttpPost("refresh")]
        public IActionResult Refresh()
        {
            var rt = Request.Cookies["refreshToken"]
                ?? throw new InvalidOperationException("Refresh token cookie missing");
            var storedToken = _refreshTokens
                .FirstOrDefault(t => t.Token == rt && !t.IsRevoked && t.Expires > DateTime.UtcNow);

            if (storedToken == null)
                return Unauthorized();

            storedToken.IsRevoked = true;

            var keyText = _config["Jwt:Key"]!;
            var issuer = _config["Jwt:Issuer"]!;
            var audience = _config["Jwt:Audience"]!;

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(keyText));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var claims = new[] { new Claim(ClaimTypes.Name, storedToken.Username) };

            var jwtToken = new JwtSecurityToken(
                issuer: issuer,
                audience: audience,
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(15),
                signingCredentials: creds);

            var tokenString = new JwtSecurityTokenHandler().WriteToken(jwtToken);
            Response.Cookies.Append("jwt", tokenString, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Expires = DateTimeOffset.UtcNow.AddMinutes(15)
            });

            return Ok(new { message = "Token refreshed" });
        }

        [Authorize]
        [HttpGet("secure-data")]
        public IActionResult GetSecureData() =>
            Ok("You made it to the secure zone.");

        [HttpPost("logout")]
        public IActionResult Logout()
        {
            var rt = Request.Cookies["refreshToken"];
            if (rt != null)
            {
                var stored = _refreshTokens.FirstOrDefault(t => t.Token == rt);
                if (stored != null) stored.IsRevoked = true;
            }

            Response.Cookies.Delete("jwt");
            Response.Cookies.Delete("refreshToken");
            return Ok(new { message = "Logged out" });
        }


    }
}
