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
                var claims = new[] { new Claim(ClaimTypes.Name, model.Username) };

                var key = new SymmetricSecurityKey(
                    Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
                var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

                var token = new JwtSecurityToken(
                    issuer: _config["Jwt:Issuer"],
                    audience: _config["Jwt:Audience"],
                    claims: claims,
                    expires: DateTime.UtcNow.AddMinutes(
                        double.Parse(_config["Jwt:ExpiresInMinutes"])),
                    signingCredentials: creds);

                var tokenString = new JwtSecurityTokenHandler().WriteToken(token);

                Response.Cookies.Append("jwt", tokenString, new CookieOptions
                {
                    HttpOnly = true,
                    Secure = true,
                    SameSite = SameSiteMode.Strict,
                    Expires = DateTimeOffset.UtcNow.AddMinutes(15)
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
            var refreshToken = Request.Cookies["refreshToken"];
            var storedToken = _refreshTokens.FirstOrDefault(t =>
                t.Token == refreshToken && !t.IsRevoked && t.Expires > DateTime.UtcNow);

            if (storedToken == null)
                return Unauthorized();

            // Optionally revoke old token
            storedToken.IsRevoked = true;

            // Issue new access token
            var claims = new[] { new Claim(ClaimTypes.Name, storedToken.Username) };
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var token = new JwtSecurityToken(
                issuer: _config["Jwt:Issuer"],
                audience: _config["Jwt:Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(15),
                signingCredentials: creds);

            var tokenString = new JwtSecurityTokenHandler().WriteToken(token);

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
        public IActionResult GetSecureData()
        {
            return Ok("You made it to the secure zone.");
        }

        [HttpPost("logout")]
        public IActionResult Logout()
        {
            var refreshToken = Request.Cookies["refreshToken"];
            var storedToken = _refreshTokens.FirstOrDefault(t => t.Token == refreshToken);
            if (storedToken != null) storedToken.IsRevoked = true;

            Response.Cookies.Delete("jwt");
            Response.Cookies.Delete("refreshToken");

            return Ok(new { message = "Logged out" });

        }

    }
}
