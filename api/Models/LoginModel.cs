namespace api.Models
{
    public class LoginModel
    {
        // Caller must supply these
        public required string Username { get; set; }
        public required string Password { get; set; }
    }
}
