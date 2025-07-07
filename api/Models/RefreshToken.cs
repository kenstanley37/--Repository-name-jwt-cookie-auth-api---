namespace api.Models
{
    public class RefreshToken
    {
        public required string Token { get; set; }
        public required string Username { get; set; }
        public DateTime Expires { get; set; }
        public bool IsRevoked { get; set; }
    }
}
