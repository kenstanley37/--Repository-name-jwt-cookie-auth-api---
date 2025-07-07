namespace api.Models
{
    public class RefreshToken
    {
        public string Token { get; set; }
        public string Username { get; set; }
        public DateTime Expires { get; set; }
        public bool IsRevoked { get; set; }

    }
}
