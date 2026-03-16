namespace TactileWorld.Auth.Models
{
    public class Usuario
    {
        public int Id { get; set; }
        public string Nome { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string SenhaHash { get; set; } = string.Empty;
        public string? Secret2FA { get; set; }
        public bool Is2FAEnabled { get; set; } = false;
    }
}