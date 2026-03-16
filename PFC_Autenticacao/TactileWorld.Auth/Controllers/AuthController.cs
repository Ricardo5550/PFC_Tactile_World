using Microsoft.AspNetCore.Mvc;
using TactileWorld.Auth.Data;
using TactileWorld.Auth.Models;
using Google.Authenticator;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace TactileWorld.Auth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly AppDbContext _context;
        private readonly IConfiguration _configuration;

        public AuthController(AppDbContext context, IConfiguration configuration)
        {
            _context = context;
            _configuration = configuration;
        }

        // Endpoint para registrar um novo usuário.
        [HttpPost("registrar")]
        public IActionResult Registrar([FromBody] UsuarioCadastroRequest request)
        {
            // Verificar se o email já existe no Banco de Dados para evitar duplicidade.
            if (_context.Usuarios.Any(u => u.Email == request.Email))
            {
                return BadRequest("Este email já está em uso no Tactile World.");
            }

            // Criptografia da senha com BCrypt usando Custo 12.
            string hashSenha = BCrypt.Net.BCrypt.HashPassword(request.Senha, 12);

            // Montar o novo usuário com a senha já criptografada.
            var novoUsuario = new Usuario
            {
                Nome = request.Nome,
                Email = request.Email,
                SenhaHash = hashSenha
            };

            // Salvar no Banco de Dados.
            _context.Usuarios.Add(novoUsuario);
            _context.SaveChanges();

            return Ok("Usuário cadastrado com sucesso no Banco de Dados!");
        }

        [HttpPost("login")]
        public IActionResult Login([FromBody] UsuarioCadastroRequest request)
        {
            // Procurar o email do usuário no Banco de Dados.
            var usuario = _context.Usuarios.FirstOrDefault(u => u.Email == request.Email);

            if (usuario == null)
            {
                return BadRequest("Usuário não encontrado no Tactile World.");
            }

            // Pegar a senha digitada e comparar com o Banco de Dados.
            bool senhaValida = BCrypt.Net.BCrypt.Verify(request.Senha, usuario.SenhaHash);

            if (!senhaValida)
            {
                return BadRequest("Senha incorreta.");
            }

            return Ok("Login realizado com sucesso! Bem-vindo de volta ao Tactile World!");
        }

        [HttpPost("configurar-2fa")]
        public IActionResult Configurar2FA([FromBody] Configurar2FARequest request)
        {
            // 1. Procurar o usuário no Banco de Dados.
            var usuario = _context.Usuarios.FirstOrDefault(u => u.Email == request.Email);

            if (usuario == null)
            {
                return BadRequest("Usuário não encontrado no Tactile World.");
            }

            // 2. Criar uma chave secreta única e ateatória para o usuário.
            string chaveSecreta = Guid.NewGuid().ToString().Replace("-", "").Substring(0, 10);

            // 3. Acionar o Autenticador para gerar os dados.
            TwoFactorAuthenticator tfa = new TwoFactorAuthenticator();
            SetupCode setupInfo = tfa.GenerateSetupCode("Tactile World", usuario.Email, chaveSecreta, false, 3);

            // 4. Salvar a chave secreta no Banco de Dados do usuário.
            usuario.Secret2FA = chaveSecreta;
            _context.SaveChanges();

            // 5. Entregar as informações para o usuário cadastrar.
            return Ok(new
            {
                Mensagem = "Abra o seu Autenticador e digite o Código Manual abaixo para vincular sua conta.",
                CodigoManual = setupInfo.ManualEntryKey,
                QrCodeImagem = setupInfo.QrCodeSetupImageUrl
            });
        }

        [HttpPost("validar-2fa")]
        public IActionResult Validar2FA([FromBody] Validar2FARequest request)
        {
            // 1. Procurar o usuário pelo e-mail.
            var usuario = _context.Usuarios.FirstOrDefault(u => u.Email == request.Email);

            if (usuario == null)
            {
                return BadRequest("Usuário não encontrado.");
            }

            // 2. Verificar se o usuário já tem uma chave secreta.
            if(string.IsNullOrEmpty(usuario.Secret2FA))
            {
                return BadRequest("O 2FA ainda não foi configurado para este usuário.");
            }

            // 3. Conferir tudo.
            TwoFactorAuthenticator tfa = new TwoFactorAuthenticator();
            bool codigoCorreto = tfa.ValidateTwoFactorPIN(usuario.Secret2FA, request.Codigo);

            if (!codigoCorreto)
            {
                return BadRequest("Código inválido ou expirado.");
            }

            // 4. Marcar oficialmente a segurança no Banco de Dados.
            usuario.Is2FAEnabled = true;
            _context.SaveChanges();

            // 5. Gerar o token com validade de 60 minutos.
            var tokenJwt = GerarTokenJwt(usuario);

            return Ok(new {
                Mensagem = "Autenticação 2FA concluída com sucesso! Acesso liberado ao Tactile World.",
                Token = tokenJwt
            });
        }
        private string GerarTokenJwt(Usuario usuario)
        {
            var jwtSettings = _configuration.GetSection("JwtSettings");
            var secretKey = Encoding.ASCII.GetBytes(jwtSettings["SecurityKey"]!);

            // ID e Email.
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, usuario.Id.ToString()),
                new Claim(JwtRegisteredClaimNames.Email, usuario.Email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var key = new SymmetricSecurityKey(secretKey);
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            // 60 minutos.
            var token = new JwtSecurityToken(
                issuer: jwtSettings["Issuer"],
                audience: jwtSettings["Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(Convert.ToDouble(jwtSettings["ExpirationMinutes"])),
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }

    // CLasse auxiliar (DTO) para receber apenas os dados necessários da Página Web.
    public class UsuarioCadastroRequest
    {
        public string Nome { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string Senha { get; set; } = string.Empty;
    }

    public class UsuarioLoginRequest
    {
        public string Email { get; set; } = string.Empty;
        public string Senha { get; set; } = string.Empty;
    }

    public class Configurar2FARequest
    {
        public string Email { get; set; } = string.Empty;
    }

    public class Validar2FARequest
    {
        public string Email { get; set; } = string.Empty;
        public string Codigo { get; set; } = string.Empty;
    }
}