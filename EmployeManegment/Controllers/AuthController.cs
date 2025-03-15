using Assignment_Q3_2.Data;
using Assignment_Q3_2.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using static Assignment_Q3_2.DTOs.AuthDTOs;

namespace Assignment_Q3_2.Controllers
{
    [Route("api/auth")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly ApplicationDbContext _context;
        private readonly IConfiguration _config;
        private readonly PasswordHasher<User> _passwordHasher = new();

        public AuthController(IConfiguration config, ApplicationDbContext context)
        {
            _config = config;
            _context = context;
        }

        //[HttpPost("register")]
        //public async Task<IActionResult> RegisterAsync([FromBody] RegisterDTO registerDto)
        //{
        //    try
        //    {
        //        if (string.IsNullOrWhiteSpace(registerDto.Username))
        //            return BadRequest("Username cannot be empty.");

        //        if (registerDto.Username.Length < 3)
        //            return BadRequest("Username must be at least 3 characters long.");

        //        if (_context.Users.Any(u => u.Username == registerDto.Username))
        //            return BadRequest("Username already exists.");

        //        if (char.IsDigit(registerDto.Username[0]))
        //            return BadRequest("Username cannot start with a number.");

        //        // Hash password with ASP.NET Identity
        //        var hashedPassword = _passwordHasher.HashPassword(null, registerDto.Password);

        //        Console.WriteLine($"Hashed Password During Registration: {hashedPassword}");

        //        var user = new User
        //        {
        //            Username = registerDto.Username,
        //            PasswordHash = hashedPassword,
        //            Role = registerDto.Role
        //        };

        //        _context.Users.Add(user);
        //        await _context.SaveChangesAsync();
        //        return Ok("User registered successfully!");
        //    }
        //    catch (Exception ex)
        //    {
        //        return StatusCode(500, $"An error occurred: {ex.Message}");
        //    }
        //}
        [HttpPost("register")]
        public async Task<IActionResult> RegisterAsync([FromBody] RegisterDTO registerDto)
        {
            try
            {
                // Existing validation code...

                // Hash password with ASP.NET Identity
                var hashedPassword = _passwordHasher.HashPassword(null, registerDto.Password);

                var user = new User
                {
                    Username = registerDto.Username,
                    PasswordHash = hashedPassword,
                    Role = registerDto.Role
                };

                _context.Users.Add(user);
                await _context.SaveChangesAsync();
                return Ok("User registered successfully!");
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"An error occurred: {ex.Message}");
            }
        }
        [HttpPost("login")]
        public IActionResult Login([FromBody] LoginDTO loginDto)
        {
            try
            {
                // Validate input
                if (string.IsNullOrWhiteSpace(loginDto.Username) || string.IsNullOrWhiteSpace(loginDto.Password))
                    return BadRequest("Username and password are required.");

                // Find the user in the database
                var user = _context.Users.FirstOrDefault(u => u.Username == loginDto.Username);

                if (user == null)
                    return Unauthorized("Invalid credentials");

                // Verify password using ASP.NET Identity password hasher
                var passwordVerificationResult = _passwordHasher.VerifyHashedPassword(null, user.PasswordHash, loginDto.Password);

                if (passwordVerificationResult == PasswordVerificationResult.Failed)
                    return Unauthorized("Invalid credentials");

                // Generate JWT token
                var token = GenerateJwtToken(user);
                return Ok(new AuthResponseDTO { Token = token });
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"An error occurred: {ex.Message}");
            }
        }
        //[HttpPost("login")]
        //public IActionResult Login([FromBody] LoginDTO loginDto)
        //{

        //    try
        //    {
        //        // Validate input
        //        if (string.IsNullOrWhiteSpace(loginDto.Username) || string.IsNullOrWhiteSpace(loginDto.Password))
        //            return BadRequest("Username and password are required.");

        //        // Find the user in the database
        //        var user = _context.Users.FirstOrDefault(u => u.Username == loginDto.Username);
        //        Console.WriteLine(user); // Debugging line, can be removed in production

        //        if (user == null || !VerifyPassword(loginDto.Password, user.PasswordHash))
        //            return Unauthorized("Invalid credentials");

        //        // Generate JWT token
        //        var token = GenerateJwtToken(user);
        //        return Ok(new AuthResponseDTO { Token = token });
        //    }
        //    catch (Exception ex)
        //    {
        //        return StatusCode(500, $"An error occurred: {ex.Message}");
        //    }

        //}

        private bool VerifyPassword(string password, string storedHash)
        {
            return HashPassword(password) == storedHash;
        }

        private string HashPassword(string password)
        {
            using var sha256 = SHA256.Create();
            byte[] hashedBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
            return Convert.ToBase64String(hashedBytes);
        }

        private string GenerateJwtToken(User user)
        {
            try
            {
                var jwtSettings = _config.GetSection("Jwt");
                var key = Encoding.UTF8.GetBytes(jwtSettings["Key"]!);
                var issuer = jwtSettings["Issuer"]!;
                var audience = jwtSettings["Audience"]!;

                var tokenHandler = new JwtSecurityTokenHandler();
                var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.Username),
                   new Claim(ClaimTypes.Role, user.Role)  // Adding role-based authorization
                };

                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(claims),
                    Expires = DateTime.UtcNow.AddHours(1), // You can make this configurable
                    Issuer = _config["Jwt:Issuer"],
                    Audience = _config["Jwt:Audience"],
                    SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
                };

                var token = tokenHandler.CreateToken(tokenDescriptor);
                return tokenHandler.WriteToken(token);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error generating JWT token: {ex.Message}");
                return "ERROR_TOKEN";
            }
        }
    }
}
