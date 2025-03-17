using Assignment_Q3_2.Data;
using Assignment_Q3_2.Models;
using Assignment_Q3_2.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;//
using System.IdentityModel.Tokens.Jwt; //Used for JWT token creation and validation
using System.Security.Claims;//used for claims role base clamames
using System.Security.Cryptography;//used for SHA256
using System.Text; //used for encoding string
using static Assignment_Q3_2.DTOs.AuthDTOs;

namespace Assignment_Q3_2.Controllers
{
    [Route("api/auth")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IUserService _userService;

        public AuthController(IUserService userService)
        {
            _userService = userService;
        }

        [HttpPost("register")]
        public async Task<IActionResult> RegisterAsync([FromBody] RegisterDTO registerDto)
        {
            try
            {
                var result = await _userService.RegisterUserAsync(registerDto);
                return Ok(result);
            }
            catch (ArgumentException ex)
            {
                return BadRequest(ex.Message);
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"An error occurred: {ex.Message}");
            }
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginDTO loginDto)
        {
            try
            {
                var (token, message) = await _userService.LoginUserAsync(loginDto);
                return Ok(new AuthResponseDTO { Token = token });
            }
            catch (UnauthorizedAccessException)
            {
                return Unauthorized("Invalid credentials");
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"An error occurred: {ex.Message}");
            }
        }
    }
}



