using Assignment_Q3_2.Models;
using static Assignment_Q3_2.DTOs.AuthDTOs;



namespace Assignment_Q3_2.Services
{
    public interface IUserService
    {
        Task<string> RegisterUserAsync(RegisterDTO registerDto);
        Task<(string token, string message)> LoginUserAsync(LoginDTO loginDto);
        Task<User?> GetUserByUsernameAsync(string username);
        Task<bool> UserExistsAsync(string username);
        Task<IEnumerable<User>> GetAllUsersAsync();
    }
}
