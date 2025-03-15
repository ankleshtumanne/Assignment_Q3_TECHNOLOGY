namespace Assignment_Q3_2.DTOs
{
    public class AuthDTOs
    {
        public class RegisterDTO
        {
            public string Username { get; set; }
            public string Password { get; set; }
            public string Role { get; set; }  // Default role
        }
        public class LoginDTO
        {
            public string Username { get; set; }
            public string Password { get; set; }
        }

        public class AuthResponseDTO
        {
            public string Token { get; set; }
        }
    }
}
