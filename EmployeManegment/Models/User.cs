using System.ComponentModel.DataAnnotations;

namespace Assignment_Q3_2.Models
{
    public class User
    {
        [Key]
        public int Id { get; set; }
        [Required]
        public string Username { get; set; }
        [Required] 
        public string PasswordHash { get; set; }
        [Required] 
        public string Role { get; set; }
    }
}
