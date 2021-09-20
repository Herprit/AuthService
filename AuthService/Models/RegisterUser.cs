using System.ComponentModel.DataAnnotations;

namespace AuthService.Models
{
    public class RegisterUser
    {
        [Required]
        public string FirstName { get; set; }

        [Required]
        public string Username { get; set; }

        [Required]
        public string Password { get; set; }
    }
}
