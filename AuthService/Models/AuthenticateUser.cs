﻿using System.ComponentModel.DataAnnotations;

namespace AuthService.Models
{
    public class AuthenticateUser
    {
        [Required]
        public string Username { get; set; }

        [Required]
        public string Password { get; set; }
    }
}
