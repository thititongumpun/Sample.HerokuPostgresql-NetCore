using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace devapi.Domain
{
    public class LoginModel
    {
        [Required(ErrorMessage = ("Username Is Required"))]
        [StringLength(50, MinimumLength = 4)]
        public string Username { get; set; }

        [Required(ErrorMessage = ("Password Is Required"))]
        [StringLength(50, MinimumLength = 4)]
        public string Password { get; set; }
    }

    public class LoginResponse
    {
        public string Username { get; set; }
        public string Token { get; set; }
        public bool Success { get; set; }
        public DateTime Expiration { get; set; }
        public List<string> Errors { get; set; }
        public IEnumerable<string> Roles { get; set; }
    }

    public class RegisterModel
    {
        [Required(ErrorMessage = ("Username Is Required"))]
        [StringLength(50, MinimumLength = 4)]
        public string Username { get; set; }

        [Required(ErrorMessage = ("Email Is Required"))]
        public string Email { get; set; }

        [Required(ErrorMessage = ("Password Is Required"))]
        [StringLength(50, MinimumLength = 4)]
        public string Password { get; set; }
    }

    public class RegisterResponse
    {
        public string Username { get; set; }
        public string Email { get; set; }
        public bool Success { get; set; }
        public List<string> Errors { get; set; }
        public string Role { get; set; }
    }
}
