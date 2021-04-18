using devapi.Domain;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace devapi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _config;

        public AuthController(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration config)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _config = config;
        }

        [AllowAnonymous]
        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel model)
        {
            var user = await _userManager.FindByNameAsync(model.Username);

            if (user == null)
            {
                return Ok(new LoginResponse()
                {
                    Errors = new List<string>()
                    {
                        $"Username {model.Username} not found please try again."
                    }
                });
            }

            if (!await _userManager.CheckPasswordAsync(user, model.Password))
            {
                return Ok(new LoginResponse()
                {
                    Errors = new List<string>()
                    {
                        "Wrong password please try again."
                    },
                    Success = false
                });
            }

            if (user != null)
            {
                var userRoles = await _userManager.GetRolesAsync(user);
                var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                };

                foreach (var userRole in userRoles)
                {
                    authClaims.Add(new Claim(ClaimTypes.Role, userRole));
                }

                var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["JwtConfig:Secret"]));

                var token = new JwtSecurityToken(
                issuer: _config["JWT:ValidIssuer"],
                audience: _config["JWT:ValidAudience"],
                expires: DateTime.Now.AddHours(3),
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
                );

                return Ok(new LoginResponse()
                {
                    Username = model.Username,
                    Token = new JwtSecurityTokenHandler().WriteToken(token),
                    Success = true,
                    Expiration = token.ValidTo,
                    Roles = userRoles
                }); ; ;
            }
            return Unauthorized();
        }

        [AllowAnonymous]
        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> Register([FromBody] RegisterModel model)
        {
            var userExists = await _userManager.FindByNameAsync(model.Username);
            var emailExists = await _userManager.FindByEmailAsync(model.Email);

            if (userExists != null && emailExists != null)
            {
                return Ok(new RegisterResponse()
                {
                    Errors = new List<string>()
                    {
                        $"Username {model.Username} already taken.",
                        $"Email {model.Email} already taken."
                    }
                });
            }

            if (userExists != null)
            {
                return Ok(new RegisterResponse()
                {
                    Errors = new List<string>()
                    {
                        $"Username {model.Username} already taken."
                    },
                    Success = false
                });
            }
            if (emailExists != null)
            {
                return Ok(new RegisterResponse()
                {
                    Errors = new List<string>()
                    {
                        $"Email {model.Email} already taken."
                    }
                });
            }

            ApplicationUser user = new ApplicationUser()
            {
                Email = model.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = model.Username
            };
            var result = await _userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
            {
                return BadRequest(new RegisterResponse()
                {
                    Errors = new List<string>()
                    {
                        "User creation failed! Please check user details and try again."
                    },
                    Success = false
                });
            }

            if (!await _roleManager.RoleExistsAsync(Roles.Admin))
                await _roleManager.CreateAsync(new IdentityRole(Roles.Admin));
            if (!await _roleManager.RoleExistsAsync(Roles.User))
                await _roleManager.CreateAsync(new IdentityRole(Roles.User));

            if (await _roleManager.RoleExistsAsync(Roles.User))
            {
                await _userManager.AddToRoleAsync(user, Roles.User);
            }

            return Ok(new RegisterResponse()
            {
                Username = user.UserName,
                Email = user.Email,
                Success = true,
                Role = Roles.User
            });
        }

        [HttpPost]
        [Route("register-admin")]
        public async Task<IActionResult> RegisterAdmin([FromBody] RegisterModel model)
        {
            var userExists = await _userManager.FindByNameAsync(model.Username);
            if (userExists != null)
            {
                return BadRequest(new RegisterResponse()
                {
                    Errors = new List<string>()
                    {
                        "User already Taken."
                    },
                    Success = false
                });
            }

            ApplicationUser user = new ApplicationUser()
            {
                Email = model.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = model.Username
            };
            var result = await _userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
            {
                return BadRequest(new RegisterResponse()
                {
                    Errors = new List<string>()
                    {
                        "User creation failed! Please check user details and try again."
                    },
                    Success = false
                });
            }

            if (!await _roleManager.RoleExistsAsync(Roles.Admin))
                await _roleManager.CreateAsync(new IdentityRole(Roles.Admin));
            if (!await _roleManager.RoleExistsAsync(Roles.User))
                await _roleManager.CreateAsync(new IdentityRole(Roles.User));

            if (await _roleManager.RoleExistsAsync(Roles.Admin))
            {
                await _userManager.AddToRoleAsync(user, Roles.Admin);
            }
            return Ok(new RegisterResponse()
            {
                Username = user.UserName,
                Email = user.Email,
                Success = true,
                Role = Roles.Admin
            });
        }
    }
}
