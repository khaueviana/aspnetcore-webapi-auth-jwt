using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using Auth.EF;
using Auth.Web.Model;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using System;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.IO;
using Microsoft.Extensions.Configuration;
using System.Collections.Generic;
using Microsoft.AspNetCore.Authorization;

namespace Auth.Web.Controllers
{
    [Produces("application/json")]
    [Route("api/Account")]
    public class AccountController : Controller
    {
        private UserManager<ApplicationUser> _userManager;
        private SignInManager<ApplicationUser> _signInManager;
        private RoleManager<IdentityRole> _roleManager;

        public AccountController(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, RoleManager<IdentityRole> roleManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _roleManager = roleManager;
        }

        [HttpPost("Create")]
        public async Task<IActionResult> Create([FromBody] AccountRegisterLoginModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState.Values.SelectMany(v => v.Errors).Select(modelError => modelError.ErrorMessage).ToList());

            var user = new ApplicationUser { UserName = model.Email, Email = model.Email };

            var result = await _userManager.CreateAsync(user, model.Password);

            if (!result.Succeeded)
                return BadRequest(result.Errors.Select(x => x.Description).ToList());

            var adminRole = await _roleManager.FindByNameAsync("Admin");

            if (adminRole == null)
            {
                adminRole = new IdentityRole("Admin");
                await _roleManager.CreateAsync(adminRole);

                await _roleManager.AddClaimAsync(adminRole, new Claim("ChicoFeelings", "Get"));
                await _roleManager.AddClaimAsync(adminRole, new Claim("ChicoFeelings", "Create"));
                await _roleManager.AddClaimAsync(adminRole, new Claim("ChicoFeelings", "SudoCreate"));
            }

            if (!await _userManager.IsInRoleAsync(user, adminRole.Name))
                await _userManager.AddToRoleAsync(user, adminRole.Name);

            return Ok();
        }

        [HttpPost("GenerateToken")]
        public async Task<IActionResult> GenerateToken([FromBody] AccountRegisterLoginModel model)
        {
            if (ModelState.IsValid)
            {
                var config = new ConfigurationBuilder()
                                 .SetBasePath(Directory.GetCurrentDirectory())
                                 .AddJsonFile("appsettings.json")
                                 .Build();

                var user = await _userManager.FindByEmailAsync(model.Email);

                if (user != null)
                {
                    var result = await _signInManager.CheckPasswordSignInAsync(user, model.Password, false);

                    if (result.Succeeded)
                    {
                        var userRoles = new List<string>();
                        var userClaims = new List<Claim>();

                        if (_userManager.SupportsUserRole)
                        {
                            var roles = await _userManager.GetRolesAsync(user);
                            foreach (var roleName in roles)
                            {
                                if (_roleManager.SupportsRoleClaims)
                                {
                                    userRoles.Add(roleName);

                                    var role = await _roleManager.FindByNameAsync(roleName);

                                    if (role != null)
                                    {
                                        userClaims.AddRange(await _roleManager.GetClaimsAsync(role));
                                    }
                                }
                            }
                        }

                        var claims = new[]
                        {
                            new Claim(JwtRegisteredClaimNames.Sub, user.Email),
                            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                        };

                        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["Token:Secret"]));
                        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

                        var token = new JwtSecurityToken(config["Token:Iss"],
                          config["Token:Aud"],
                          claims.Union(userClaims),
                          expires: DateTime.Now.AddMinutes(30),
                          signingCredentials: creds);

                        token.Payload.Add("roles", userRoles);


                        return Ok(new { token = new JwtSecurityTokenHandler().WriteToken(token) });
                    }
                }
            }

            return BadRequest("Could not create token");
        }

        [Authorize]
        [HttpGet("claims")]
        public object Claims()
        {
            return User.Claims.Select(c =>
            new
            {
                Type = c.Type,
                Value = c.Value
            });
        }
    }
}