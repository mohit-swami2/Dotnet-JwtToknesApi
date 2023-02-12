using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
// Create a mehthod to register a user with two methods first is register and createpasswordhash
// Create a method for login the user 
// Now we have to verify the password affcource

namespace JwtToknesPatricApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration _config;
        public AuthController(IConfiguration config)
        {
            _config = config;
        }
        public static User user = new User();

        [HttpPost("Register")]
        public async Task<ActionResult<User>> Register(UserDto Request)
        {
            CreatePasswordHash(Request.Password, out byte[] PasswordHash, out byte[] PasswordSalt);
            user.UserName = Request.UserName;
            user.PasswordHash = PasswordHash;
            user.PasswoadSalt = PasswordSalt;

            return Ok(user); 
        }

        [HttpPost("Loggin")]
        public async Task<ActionResult<string>> Loggin( UserDto Request)
        {
            if(user.UserName != Request.UserName)
            {
                return BadRequest("Name  Not found");
            }

            if (!VerifyPassword(Request.Password, user.PasswordHash, user.PasswoadSalt))
            {
                return BadRequest("Password doesn't Match"); 
            }
            string token = CreateToken(user);
            return Ok(token); 
        }

        private string CreateToken(User user)
        {
            List<Claim> Claims = new List<Claim>
            {
               new Claim(ClaimTypes.Name , user.UserName)
            };
            var Key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(
                _config.GetSection("Authentication:Secretkey").Value));
            var Cred = new SigningCredentials(Key , SecurityAlgorithms.HmacSha512Signature);

            var token = new JwtSecurityToken(
                claims: Claims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials:Cred);

            var jwt = new JwtSecurityTokenHandler().WriteToken(token);

            return jwt;
        }

        private void CreatePasswordHash(string Password , out byte[] PasswordHash , out byte[] PasswordSalt)
        {
            using (var hmac = new HMACSHA512())
            {
                PasswordSalt = hmac.Key;
                PasswordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(Password)); 
            }
        }

        private bool VerifyPassword(string Password , byte[] PasswordHash , byte[] PasswordSalt)
        {
            using (var hmac = new HMACSHA512(PasswordSalt))
            {
                var ComputerHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(Password));
                return ComputerHash.SequenceEqual(PasswordHash); 
            }
        }
    }
}
