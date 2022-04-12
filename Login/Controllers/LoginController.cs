using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using WebApp.Model;
using JwtRegisteredClaimNames = System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames;

namespace WebApp.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class LoginController : Controller
    {
        private IConfiguration _config;
        public LoginController ( IConfiguration config)
        {
            _config = config;

        }
/*        List<Login> us = new List<Login>
        {
            new Login(){Username = "huydd" , Password ="123" , Role="Admin"},
            new Login(){Username = "lamnh" , Password ="123" , Role="Member"}

        };*/
            [HttpGet]
        public IActionResult Login(string username , string password)
        {
            Login login = new Login();
            login.Username = username;
            login.Password = password;
            IActionResult respone = Unauthorized();
            var user = AuthenticateUser(login);
            if (user !=null)
            {
                var tokenStr = GenerateJSONWebToken(user);
                respone = Ok(new { token = tokenStr });
            }
            return respone;
        }

        private string  GenerateJSONWebToken(Login userinfor)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub,userinfor.Username),
                new Claim (ClaimTypes.Role,userinfor.Role),
                new Claim(JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString())
            };
            var token = new JwtSecurityToken(
                issuer: _config["Jwt:Issuer"],
                audience: _config["Jwt:Issuer"],
                claims,
                expires: DateTime.Now.AddMinutes(120),
                signingCredentials: credentials
                );
           var encodetoken = new JwtSecurityTokenHandler().WriteToken(token);
            return encodetoken; 
        }

        public  Login AuthenticateUser(Login login)
        {
            Login user = null;
            if(login.Username =="huyddjs" && login.Password=="123" )
            {
                user = new Login { Username = "huydd", Password = "123", Role = "Admin" };
            }
            if (login.Username == "lamnh" && login.Password == "123")
            {
                user = new Login { Username = "lamnh", Password = "123", Role = "Member" };
            } 
            return user;
        }


        [Authorize(Roles = "Admin")]
        [HttpPost("Post")]
        public string Post()
        {
            var identity = HttpContext.User.Identity as ClaimsIdentity;
            IList<Claim> claim = identity.Claims.ToList();
            var userName = claim[0].Value;
            return "Welcome Admin, " + userName ;
        }


        [Authorize(Roles = "Member")]
        [HttpGet("GetValue")]
        public ActionResult<IEnumerable<string>>Get()
        {
            return new string[] { "Welcome Member!" };
        }
    }
}
