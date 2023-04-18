using API_ver1.Context;
using API_ver1.Helpers;
using API_ver1.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace API_ver1.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly AppDbContext _authContext;
        public UserController(AppDbContext authContext)
        {
            _authContext = authContext;
        }
        [HttpGet]
        public async Task<ActionResult<User>> GetAllUsers()
        {
            return Ok(await _authContext.Users.ToListAsync());
        }
        [HttpPost("authentication")]
        public async Task<IActionResult> Authentication([FromBody] User userObj )
        {
            if (userObj == null)
                return BadRequest();
            //
            var user = await _authContext.Users.FirstOrDefaultAsync(x => x.Username == userObj.Username && x.Password==userObj.Password);//hashing ko check pass,check sau
            if (user == null) return NotFound(new {Message="User not found!"});
            //if (!PasswordHashing.VerifyPassword(userObj.Password,user.Password))
            //{
            //    return BadRequest(new {Message="Password is incorrect"});
            //}
            user.Token = createJWT(user);
            return Ok(new 
            {
                Token=user.Token,
                Message="Login Success"
            });
        }
        [HttpPost("Register")]
        public async Task<IActionResult> RegisterUser([FromBody] User userObj)
        {
            if (userObj == null)
                return BadRequest();
            //check username exist
            if (await CheckUsernameExistAsync(userObj.Username))
                return BadRequest(new { message = "Username Already Exist!" });
            //check email exist
            if (await CheckEmailExistAsync(userObj.Email))
                return BadRequest(new { message = "Email Already Exist!" });

            //userObj.Password= PasswordHashing.HashPassword(userObj.Password);
            userObj.Role = "User";
            userObj.Token = "";

            await _authContext.Users.AddAsync(userObj);
            await _authContext.SaveChangesAsync();
            return Ok(
                new
                {
                    Message = "User register"
                }
                ); ;

        }
        private string createJWT(User user)
        {
            var tokenhandle = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes("secret");
            var identity = new ClaimsIdentity(new Claim[]
            {
                new Claim(ClaimTypes.Role,user.Role),
                new Claim(ClaimTypes.Name,$"{user.FirstName} {user.LastName}")
            });
            var credentials=new SigningCredentials(new SymmetricSecurityKey(key),SecurityAlgorithms.HmacSha256);
            var tokendiscription = new SecurityTokenDescriptor
            {
                Subject = identity,
                Expires = DateTime.Now.AddDays(1),
                SigningCredentials = credentials
            };
            var token=tokenhandle.CreateToken(tokendiscription);
            return tokenhandle.WriteToken(token);
        }


        private Task<bool> CheckUsernameExistAsync(string username)
            => _authContext.Users.AnyAsync(x => x.Username == username);

        private Task<bool> CheckEmailExistAsync(string email)
            => _authContext.Users.AnyAsync(x => x.Email == email);
    }
}
