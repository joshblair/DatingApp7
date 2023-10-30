using System.Security.Cryptography;
using System.Text;
using API.Data;
using API.DTOs;
using API.Entities;
using API.Interfaces;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers
{
    /// <summary>
    /// The `AccountController` class is a C# controller that handles user registration and login functionality for an API.
    /// </summary>
    public class AccountController : BaseApiController
    {
        private readonly DataContext _context;
        private readonly ITokenService _tokenService;

        /// <summary>
        /// The `public AccountController(DataContext context, ITokenService tokenService)` is a constructor for the `AccountController` class. It takes two parameters: `context` of type `DataContext` and `tokenService` of type `ITokenService`.
        /// </summary>
        /// <param name="context"></param>
        /// <param name="tokenService"></param>
        public AccountController(DataContext context, ITokenService tokenService)
        {
            _context = context;
            _tokenService = tokenService;
        }

        /// <summary>
        /// The Register function is a POST endpoint that registers a new user by creating a new AppUser object,
        /// hashing the password, and saving the user to the database.
        /// </summary>
        /// <param name="RegisterDto">The RegisterDto is a data transfer object that contains the information
        /// needed to register a user. It typically includes the following properties:</param>
        /// <returns>
        /// The method is returning an `ActionResult<UserDto>`.
        /// </returns>
        [HttpPost("register")] // POST: api/accounts/register
        public async Task<ActionResult<UserDto>> Register(RegisterDto registerDto)
        {
            if (await UserExists(registerDto.Username)) return BadRequest("Username is taken");
            using var hmac = new HMACSHA512();

            var user = new AppUser
            {
                UserName = registerDto.Username.ToLower(),
                PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(registerDto.Password)),
                PasswordSalt = hmac.Key
            };

            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            return new UserDto
            {
                Username = user.UserName,
                Token = _tokenService.CreateToken(user)
            };
        }

        /// <summary>
        /// The Login function is a login endpoint that checks if the provided username and password are valid
        /// and returns a user DTO with a token if successful.
        /// </summary>
        /// <param name="LoginDto">The LoginDto is a data transfer object that contains the following
        /// properties:</param>
        /// <returns>
        /// The method is returning an `ActionResult<UserDto>`.
        /// </returns>
        [HttpPost("login")]
        public async Task<ActionResult<UserDto>> Login(LoginDto loginDto)
        {
            var user = await _context.Users.SingleOrDefaultAsync(x => x.UserName == loginDto.Username);
            if (user == null) return Unauthorized("Invalid username");

            using var hmac = new HMACSHA512(user.PasswordSalt);

            var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(loginDto.Password));

            for (int i = 0; i < computedHash.Length; i++)
            {
                if (computedHash[i] != user.PasswordHash[i]) return Unauthorized("Invalid password");
            }

            return new UserDto
            {
                Username = user.UserName,
                Token = _tokenService.CreateToken(user)
            };
        }

        /// <summary>
        /// The UserExists function checks if a user with a given username exists in the database.
        /// </summary>
        /// <param name="username">The username parameter is a string that represents the username of a
        /// user.</param>
        /// <returns>
        /// The method is returning a Task<bool> which represents a boolean value indicating whether a user
        /// with the specified username exists in the database.
        /// </returns>
        private async Task<bool> UserExists(string username)
        {
            return await _context.Users.AnyAsync(x => x.UserName == username.ToLower());
        }
    }
}