using CleanArchitectureDemo.Application.Interfaces;
using CleanArchitectureDemo.Domain.Entities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.ObjectPool;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using CleanArchitectureDemo.WebAPI.Utility;

namespace CleanArchitectureDemo.WebAPI.Controllers
{

    [Route("api/[controller]")]
    [ApiController]
    [AllowAnonymous]
    public class LoginController : ControllerBase
    {

        private string key = "thisisasecretkey@123"; //Secret key which will be used later during validation    
        private string issuer = "http://localhost:5261";  //normally this will be your site URL    

        [HttpPost, Route("login")]
        public IActionResult Login(LoginDTO loginDTO)
        {
            try
            {
                /*
                if (string.IsNullOrEmpty(loginDTO.UserName) ||
                string.IsNullOrEmpty(loginDTO.Password))
                    return BadRequest("Username and/or Password not specified");
                if (loginDTO.UserName.Equals("string") &&
                loginDTO.Password.Equals("string"))
                {
                    var secretKey = new SymmetricSecurityKey
                    (Encoding.UTF8.GetBytes("thisisasecretkey@123"));
                    var signinCredentials = new SigningCredentials
                    (secretKey, SecurityAlgorithms.HmacSha256);
                    var jwtSecurityToken = new JwtSecurityToken(
                        issuer: "ABCXYZ",
                        audience: "http://localhost:5261",
                        claims: new List<Claim>(),
                        expires: DateTime.Now.AddMinutes(10),
                        signingCredentials: signinCredentials
                    );
                    return Ok(new JwtSecurityTokenHandler().
                    WriteToken(jwtSecurityToken));
                    }
                    */

                
                
            
                var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key));    
                var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);    

                if (string.IsNullOrEmpty(loginDTO.UserName) ||
                string.IsNullOrEmpty(loginDTO.Password))
                    return BadRequest("Username and/or Password not specified");
                if (loginDTO.UserName.Equals("string") &&
                loginDTO.Password.Equals("string"))
                {    
                    /*        
                    //Create a List of Claims, Keep claims name short    
                    var permClaims = new List<Claim>();    
                    permClaims.Add(new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()));    
                    permClaims.Add(new Claim("valid", "1"));    
                    permClaims.Add(new Claim("userid", "1"));    
                    permClaims.Add(new Claim("name", "bilal"));   
                    //permClaims.Add(new Claim("Department", "HR"));   
                    //permClaims.Add(new Claim("Department", "Develop"));   
                    permClaims.Add(new Claim("Department", "Admin"));   
                    permClaims.Add(new Claim("Department", "HR"));   
                     
                
                    //Create Security Token object by giving required parameters    
                    var token = new JwtSecurityToken(issuer, //Issure    
                    issuer,  //Audience    
                    permClaims,    
                    expires: DateTime.Now.AddMinutes(1),    
                    signingCredentials: credentials);    
                    var jwt_token = new JwtSecurityTokenHandler().WriteToken(token); 
                    return Ok(jwt_token);     
                    */
                    var accessToken = TokenUtils.GenerateAccessToken(key,issuer);
                    var refreshToken = TokenUtils.GenerateRefreshToken();                    
                    var response = new TokenResponse
                            {
                                AccessToken = accessToken,
                                RefreshToken = refreshToken
                            };


                    return Ok(response);     
                }           
            }
            catch
            {
                return BadRequest
                ("An error occurred in generating the token");
            }
            return Unauthorized();
        }

        [HttpPost("refresh")]
        public IActionResult Refresh(TokenResponse tokenResponse)
        {
            // For simplicity, assume the refresh token is valid and stored securely
            // var storedRefreshToken = _userService.GetRefreshToken(userId);

            // Verify refresh token (validate against the stored token)
            // if (storedRefreshToken != tokenResponse.RefreshToken)
            //    return Unauthorized();

            var principel = TokenUtils.GetPrincipalFromExpiredToken(tokenResponse.AccessToken,key,issuer);

            // For demonstration, let's just generate a new access token
            var newAccessToken = TokenUtils.GenerateAccessTokenFromRefreshToken(tokenResponse.RefreshToken, key,issuer);

            var response = new TokenResponse
            {
                AccessToken = newAccessToken,
                RefreshToken = tokenResponse.RefreshToken // Return the same refresh token
            };

            return Ok(response);
        }
    }

    public class TokenResponse
    {
        public string AccessToken { get; set; }
        public string RefreshToken { get; set; }
    }

    public class LoginDTO
    {
        public string UserName { get; set; }
        public string Password { get; set; }
    }
}