using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace CleanArchitectureDemo.WebAPI.Utility
{
    public static class TokenUtils
    {
        public static string GenerateAccessToken(string secret, string issuer)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(secret);

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

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(permClaims),
                Expires = DateTime.UtcNow.AddMinutes(15), // Token expiration time
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature),
                Issuer=issuer,
                Audience=issuer
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        public static string GenerateRefreshToken()
        {
            var randomNumber = new byte[32];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }

        public static string GenerateAccessTokenFromRefreshToken(string refreshToken, string secret,string issuer)
        {
            // Implement logic to generate a new access token from the refresh token
            // Verify the refresh token and extract necessary information (e.g., user ID)
            // Then generate a new access token

            // For demonstration purposes, return a new token with an extended expiry
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(secret);
          
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

             var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(permClaims),
                Expires = DateTime.UtcNow.AddMinutes(15), // Token expiration time
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature),
                Issuer=issuer,
                Audience=issuer
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        public static ClaimsPrincipal GetPrincipalFromExpiredToken(string token, string secret,string issuer)
        {
            var env = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT");
            var JwtSecret = secret;
            var Issuer = issuer;
            var Audience = issuer;
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = true,
                ValidateIssuer = true,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(JwtSecret)),
                ValidateLifetime = false,
                ValidIssuer = Issuer,
                ValidAudience = Audience
            };
            var tokenHandler = new JwtSecurityTokenHandler();
            SecurityToken securityToken;
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out securityToken);
            var jwtSecurityToken = securityToken as JwtSecurityToken;
            if (jwtSecurityToken == null || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                throw new SecurityTokenException("Invalid token");
            return principal;
        }
    }
}