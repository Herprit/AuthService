using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using JwtRegisteredClaimNames = System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames;

namespace AuthService.Controllers
{
    [ApiController]
    [Route("[controller]/[action]")]
    public class TokenController : ControllerBase
    {
        private readonly ILogger<TokenController> _logger;

        public TokenController(ILogger<TokenController> logger)
        {
            _logger = logger;
        }

        [HttpPost]
        public IActionResult CreateToken(string userIdentifier)
        {
            return new ObjectResult(GenerateToken(userIdentifier));
        }

        private string GenerateToken(string userIdentifier)
        {
            var claims = new List<Claim>
            {
                new Claim (ClaimTypes.Name, userIdentifier),
                new Claim (JwtRegisteredClaimNames.Nbf, new DateTimeOffset(DateTime.Now).ToUnixTimeSeconds().ToString()),
                new Claim (JwtRegisteredClaimNames.Exp, new DateTimeOffset(DateTime.Now.AddMinutes(10)).ToUnixTimeSeconds().ToString()),
                new Claim (ClaimTypes.Role, "zzz-12" ),
            };

            var token = new JwtSecurityToken(
                new JwtHeader(
                    new SigningCredentials(
                        new SymmetricSecurityKey(Encoding.UTF8.GetBytes("SecurityKeyRandomStoreInKeyVault")),
                        SecurityAlgorithms.HmacSha256)),
                new JwtPayload(claims));

            var jwtSeriToken = new JwtSecurityTokenHandler().WriteToken(token);

            return jwtSeriToken;
        }
    }
}
