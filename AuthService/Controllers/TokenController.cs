﻿using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
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
        private readonly IConfiguration _configuration;
        public TokenController(ILogger<TokenController> logger, IConfiguration iConfig)
        {
            _logger = logger;
            _configuration = iConfig;
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
                new Claim (ClaimTypes.NameIdentifier, userIdentifier), //user id "can be username for testing"
                new Claim (JwtRegisteredClaimNames.Nbf, new DateTimeOffset(DateTime.Now).ToUnixTimeSeconds().ToString()),
                new Claim (JwtRegisteredClaimNames.Exp, new DateTimeOffset(DateTime.Now.AddMinutes(1)).ToUnixTimeSeconds().ToString()),
                //get user role from db
                new Claim (ClaimTypes.Role, "admin" ),
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Secret"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _configuration["Issuer"],
                audience: _configuration["Audience"],
                claims: claims,
                signingCredentials:
                creds);

            var jwtToken = new JwtSecurityTokenHandler().WriteToken(token);

            SetTokenCookie(jwtToken);

            return jwtToken;
        }

        [HttpPost]
        public IActionResult RefreshToken(string token)
        {
            try
            {
                //TODO check Identifier and ip address exit in db
                var nameIdentifierclaim = GetClaim(token, "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier");

                var jwtToken = new JwtSecurityTokenHandler().ReadJwtToken(token);

                if (jwtToken.ValidTo <= DateTime.UtcNow)
                {
                    var jwtTokenRefreshed = GenerateToken(nameIdentifierclaim);

                    return Ok(jwtTokenRefreshed);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex.ToString());

            }

            return Unauthorized();
        }

        private void SetTokenCookie(string token)
        {

            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = DateTime.UtcNow.AddMinutes(1),

            };

            Response.Cookies.Append("refreshToken", token, cookieOptions);
        }

        private string GetClaim(string token, string claimType)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var securityToken = tokenHandler.ReadToken(token) as JwtSecurityToken;

            var stringClaimValue = securityToken.Claims.First(claim => claim.Type == claimType).Value;

            return stringClaimValue;
        }

        private string GetIpAddress()
        {
            if (Request.Headers.ContainsKey("X-Forwarded-For"))
                return Request.Headers["X-Forwarded-For"];
            else
                return HttpContext.Connection.RemoteIpAddress.MapToIPv4().ToString();
        }
    }
}
