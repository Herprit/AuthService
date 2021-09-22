using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Collections.Generic;

namespace AuthService.Controllers
{
    [Authorize]
    [Route("[controller]/[action]")]
    [ApiController]
    public class AuthorizeJwtController : ControllerBase
    {
        [HttpGet]
        //Run in postman, add Bearer to the header
        public IActionResult TestAuthorize()
        {
            Dictionary<string, string> requestHeaders = new Dictionary<string, string>();
            foreach (var header in Request.Headers)
            {
                requestHeaders.Add(header.Key, header.Value);
            }

            return Ok(requestHeaders);
        }
    }
}
