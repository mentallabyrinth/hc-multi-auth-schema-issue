using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Authentication.Controllers;

[ApiController]
[Route("api/demo")]
public class DemoController : Controller
{
    /// <summary>
    /// JWT using the "Bearer1" configuration is required.
    /// </summary>
    /// <returns></returns>
    [Authorize(AuthenticationSchemes = Constants.Token.BearerOne)]
    [HttpGet("one")]
    public IActionResult GetSecretOne()
    {
        return Ok("Hello");
    }
    
    /// <summary>
    /// JWT using the "Bearer2" configuration is required.
    /// </summary>
    /// <returns></returns>
    [Authorize(AuthenticationSchemes = Constants.Token.BearerTwo)]
    [HttpGet("two")]
    public IActionResult GetSecretTwo()
    {
        return Ok("World");
    }

    /// <summary>
    /// JWT using either the "Bearer1" or "Bearer2" configuration is required.
    /// </summary>
    /// <returns></returns>
    [Authorize(Policy = Constants.Policies.SharedSchemas)]
    [HttpGet("three")]
    public IActionResult GetSecretThree()
    {
        return Ok("Shared");
    }

    /// <summary>
    /// JWT using the "JustBearerTwo" authorization policy
    /// </summary>
    /// <returns></returns>
    [Authorize(Policy = Constants.Policies.JustBearerTwo)]
    [HttpGet("four")]
    public IActionResult GetSecretFour()
    {
        return Ok("Using policy");
    }
}