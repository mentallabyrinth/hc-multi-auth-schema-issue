using System.ComponentModel.DataAnnotations;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Authentication.Controllers;

[ApiController]
[Route("api/authentication/login")]
public class AuthenticationController : Controller
{
    private readonly JwtSettings _jwtSettings;

    public AuthenticationController(IOptions<JwtSettings> jwtSettings)
    {
        _jwtSettings = jwtSettings.Value;
    }
    
    /// <summary>
    /// Generated a JWT that uses the "Bearer1" configuration
    /// </summary>
    /// <returns></returns>
    [AllowAnonymous]
    [HttpPost("one")]
    public IActionResult AuthenticateOne()
    {
        var responseModel = new AuthenticateResponse();
        var nowUtc = DateTime.UtcNow;
        
        var claims = new List<Claim>()
        {
            new (JwtRegisteredClaimNames.Amr, "pwd", ClaimValueTypes.String),
            new (JwtRegisteredClaimNames.Sub, Guid.NewGuid().ToString(), ClaimValueTypes.String),
            new (JwtRegisteredClaimNames.Sid, Guid.NewGuid().ToString(), ClaimValueTypes.String),
            new (JwtRegisteredClaimNames.Iat,  EpochTime.GetIntDate(nowUtc).ToString(), ClaimValueTypes.Integer64),
            new (JwtRegisteredClaimNames.UniqueName, "test", ClaimValueTypes.String)
        };

        var symmetricKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(_jwtSettings.AudienceOneKey));
        
        var token = new JwtSecurityToken(
            issuer: _jwtSettings.Issuer,
            audience: _jwtSettings.AudienceOne,
            claims: claims,
            expires: nowUtc.AddMinutes(30),
            notBefore: nowUtc.Subtract(TimeSpan.FromMinutes(-1)),
            signingCredentials: new SigningCredentials(symmetricKey, SecurityAlgorithms.HmacSha256Signature));

        responseModel.AccessToken = new JwtSecurityTokenHandler().WriteToken(token);
        responseModel.Expires = (int) (token.ValidTo - nowUtc).TotalSeconds;

        return Ok(responseModel);
    }
    
    /// <summary>
    /// Generated a JWT that uses the "Bearer2" configuration
    /// </summary>
    /// <returns></returns>
    [AllowAnonymous]
    [HttpPost("two")]
    public IActionResult AuthenticateTwo()
    {
        var responseModel = new AuthenticateResponse();
        var nowUtc = DateTime.UtcNow;
        
        var claims = new List<Claim>()
        {
            new (JwtRegisteredClaimNames.Amr, "pwd", ClaimValueTypes.String),
            new (JwtRegisteredClaimNames.Sub, Guid.NewGuid().ToString(), ClaimValueTypes.String),
            new (JwtRegisteredClaimNames.Sid, Guid.NewGuid().ToString(), ClaimValueTypes.String),
            new (JwtRegisteredClaimNames.Iat,  EpochTime.GetIntDate(nowUtc).ToString(), ClaimValueTypes.Integer64),
            new (JwtRegisteredClaimNames.UniqueName, "test", ClaimValueTypes.String)
        };

        var symmetricKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(_jwtSettings.AudienceTwoKey));
        
        var token = new JwtSecurityToken(
            issuer: _jwtSettings.Issuer,
            audience: _jwtSettings.AudienceTwo,
            claims: claims,
            expires: nowUtc.AddMinutes(30),
            notBefore: nowUtc.Subtract(TimeSpan.FromMinutes(-1)),
            signingCredentials: new SigningCredentials(symmetricKey, SecurityAlgorithms.HmacSha256Signature));

        responseModel.AccessToken = new JwtSecurityTokenHandler().WriteToken(token);
        responseModel.Expires = (int) (token.ValidTo - nowUtc).TotalSeconds;

        return Ok(responseModel);
    }

    public class AuthenticateResponse
    {
        public string AccessToken { get; set; } = null!;
        public int Expires { get; set; }
    }
}