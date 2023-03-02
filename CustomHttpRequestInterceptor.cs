using System.IdentityModel.Tokens.Jwt;
using HotChocolate.AspNetCore;
using HotChocolate.Execution;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Net.Http.Headers;

namespace Authentication;

public class CustomHttpRequestInterceptor : DefaultHttpRequestInterceptor
{
    private readonly JwtSettings _jwtSettings;
    private readonly ILogger<CustomHttpRequestInterceptor> _logger;
    private readonly JwtSecurityTokenHandler _jwtHandler;

    public CustomHttpRequestInterceptor(JwtSettings jwtSettings, ILogger<CustomHttpRequestInterceptor> logger)
    {
        _jwtSettings = jwtSettings;
        _logger = logger;
        _jwtHandler = new JwtSecurityTokenHandler();
    }
    
    public override async ValueTask OnCreateAsync(HttpContext context, IRequestExecutor requestExecutor, IQueryRequestBuilder requestBuilder,
        CancellationToken cancellationToken)
    {
        var authenticationHeader = context.Request.Headers[HeaderNames.Authorization].FirstOrDefault();
        
        var tokenEncoded = authenticationHeader?["Bearer ".Length..]?.Trim();
        var tokenDecoded = _jwtHandler.CanReadToken(tokenEncoded) 
            ? _jwtHandler.ReadJwtToken(tokenEncoded) 
            : null;

        if (tokenDecoded is null)
        { 
            await base.OnCreateAsync(context, requestExecutor, requestBuilder, cancellationToken);
            return;
        }

        var audience = tokenDecoded?.Audiences.FirstOrDefault();

        var authenticationSchema = audience == _jwtSettings.AudienceOne 
            ? Constants.Token.BearerOne 
            : audience == _jwtSettings.AudienceTwo 
                ? Constants.Token.BearerTwo 
                : null;

        if (authenticationSchema is null)
        {
            await base.OnCreateAsync(context, requestExecutor, requestBuilder, cancellationToken);
            return;
        }

        var result = await context.AuthenticateAsync(authenticationSchema);
        if (result.Succeeded)
        {
            _logger.LogInformation("Authentication succeeded with schema {Schema} found using audience {Audience}", 
                authenticationSchema, audience);
        }
        
        await base.OnCreateAsync(context, requestExecutor, requestBuilder, cancellationToken);
    }
}