using System.IdentityModel.Tokens.Jwt;
using HotChocolate.AspNetCore;
using HotChocolate.Execution;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Net.Http.Headers;

namespace Authentication;

public class CustomHttpRequestInterceptor : DefaultHttpRequestInterceptor
{
    private readonly JwtSettings _jwtSettings;
    private readonly JwtSecurityTokenHandler _jwtHandler;

    public CustomHttpRequestInterceptor(JwtSettings jwtSettings)
    {
        _jwtSettings = jwtSettings;
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
            await base.OnCreateAsync(context, requestExecutor, requestBuilder, cancellationToken);

        var audience = tokenDecoded?.Audiences.FirstOrDefault();

        var authorizationSchema = audience == _jwtSettings.AudienceOne 
            ? Constants.Token.BearerOne 
            : audience == _jwtSettings.AudienceTwo 
                ? Constants.Token.BearerTwo 
                : null;

        if (authorizationSchema is null)
            await base.OnCreateAsync(context, requestExecutor, requestBuilder, cancellationToken);

        await context.AuthenticateAsync(authorizationSchema);
        await base.OnCreateAsync(context, requestExecutor, requestBuilder, cancellationToken);
    }
}