using HotChocolate.AspNetCore;
using HotChocolate.Execution;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;

namespace Authentication;

public class HttpRequestInterceptor : DefaultHttpRequestInterceptor
{
    private readonly IPolicyEvaluator _policyEvaluator;
    private readonly IAuthorizationPolicyProvider _policyProvider;

    public HttpRequestInterceptor(IPolicyEvaluator policyEvaluator, IAuthorizationPolicyProvider policyProvider)
    {
        _policyEvaluator = policyEvaluator;
        _policyProvider = policyProvider;
    }

    public override async ValueTask OnCreateAsync(HttpContext context,
        IRequestExecutor requestExecutor, IQueryRequestBuilder requestBuilder,
        CancellationToken cancellationToken)
    {
        // var defaultPolicy = await _policyProvider.GetDefaultPolicyAsync();
        var policyOne = await _policyProvider.GetPolicyAsync(Constants.Policies.SharedSchemas);
        var policyTwo = await _policyProvider.GetPolicyAsync(Constants.Policies.JustBearerTwo);
        
        var defaultPolicy = new AuthorizationPolicyBuilder()
            .AddAuthenticationSchemes(Constants.Token.BearerOne, Constants.Token.BearerTwo)
            .RequireAuthenticatedUser()
            .Build();
        
        var authenticateResult = await _policyEvaluator.AuthenticateAsync(defaultPolicy, context);
        var authorizationResult =
            await _policyEvaluator.AuthorizeAsync(defaultPolicy, authenticateResult, context.Request.HttpContext,
                context);
        
        await base.OnCreateAsync(context, requestExecutor, requestBuilder, cancellationToken);
    }
}