using System.IdentityModel.Tokens.Jwt;
using System.Reflection;
using System.Security.Claims;
using System.Text;
using Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Net.Http.Headers;
using Microsoft.OpenApi.Models;
using Swashbuckle.AspNetCore.Filters;
using Path = System.IO.Path;

var builder = WebApplication.CreateBuilder(args);

var jwtSettingsConfig = builder.Configuration.GetSection("Jwt");

var jwtSettings = jwtSettingsConfig.Get<JwtSettings>();
builder.Services.Configure<JwtSettings>(options => jwtSettingsConfig.Bind(options));
builder.Services.AddSingleton(context =>
    context.GetRequiredService<IOptions<JwtSettings>>().Value);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "Multiple Token Example",
        Description = "API that uses multiple JWT tokens",
        Version = "v1"
    });
    
    var xmlFile = $"{Assembly.GetExecutingAssembly().GetName().Name}.xml";
    var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
    options.IncludeXmlComments(xmlPath);
    
    options.AddSecurityDefinition("oauth2", new OpenApiSecurityScheme
    {
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.Http,
        Scheme = JwtBearerDefaults.AuthenticationScheme,
        BearerFormat = "JWT",
        Name = "Authorization",
        Description = "Standard authorization header",
    });
    
    options.OperationFilter<SecurityRequirementsOperationFilter>();
});

builder.Services.AddAuthentication(options =>
    {
        options.DefaultScheme = "CombinedSchemas";
        options.DefaultAuthenticateScheme = "CombinedSchemas";
    })
    .AddJwtBearer(Constants.Token.BearerOne, options =>
    {
        options.SaveToken = true;
        options.Audience = jwtSettings.AudienceOne;
        options.ClaimsIssuer = jwtSettings.Issuer;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidIssuer = jwtSettings.Issuer,
            ValidateIssuer = true,
            ValidAudience = jwtSettings.AudienceOne,
            ValidateAudience = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(jwtSettings.AudienceOneKey))
        };
    })
    .AddJwtBearer(Constants.Token.BearerTwo, options =>
    {
        options.SaveToken = true;
        options.Audience = jwtSettings.AudienceTwo;
        options.ClaimsIssuer = jwtSettings.Issuer;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidIssuer = jwtSettings.Issuer,
            ValidateIssuer = true,
            ValidAudience = jwtSettings.AudienceTwo,
            ValidateAudience = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(jwtSettings.AudienceTwoKey))
        };
    })
    // Note: only works with .NETCore (AuthenticationSchemes) API and not Hot Chocolate 
    .AddPolicyScheme("CombinedSchemas", "CombinedSchemas", options =>
    {
        options.ForwardDefaultSelector = context =>
        {
            var authorization = context.Request.Headers[HeaderNames.Authorization].FirstOrDefault();
            
            if (string.IsNullOrEmpty(authorization) || !authorization.StartsWith("Bearer "))
                return Constants.Token.BearerOne;
            
            var token = authorization["Bearer ".Length..].Trim();
            var jwtHandler = new JwtSecurityTokenHandler();

            var audience = jwtHandler.CanReadToken(token)
                ? jwtHandler.ReadJwtToken(token).Audiences.FirstOrDefault()
                : null;

            return audience == jwtSettings.AudienceOne 
                ? Constants.Token.BearerOne 
                : audience == jwtSettings.AudienceTwo 
                    ? Constants.Token.BearerTwo 
                    : Constants.Token.BearerOne;
        };
    });

builder.Services.AddAuthorization(options =>
{
    var defaultPolicyBuilder = new AuthorizationPolicyBuilder(
        Constants.Token.BearerOne, 
        Constants.Token.BearerTwo);

    options.DefaultPolicy = defaultPolicyBuilder
        .RequireAuthenticatedUser()
        .Build();
    
    options.AddPolicy(Constants.Policies.SharedSchemas, policyBuilder =>
    {
        policyBuilder
            .AddAuthenticationSchemes(Constants.Token.BearerOne, Constants.Token.BearerTwo)
            .RequireAuthenticatedUser();
    });
    
    options.AddPolicy(Constants.Policies.JustBearerTwo, policyBuilder =>
    {
        // When the authentication token is read the claim names are transformed (mapped) to support open ID connect
        // see: https://learn.microsoft.com/en-us/aspnet/core/security/authentication/claims?view=aspnetcore-6.0
        // Don't fully understand the purpose for this, but moving on. This means that is there's a claim "role"
        // the name is changed to "http://schemas.microsoft.com/ws/2008/06/identity/claims/role." Because of
        // this using "role" will not work. The fully qualified value is found in the `ClaimTypes.Role`
        // constant and is the reason for its use below. Yes, this map can be cleared, but decided to
        // leave it as is for the learning experience. To clear the map use:
        // JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();
        //
        // Note: all mapped claim types can be found using the following link:
        // https://learn.microsoft.com/en-us/dotnet/api/system.security.claims.claimtypes?view=net-7.0
        policyBuilder
            .AddAuthenticationSchemes(Constants.Token.BearerTwo)
            .RequireClaim(ClaimTypes.Role, "standard")
            .RequireAuthenticatedUser();
    });
    
    
});

builder.Services.AddGraphQl();

builder.Services.AddHealthChecks();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    IdentityModelEventSource.ShowPII = true;
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseRouting();
app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

app.UseEndpoints(endpoints =>
{
    endpoints.MapHealthChecks("/health");
    endpoints.MapControllers();
    endpoints.MapGraphQL();
});

app.Run();