using System.Reflection;
using System.Text;
using Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using Swashbuckle.AspNetCore.Filters;
using Path = System.IO.Path;

var builder = WebApplication.CreateBuilder(args);

var jwtSettingsConfig = builder.Configuration.GetSection("Jwt");
var jwtSettings = jwtSettingsConfig.Get<JwtSettings>();
builder.Services.Configure<JwtSettings>(options => jwtSettingsConfig.Bind(options));

// Add services to the container.
builder.Services.AddGraphQl();

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
        options.DefaultScheme = Constants.Token.BearerOne; 
    }
).AddJwtBearer(Constants.Token.BearerOne, options =>
    {
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
    }
).AddJwtBearer(Constants.Token.BearerTwo, options =>
    {
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
    }
);

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy(Constants.Policies.SharedSchemas, policyBuilder =>
    {
        policyBuilder
            .AddAuthenticationSchemes(Constants.Token.BearerOne, Constants.Token.BearerTwo)
            .RequireAuthenticatedUser();
    });
});

builder.Services.AddHealthChecks();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    IdentityModelEventSource.ShowPII = true;
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();
app.MapGraphQL();
app.MapHealthChecks("/health");

app.Run();