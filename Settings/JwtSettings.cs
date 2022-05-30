namespace Authentication;

public class JwtSettings
{
    public string Issuer { get; set; } = null!;
    public string AudienceOne { get; set; } = null!;
    public string AudienceTwo { get; set; } = null!;
    public string AudienceOneKey { get; set; } = null!;
    public string AudienceTwoKey { get; set; } = null!;
}