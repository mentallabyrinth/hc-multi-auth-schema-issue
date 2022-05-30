namespace Authentication;

public class Constants
{
    public static class Token
    {
        public const string BearerOne = nameof(BearerOne);
        public const string BearerTwo = nameof(BearerTwo);
    }

    public static class Policies
    {
        public const string SharedSchemas = nameof(SharedSchemas);
        public const string JustBearerTwo = nameof(JustBearerTwo);
    }
}