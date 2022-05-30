namespace Authentication;

public static class GraphQlService
{
    public static IServiceCollection AddGraphQl(this IServiceCollection services)
    {
        services
            .AddGraphQLServer()
            .AddQueryType<Query>();
        
        return services;
    }
}