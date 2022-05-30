using Authentication.Models;
using HotChocolate.AspNetCore.Authorization;

namespace Authentication;

public class Query
{
    /// <summary>
    /// As expected only works when using the JWT generated with the "Bearer1" configuration.
    /// </summary>
    /// <returns></returns>
    [Authorize]
    public Book GetBook() => 
        new Book
        {
            Title = "C# in depth.",
            Author = new Author
            {
                Name = "Jon Skeet"
            }
        };

    /// <summary>
    /// Doesn't work when using either "Bearer1" or "Bearer2" JWT but is expected to work.
    /// see /api/demo/three for working example. (available in openapi doc).
    /// </summary>
    /// <returns></returns>
    [Authorize(Policy = Constants.Policies.SharedSchemas)]
    public Book GetSecretOne() => 
        new Book
        {
            Title = "How to Win Friends & Influence People",
            Author = new Author
            {
                Name = "Dale Carnegie"
            }
        };

    /// <summary>
    /// Doesn't work when using the "Bearer2" JWT but is expected to work.
    /// see /api/demo/four for working example (available in openapi doc).
    /// </summary>
    /// <returns></returns>
    [Authorize(Policy = Constants.Policies.JustBearerTwo)]
    public Book GetSecretTwo() =>
        new Book
        {
            Title = "The Art of War",
            Author = new Author
            {
                Name = "Sun Tzu"
            }
        };
}