using Authentication.Models;

namespace Authentication;

public class Query
{
    public Book GetBook() => 
        new Book
        {
            Title = "C# in depth.",
            Author = new Author
            {
                Name = "Jon Skeet"
            }
        };
}