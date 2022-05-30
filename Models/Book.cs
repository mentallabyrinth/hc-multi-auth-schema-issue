namespace Authentication.Models;

public class Book
{
    public string Title { get; set; } = null!;
    public Author? Author { get; set; }
}

public class Author
{
    public string Name { get; set; } = null!;
}