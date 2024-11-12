using CleanArchitectureDemo.Domain.Entities;
namespace CleanArchitectureDemo.Application.Interfaces
{
    public interface IProductService
    {
        Task<IEnumerable<Product>> GetAllProductsAsync();
        Task<Product?> GetProductByIdAsync(int id);
        Task<Product?> GetProductByNameAsync(string name);
    }
}
