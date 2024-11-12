using CleanArchitectureDemo.Application.Interfaces;
using CleanArchitectureDemo.Domain.Entities;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace CleanArchitectureDemo.Infrastructure.Repositories
{
    public class ProductRepository : IProductService
    {
        private IEnumerable<Product> items;

        public ProductRepository()
        {
            items=  Enumerable.Range(1, 500).Select(index => new Product(){Id=index,Name ="Dkc_"+index, Price = (decimal)index}).ToArray();
        }

        public Task<IEnumerable<Product>> GetAllProductsAsync()
        {
            return Task.FromResult(items);
        }

        public Task<Product?> GetProductByIdAsync(int id)
        {
            var product= new Product(); 
            product =items.FirstOrDefault(p=>p.Id ==id);            
            return Task.FromResult(product);
        }

        public Task<Product?> GetProductByNameAsync(string name)
        {
            var product= new Product(); 
            product =items.FirstOrDefault(p=>p.Name.IndexOf(name, StringComparison.OrdinalIgnoreCase)>-1);            
            return Task.FromResult(product);
        }
    }
}
