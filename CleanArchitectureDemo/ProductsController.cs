using CleanArchitectureDemo.Application.Interfaces;
using CleanArchitectureDemo.Domain.Entities;
using CleanArchitectureDemo.WebAPI.Attribute;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.ObjectPool;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;

namespace CleanArchitectureDemo.WebAPI.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class ProductsController : ControllerBase
    {
        private readonly IProductService _productService;

        public ProductsController(IProductService productService)
        {
            _productService = productService;
        }

        [HttpGet]
        [Authorize(Policy ="Department")]
        public async Task<IEnumerable<Product>> Get()
        {
            return await _productService.GetAllProductsAsync();
        }

        [HttpGet("ProductByID/{id}")]
        [ClaimsAuthorizeAttribute("Department","Admin")]
        public async Task<Product?> Get(int id)
        {
            return await _productService.GetProductByIdAsync(id);
        }

        [HttpGet("ProductByName/{name}")]
        [Authorize(Policy ="Department")]
        [ClaimsAuthorizeAttribute("Department","HR")]
        public async Task<Product?> Get(string name)
        {
            var data= await _productService.GetProductByNameAsync(name);
            return data;            
        }
    }
}
