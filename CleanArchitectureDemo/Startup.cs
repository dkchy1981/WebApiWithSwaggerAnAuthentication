using System.Text;
using CleanArchitectureDemo.Application.Interfaces;
using CleanArchitectureDemo.Infrastructure.Repositories;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using AspNetCoreRateLimit;

public class Startup
{
    private string MyAllowSpecificOrigins = "_myAllowSpecificOrigins";
    public Startup(IConfiguration configuration)
    {
        Configuration = configuration;
    }

    public IConfiguration Configuration { get; }

    public void ConfigureServices(IServiceCollection services)
    {
        services.AddMvc();
        services.AddScoped<IProductService, ProductRepository>();
        services.AddEndpointsApiExplorer();
        //services.AddSwaggerGen();
        services.Configure<IpRateLimitOptions>(options =>
        {
            options.EnableEndpointRateLimiting =true;
            options.StackBlockedRequests = false;
            options.HttpStatusCode =429;
            options.RealIpHeader ="X-Real-IP";
            options.RealIpHeader ="X-ClientId";
            options.GeneralRules = new List<RateLimitRule>
            {
                new RateLimitRule
                {
                    Endpoint="*",
                    Period="1s",
                    Limit=20
                }
            };
        });

        services.AddSingleton<IIpPolicyStore,MemoryCacheIpPolicyStore>();
        services.AddSingleton<IRateLimitCounterStore,MemoryCacheRateLimitCounterStore>();
        services.AddSingleton<IRateLimitConfiguration,RateLimitConfiguration>();
        services.AddSingleton<IProcessingStrategy,AsyncKeyLockProcessingStrategy>();
        services.AddInMemoryRateLimiting();        

        // Add CORS support
        services.AddCors(options =>
        {
           options.AddPolicy(name: MyAllowSpecificOrigins,
                      policy  =>
                      {
                          policy.WithOrigins("http://localhost:3000",
                                              "http://www.contoso.com");
                          policy.AllowAnyHeader();                    
                          policy.AllowAnyMethod();
                      });
        });

        services.AddSwaggerGen(options =>
        {
            options.SwaggerDoc("v1", new OpenApiInfo
            {
                Version = "v1",
                Title = "ToDo API",
                Description = "An ASP.NET Core Web API for managing ToDo items",
                TermsOfService = new Uri("https://example.com/terms"),
                Contact = new OpenApiContact
                {
                    Name = "Example Contact",
                    Url = new Uri("https://example.com/contact")
                },
                License = new OpenApiLicense
                {
                    Name = "Example License",
                    Url = new Uri("https://example.com/license")
                }
            });

            options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
            {
                In = ParameterLocation.Header,
                Description = "Please enter a valid token",
                Name = "Authorization",
                Type = SecuritySchemeType.Http,
                BearerFormat = "JWT",
                Scheme = "Bearer"
            });
            options.AddSecurityRequirement(new OpenApiSecurityRequirement
            {
                {
                    new OpenApiSecurityScheme
                    {
                        Reference = new OpenApiReference
                        {
                            Type=ReferenceType.SecurityScheme,
                            Id="Bearer"
                        }
                    },
                    new string[]{}
                }
            });
        });
        IdentityModelEventSource.ShowPII = true;
        services.AddHealthChecks();
        services.AddControllers();
        services.AddAuthorization();
        services.AddAuthorization(options =>
        {
            options.AddPolicy("Department", policy =>
                            policy.RequireClaim("Department", "HR","Develop","Admin"));
        });
        
        services.AddAuthentication(options => {
         options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        })
        .AddJwtBearer(options =>
        {
            options.Audience = "http://localhost:5261";
            options.Authority = "http://localhost:5261";
            options.RequireHttpsMetadata= false;
            options.IncludeErrorDetails = true;
            options.RequireHttpsMetadata = false;
            options.SaveToken = true;
            options.Configuration = new OpenIdConnectConfiguration();
            options.TokenValidationParameters = new TokenValidationParameters {
                ValidateIssuerSigningKey = true,
                ValidateLifetime = true,
                ValidateIssuer = true,
                ValidIssuer = "http://localhost:5261",    //Missing line here
                ValidateAudience = true,
                ValidAudience ="http://localhost:5261",
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes("thisisasecretkey@123"))                
            };

            options.Events = new JwtBearerEvents  
              {  
                  OnAuthenticationFailed = context =>  
                  {  
                      if (context.Exception.GetType() == typeof(SecurityTokenExpiredException))  
                      {  
                          context.Response.Headers.Add("Token-Expired", "true");  
                      }  
                      return Task.CompletedTask;  
                  }  
              };  
        });
    }

    public void Configure(IApplicationBuilder app, IWebHostEnvironment env, ILogger<Startup> logger)
    {
        if (env.IsDevelopment())
        {
            app.UseDeveloperExceptionPage();
            app.UseIpRateLimiting();
        }
    
        // Configure the HTTP request pipeline.
        if (env.IsDevelopment())
        {
            app.UseSwagger();
            app.UseSwaggerUI(c => { 
                c.SwaggerEndpoint("/swagger/v1/swagger.json", "My API V1");
                c.RoutePrefix=string.Empty; 
                });               
        }

        
        app.UseHttpsRedirection();

        app.UseRouting();
        app.UseAuthentication();  
        app.UseAuthorization(); 

        app.UseCors(MyAllowSpecificOrigins);

        app.UseEndpoints(endpoints =>
        {
            endpoints.MapControllers();
        });        

        // Example of logging in the Configure method
        logger.LogInformation("Application started at {Time}", DateTime.UtcNow);
    }

}
