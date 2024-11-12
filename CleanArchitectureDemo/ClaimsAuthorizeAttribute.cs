using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;


namespace CleanArchitectureDemo.WebAPI.Attribute
{
    public class ClaimsAuthorizeAttribute : AuthorizeAttribute,IAuthorizationFilter
    {
        private string claimType;
        private string claimValue;
        public ClaimsAuthorizeAttribute(string type, string value)
        {
            this.claimType = type;
            this.claimValue = value;
        }
        public void OnAuthorization(AuthorizationFilterContext  filterContext)
        {
            var user = filterContext.HttpContext.User as ClaimsPrincipal;
            if (!(user != null && user.HasClaim(claimType, claimValue)))
            {
                filterContext.Result = new StatusCodeResult((int)System.Net.HttpStatusCode.Forbidden);
                return;
            }
        }
    }
}