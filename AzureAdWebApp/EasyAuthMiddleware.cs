using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace AzureAdWebApp
{
    public class EasyAuthMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<EasyAuthMiddleware> _logger;

        public EasyAuthMiddleware(RequestDelegate next, ILogger<EasyAuthMiddleware> logger)
        {
            _next = next;
            _logger = logger;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            if (context.Request.Headers.TryGetValue("X-MS-TOKEN-AAD-ID-TOKEN", out var tokenHeader))
            {
                var token = tokenHeader.ToString();
                _logger.LogInformation("ID Token received." + token);

                var handler = new JwtSecurityTokenHandler();

                if (handler.CanReadToken(token))
                {
                    var jwtToken = handler.ReadJwtToken(token);

                    var identity = new ClaimsIdentity("EasyAuth", ClaimTypes.Name, ClaimTypes.Role);

                    foreach (var claim in jwtToken.Claims)
                    {
                        var claimType = claim.Type;

                        // Normalize certain claim types
                        if (claim.Type == "roles") claimType = ClaimTypes.Role;
                        if (claim.Type == "name") claimType = ClaimTypes.Name;

                        identity.AddClaim(new Claim(claimType, claim.Value));
                        _logger.LogInformation($"Claim added: {claimType} = {claim.Value}");
                    }

                    context.User = new ClaimsPrincipal(identity);
                    _logger.LogInformation("User context updated from ID token.");
                }
                else
                {
                    _logger.LogWarning("Invalid token format. Cannot read token.");
                }
            }
            else
            {
                _logger.LogWarning("No ID token header found.");
            }

            await _next(context);
        }

    }
}

