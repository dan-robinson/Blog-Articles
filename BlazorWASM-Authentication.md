# Blazor WebAssembly - Azure AD with Custom Authorization

## Intro

This is a guide I put together after struggling to figure out how to do this for a proof of concept Blazor WebAssembly application for my employer. We will focus on configuring a Blazor WebAssembly application that is hosted by an ASP.NET Core API with Azure Active Directory authentication with custom application layer provided authorization. A lot of the guides and tutorials on this topic seemed to always defer to using Azure Groups and Roles, which required creating custom roles in the application manifest directly in Azure. This seemed like an adminstration headache to me and I wanted to be able to just read out the permissions that our existng application already had defined locally. We used Windows Authentication and then read the database to determine what permissions (authorization) the user had in the app.

This guide will breifly discuss configuing the Azure Active Directory Authentication for the solution. Really I just defer to Microsoft's tutorial for this because it's great and there isn't much I can add. After the authentication is set up we dive into what it takes to be able to add your own custom authorization.

Hopefully you find this guide useful and that I didn't make any huge security mistakes with this solution. Please let me know if there are any corrections or improvements that can be made.

(This is my first post/guide, so sorry if it sucks :P - you were warned)

## Setup Azure AD Authentication

The first step is to configure the basics for Azure Active Directory (AAD) with Blazor WebAssembly. The [Microsoft Docs Tutorial][1] for this is an excellent guide to follow so I won't repeat it here.

[1]: https://docs.microsoft.com/en-us/aspnet/core/blazor/security/webassembly/hosted-with-azure-active-directory?view=aspnetcore-3.1 "Secure an ASP.NET Core Blazor WebAssembly hosted app with Azure Active Directory"

The tutorial assumes you will be creating a brand new solution. Luckily, the tutorial also lays out all of the components required that make the authentication work. You just need to make sure each component is added to your existing solution. You should read the parts that refer to the default project template WeatherForecast Controller in the API project and the FetchData Component in the Blazor WebAssembly project to understand how to apply the authentication to your own API endpoints and app components.

After following the tutorial, you should be able to verify that the authentication is working in your app before moving on to adding the custom authorization.

## Add custom claims to token received from AAD in the API

The next step is to start adding claims to the token we receive from AAD at the API layer. When a user authenticates with the API, the AzureAD middleware will go out and request a token from AAD for the registered API application you setup in the beginning of this guide. One of the optional code changes suggested in the tutorial at the beginning of this guide is to configure the `NameClaimType` of the token to `"name"`. We will build on this to add our own claims after the token has been validated.

    services.Configure<JwtBearerOptions>(
        AzureADDefaults.JwtBearerAuthenticationScheme, options =>
    {
        options.TokenValidationParameters.NameClaimType = "name";
        options.Events = new JwtBearerEvents
        {
            OnTokenValidated = TokenValidated
        };
    });

We add a `TokenValidated` event that will be called after the token passes validation. Here is where we can add additional claims to user for use in authorization throughout the API and later in the Blazor Web Assembly client app.

Below is a sample `TokenValidated` function that will read a list of permissions from a database and add them as claims to the user.

    public async Task TokenValidated(TokenValidatedContext ctx)
    {
        // Gets the current user as a ClaimsIdentity
        var user = (ClaimsIdentity)ctx.Principal.Identity;

        // Using EF Core - retieve an instance of the DBContext
        var db = ctx.HttpContext.RequestServices.GetRequiredService<SecurityDBContext>();

        // Get user permissions from the database
        var userPermissions = await db.UserPermissions
            .Where(u => u.GivenName == user.Name)
            .ToListAsync();

        if (userPermissions.Any())
        {
            foreach (var userPermission in userPermissions)
            {
                // Add a new claim of ClaimType "permission" with all of the user permissions
                user.AddClaim(new Claim("permission", userPermission.PermissionName.Replace(" ", "")));
            }
        }
    }

## Create custom AuthorizeAttribute and IAuthorizationPolicyProvider

Now that we have our permission claim on the authenticated user, we can use it for authorization. I typically work with enterprise financial applications and prefer keeping the authorization as granular as possible to allow for flexibility in the user security configuration. Permissions can still be assigned to group roles and users can be members of those roles, but you would still retrieve a complete list of individual permissions for each user. Because I prefer these granular permissions for authorization, I choose to use a custom Authorization Policy Provider with a custom Authorization Attribute. Microsoft also has a great [doc][2] explaining these concepts and I highly suggest you read through that before continuing here to get a solid base understanding for what I'm about to lay out.

[2]: https://docs.microsoft.com/en-us/aspnet/core/security/authorization/iauthorizationpolicyprovider?view=aspnetcore-3.1 "Custom Authorization Policy Providers in ASP.NET Core"

Did you read that doc? You really should if you didn't.

Okay, first up, I choose to use an enum type to hold the list of possible permissions. I know some people may prefer to use an [Enumeration Class][3], but for the pruposes of this guide, we will just stick with a plain old enum.

[3]: https://docs.microsoft.com/en-us/dotnet/architecture/microservices/microservice-ddd-cqrs-patterns/enumeration-classes-over-enum-types "Using Enumeration classes instead of enum types"

Below is my custom `PermissionAuthorizeAttribute` that I derive from `AuthorizeAttribute`.

    public class PermissionAuthorizeAttribute : AuthorizeAttribute
    {
        const string POLICY_PREFIX = "Permission_";

        public PermissionAuthorizeAttribute(Permission permission) => Permission = permission;

        public Permission Permission
        {
            get
            {
                if (Enum.TryParse(Policy.Substring(POLICY_PREFIX.Length), out Permission permission))
                {
                    return permission;
                }
                return default;
            }
            set
            {
                Policy = $"{POLICY_PREFIX}{value}";
            }
        }
    }

What we are doing with this custom authorize attribute is allowing the specific parameter type to be passed in as a parameter to the attribute.

Example: `[PermissionAuthorizeAttribute(Permission.AdjustmentsRead)]`.

This attribute will evaluate a policy `Permission_AdjustmentsRead` (that we will define below) to determine if the user should be authorized to use/see the resource.

Okay, now for the custom `IAuthorizationPolicyProvider`. First the code and then we will talk about it.

    public class PermissionPolicyProvider : IAuthorizationPolicyProvider
    {
        const string POLICY_PREFIX = "Permission_";
        private DefaultAuthorizationPolicyProvider FallbackPolicyProvider { get; }

        public PermissionPolicyProvider(IOptions<AuthorizationOptions> options)
        {
            FallbackPolicyProvider = new DefaultAuthorizationPolicyProvider(options);
        }

        public Task<AuthorizationPolicy> GetPolicyAsync(string policyName)
        {
            if (policyName.StartsWith(POLICY_PREFIX, StringComparison.OrdinalIgnoreCase) &&
                Permission.TryParse(policyName.Substring(POLICY_PREFIX.Length), out Permission permission))
            {
                var policy = new AuthorizationPolicyBuilder();
                policy.RequireClaim("permission", permission.ToString());
                return Task.FromResult(policy.Build());
            }

            return FallbackPolicyProvider.GetPolicyAsync(policyName);
        }

        public Task<AuthorizationPolicy> GetDefaultPolicyAsync() => FallbackPolicyProvider.GetDefaultPolicyAsync();

        public Task<AuthorizationPolicy> GetFallbackPolicyAsync() => FallbackPolicyProvider.GetFallbackPolicyAsync();
    }

If you did indeed read the Microsoft document on this topic you should have a basic grasp of what's going on. The real meat and potatoes here is inside `GetPolicyAsync` :

    var policy = new AuthorizationPolicyBuilder();
    policy.RequireClaim("permission", permission.ToString());
    return Task.FromResult(policy.Build());

We simply use the built-in `RequireClaim` policy builder option like you would if using the default policy builder in `startup.cs`. We are creating this custom one so that we don't have to define a new policy for every single permission our app has, we can just re-use this in combination with our custom `PermissionAuthorizeAttribute` to dynamically create the policies we need.

Since we are using a custom `IAuthorizationPolicyProvider` we need to make sure we register it in the services container. Add the following line to your `startup.cs` file in the `ConfigureServices` function:

    services.AddSingleton<IAuthorizationPolicyProvider, PermissionPolicyProvider>();

At this point we should have a fully functioning authorization system working for our API and you should be able to test this on your API controllers or controller actions.

Next is getting this down to the Blazor WebAssembly app to use on the front-end.

## Add API endpoint to send custom claims to the client app

Because the Blazor WebAssembly app is getting an authentication token directly from AAD we need to add our permission claims again at this level. And since this part of the app will be running locally in the user's browser, we can't make the database call to retreive the list of permissions. So instead, we will ask the API for the user's permissions and add them as a claim to authenticated user at the client app level. Hopefully you'll see it once we get there if this doesn't quite make sense yet.

Alright, so we need to make the API endpoint for retrieving the user's permissions. Since we only want to send the permissions for the currently authenticated user, we can secure this endpoint with the default `AuthorizeAttribute`. This will require authenticated which will guess what, yep, it will add the additional permission claims to the user ready for us to pass on to the client. So all we need to do in the controller action is to pull the `"permission"` claims off of the user and return them in the response. Here is what I did:

    // UserPermission.cs (model)
    public class UserPermissions
    {
        public List<string> Permissions { get; set; }
    }

    // UserController.cs
    [Authorize]
    [ApiController]
    [Route("api/[controller]")]
    public class UserController : ControllerBase
    {
        [HttpGet]
        public ActionResult<UserPermissions> GetUser()
        {
            var userPermissions = new UserPermissions
            {
                Permissions = HttpContext.User.Claims
                    .Where(c => c.Type == "permission")
                    .Select(c => c.Value)
                    .ToList()
            };

            return Ok(userPermissions);
        }
    }

And that's it for this step. Next we will see how to use this in the Blazor WebAssembly client app.

## Customize the authenticated user in the client app

Again I will start by referring you to a quick [doc][4] Microsoft has made available providing an example of how to customize the user in a Blazor WebAssembly app.

[4]: https://docs.microsoft.com/en-us/aspnet/core/blazor/security/webassembly/additional-scenarios?view=aspnetcore-3.1#customize-the-user "Customize the user - ASP.NET Core Blazor WebAssembly additional security scenarios"

We will be using the `AccountClaimsPrincipalFactory` to derive our own version that will pull the user's permissions from the API and add them as additional claims to the authenticated user in the Blazor WebAssembly app.

First we can talk breifly about configuring the HttpClient so we can use it to make the API call for the user permissions. In the `program.cs` file you'll want to add the following:

    builder.Services.AddHttpClient("UserAPI", client =>
        client.BaseAddress = new Uri(builder.HostEnvironment.BaseAddress))
        .AddHttpMessageHandler<BaseAddressAuthorizationMessageHandler>();

Here we are naming the HttpClient so we can use the HttpClientFactory to get an instance of this specific configured HttpClient. The `.AddHttpMessageHandler<BaseAddressAuthroizationMessageHandler>()` should be familiar from the first Microsoft tutorial I referenced in this guide. This is what will add the token to the http request sent to the API which is required to pass the Authorize attributed we put on the API controller.

With that set we can create our custom `AccountClaimsPrincipalFactory`. And here it is:

    public class UserPermissionPrincipalFactory : AccountClaimsPrincipalFactory<RemoteUserAccount>
    {
        private readonly IHttpClientFactory _httpClientFactory;

        public UserPermissionPrincipalFactory(NavigationManager navigationManager, IAccessTokenProviderAccessor accessor, IHttpClientFactory httpClientFactory)
            : base(accessor)
        {
            _httpClientFactory = httpClientFactory;
        }

        public async override ValueTask<ClaimsPrincipal> CreateUserAsync(
            RemoteUserAccount account,
            RemoteAuthenticationUserOptions options)
        {
            var initialUser = await base.CreateUserAsync(account, options);

            if (initialUser.Identity.IsAuthenticated)
            {
                var userIdentity = (ClaimsIdentity)initialUser.Identity;

                var client = _httpClientFactory.CreateClient("UserAPI");
                var user = await client.GetFromJsonAsync<UserPermissions>($"api/user");
                foreach (var permission in user.Permissions)
                {
                    userIdentity.AddClaim(new Claim("permission", permission));
                }
            }

            return initialUser;
        }
    }

Nothing too special. First we inject an `IHttpClientFactory` we can use to get the `"UserAPI"` HttpClient. Then in the `CreateUserAsync` we can validate that the user has been authenticated (token validation passed) and then send the API request to get the user permissions. Finally we add the permissions as a new claim to the user `ClaimsIdentity`.

Don't forget, we will have to register this custom `AccountClaimsPrincipalFactory` in `program.cs`.

    builder.Services.AddMsalAuthentication<RemoteAuthenticationState, RemoteUserAccount>(options =>
    {
        builder.Configuration.Bind("AzureAD", options.ProviderOptions.Authentication);
        options.ProviderOptions.DefaultAccessTokenScopes.Add(@"40640219-50f2-484e-bd8f-1bd895bcc52a/API.Access");
    })
        .AddAccountClaimsPrincipalFactory<RemoteAuthenticationState, RemoteUserAccount, UserPermissionPrincipalFactory>();

Now our user should have the new permisison claims we can use in authorization. Remember the custom `IAuthorizationPolicyProvider` and `PermissionAuthorizeAttribute`. We can re-use these in the Blazor WebAssembly app too! I put those class definitions in a shared library project (that is created as part of the default Blazor WebAssembly solution template). Then you can just register the `IAuthorizationPolicyProvider` in `program.cs`.

    builder.Services.AddSingleton<IAuthorizationPolicyProvider, PermissionPolicyProvider>();

With that you can use the `[PermissionAuthorize(Permission.AdjustmentsRead)]` in your Blazor components and anywhere else you need to check user authorization (ex. [Procedural logic][5]).

[5]: https://docs.microsoft.com/en-us/aspnet/core/blazor/security/?view=aspnetcore-3.1#procedural-logic "Procedural Logic - ASP.NET Core Blazor authentication and authorization"

### The End

And that's it! Again, hopefully you found this guide useful and that I didn't make any huge security mistakes with this solution. Please let me know if there are any corrections or improvements that can be made. I pieced this together since I couldn't find any existing guides or tutorials on this subject as a whole.

