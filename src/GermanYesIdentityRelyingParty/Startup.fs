namespace GermanYesIdentityRelyingParty

open System
open Microsoft.AspNetCore.Builder
open Microsoft.AspNetCore.Hosting
open Microsoft.Extensions.DependencyInjection
open Microsoft.Extensions.Hosting

type Startup() =
    member _.ConfigureServices(services: IServiceCollection) =
        services.AddDistributedMemoryCache() |> ignore
        services.AddSession(fun options ->
            options.IdleTimeout <- TimeSpan.FromMinutes(10.)
            options.Cookie.HttpOnly <- true
            options.Cookie.IsEssential <- true) |> ignore
        services.AddControllers() |> ignore

    member _.Configure(app: IApplicationBuilder, env: IWebHostEnvironment) =
        if env.IsDevelopment() then
            app.UseDeveloperExceptionPage() |> ignore

        app.UseRouting() |> ignore
        app.UseSession() |> ignore
        app.UseEndpoints(fun endpoints ->
            endpoints.MapControllerRoute(
                name = "default",
                pattern = "{controller=Home}/{action=Index}/{id?}") |> ignore) |> ignore