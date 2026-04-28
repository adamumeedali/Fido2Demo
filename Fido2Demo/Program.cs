using Fido2Demo.Service.Common;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();


// 1. Enable Session
builder.Services.AddSession(options => {
    options.IdleTimeout = TimeSpan.FromMinutes(2);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
});

builder.Services.AddSingleton<Utils>();

builder.Services.AddFido2(options => {
    options.ServerDomain = "localhost";
    options.ServerName = "My Secure App";
    options.Origins = new HashSet<string>
    {
        "https://localhost:7137"
    }; // Change to your actual port
});

// Add Session support (needed to store challenges between steps)
builder.Services.AddSession();
builder.Services.AddControllersWithViews();


var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}



app.UseHttpsRedirection();
app.UseRouting();
app.UseSession(); 
app.UseAuthentication();
app.UseAuthorization();
app.MapStaticAssets();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");


app.Run();
