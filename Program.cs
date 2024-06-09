using Save_cloud.Data;
using Microsoft.EntityFrameworkCore;
using SQLitePCL;
using Microsoft.AspNetCore.Authentication.Cookies;
using Save_cloud.Services.Cloud_Storage;
using Microsoft.DotNet.Scaffolding.Shared.Messaging;
using Microsoft.AspNetCore.Http.Features;

namespace Save_cloud
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);
            builder.WebHost.ConfigureKestrel(opts => {
                opts.Limits.MaxRequestBodySize = long.MaxValue;
            });
            builder.Services.Configure<FormOptions>(options =>
            {
                options.MultipartBodyLengthLimit = 209715200000;
            });
            builder.Services.AddControllersWithViews(); // ��������� ������� MVC
            builder.Services.AddDbContext<UsersDbContext>(options => options.UseSqlite(
                builder.Configuration.GetConnectionString("DefaultConnection")));
            builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
                .AddCookie(options =>
                {
                    options.LoginPath = "/Users/Login"; // ���� � �������� �����
                    options.AccessDeniedPath = "/Users/Login"; // ���� � �������� ������� ��������
                    options.SlidingExpiration = false; // �������� ����� ����� �������� ����
                });
            builder.Services.AddAuthorization(options =>
            {
                options.AddPolicy("AdminPolicy", policy => policy.RequireRole("Admin")); // �������� ��� ��������������
                options.AddPolicy("UserPolicy", policy => policy.RequireRole("User")); // �������� ��� �������� ������������
            });
            var yandexDiskToken = builder.Configuration.GetValue<string>("YandexDisk:Token");
            var storageFolder = builder.Configuration.GetValue<string>("YandexDisk:Folder");
            builder.Services.AddTransient<Services.Cloud_Storage.ICloudStorageHelper, Services.Cloud_Storage.YandexDiskHelper>(provider => new Services.Cloud_Storage.YandexDiskHelper(yandexDiskToken, storageFolder));
            var app = builder.Build();

            // ������� ��������� ��������� ���� ������
            using (var dbContext = new UsersDbContext())
            {
                // ��� ������ ������� ������� ���� ������ � �������
                dbContext.Database.EnsureCreated();
            }

            // ������������� ������������� ��������� � �������������
            app.UseHttpsRedirection();
            app.UseStaticFiles();
            app.UseRouting();
            app.UseAuthentication();
            app.UseAuthorization();
            app.MapControllerRoute(
                name: "default",
                pattern: "{controller=Users}/{action=Index}/{id?}");
            app.Urls.Add("https://*:7107") ;
            app.Urls.Add("http://*:5153");
            app.Run();
        }
    }
}