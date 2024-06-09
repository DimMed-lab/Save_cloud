using Microsoft.EntityFrameworkCore;
using Save_cloud.Models;
namespace Save_cloud.Data
{
    public class UsersDbContext : DbContext
    {
        public UsersDbContext()
        {
        }

        public UsersDbContext(DbContextOptions<UsersDbContext> options) : base(options)
        {
        }

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            string dbPath = Path.Combine(Environment.CurrentDirectory, "Save_cloud.db");
            optionsBuilder.UseSqlite($"Data Source={dbPath}");
            base.OnConfiguring(optionsBuilder);
        }

        public DbSet<Users> Users { get; set; }
        public DbSet<Files> Files { get; set; }
        public DbSet<Save_cloud.Models.FileAccess> FileAccesses { get; set; }
    }
}
