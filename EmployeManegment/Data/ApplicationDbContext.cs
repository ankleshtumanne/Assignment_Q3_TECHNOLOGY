using Assignment_Q3_2.Models;
using Microsoft.EntityFrameworkCore;

namespace Assignment_Q3_2.Data
{
    public  class ApplicationDbContext : DbContext
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
        {
        }
        public DbSet<Employee> Employees { get; set; }
        public DbSet<User> Users { get; set; }
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<Employee>()
                .HasIndex(e => e.Email)  // Ensure Email is unique
                .IsUnique();
            modelBuilder.Entity<User>(entity =>
            {
                entity.Property(e => e.Id)
                    .UseIdentityColumn(1, 1); // This sets start value to 1 and increment to 1
            });
            modelBuilder.Entity<Employee>(entity =>
            {
                entity.Property(e => e.Id)
                    .UseIdentityColumn(1, 1);
            });
        }
    }

    
}
