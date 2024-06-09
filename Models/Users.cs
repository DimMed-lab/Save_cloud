using System.ComponentModel.DataAnnotations;

namespace Save_cloud.Models
{
    public enum UserRole
    {
        User,
        Admin
    }
    public class Users
    {
        [Key]
        public string? Id { get; set; }
        [Required(ErrorMessage = "Email обязательный")]
        [EmailAddress(ErrorMessage = "Неверный email")]
        public string? Username { get; set; }
        [Required(ErrorMessage = "Пароль обязательный")]
        [RegularExpression("^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[!@#$%^&*-]).{10,}$",ErrorMessage ="Пароль слишком простой")]
        public string? PasswordHash { get; set; }
        [Required]
        public UserRole Role { get; set; }
        [Required]
        public string Salt {  get; set; } = "Salt";
    }
}
