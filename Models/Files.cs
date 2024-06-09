using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Save_cloud.Models
{
    public class Files
    {
        [Key]
        public string FileID { get; set; }
        public string FileName { get; set; }
        public string FileHash { get; set; }
        public string EncryptionKey { get; set; }
        public string InitializationVector { get; set; }
        public DateTime UploadDate { get; set; } // Дата загрузки файла

        public string OwnerID { get; set; }
        [ForeignKey("OwnerID")]
        public Users Owner { get; set; }
    }
}
