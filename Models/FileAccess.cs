using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Save_cloud.Models
{
    [Flags]
    public enum AccessType
    {
        None = 0b00000,
        Read = 0b00001, //читать
        Write = 0b00010, //писать
        Modify = 0b00100, //изменять
        Delete = 0b01000, //удалять
        Share = 0b10000, //делиться 
        All = 0b11111
    }

    public class FileAccess
    {
        [Key]
        public string AccessID { get; set; }

        public string FileID { get; set; }

        public string UserID { get; set; }

        public AccessType AccessType { get; set; }

        [ForeignKey("FileID")]
        public Files File { get; set; }

        [ForeignKey("UserID")]
        public Users User { get; set; }
    }
}
