using System.ComponentModel.DataAnnotations;

namespace Auth.Web.Model
{
    public class ChicoFeelingsModel
    {
        [Required]
        public string NomeMusica { get; set; }

        [Required]
        public string TrechoLetra { get; set; }
    }
}