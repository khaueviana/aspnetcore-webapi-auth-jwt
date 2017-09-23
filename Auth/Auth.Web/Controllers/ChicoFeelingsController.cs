using System.Collections.Generic;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Auth.Web.Model;
using System.Linq;

namespace Auth.Web.Controllers
{
    [Route("api/[controller]")]
    public class ChicoFeelingsController : Controller
    {
        private static List<ChicoFeelingsModel> _data = new List<ChicoFeelingsModel>
        { new ChicoFeelingsModel { NomeMusica = "Bastidores", TrechoLetra = "Chorei, chorei, até ficar com dó de mim"},
          new ChicoFeelingsModel { NomeMusica = "Bastidores", TrechoLetra = "Quando você me quiser rever, já vai me encontrar refeita, pode crer"},
          new ChicoFeelingsModel { NomeMusica = "Sinhá", TrechoLetra = "Por que talhar meu corpo eu não olhei Sinhá para que que vosmincê meus olhos vai furar"}
        };

        [HttpGet("get")]
        [Authorize(Policy = "CanChicoFeelingsRead")]
        public List<ChicoFeelingsModel> Get()
        {
            return _data;
        }

        [HttpPost("create")]
        [Authorize(Policy = "CanChicoFeelingsCreate")]
        public IActionResult Create([FromBody]ChicoFeelingsModel chicoFeelingsModel)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState.Values.SelectMany(v => v.Errors).Select(modelError => modelError.ErrorMessage).ToList());
            }

            _data.Add(chicoFeelingsModel);

            return Ok();
        }

        [HttpPost("sudocreate")]
        [Authorize(Policy = "CanChicoFeelingsSudoCreate")]
        public IActionResult SudoCreate([FromBody]ChicoFeelingsModel chicoFeelingsModel)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState.Values.SelectMany(v => v.Errors).Select(modelError => modelError.ErrorMessage).ToList());
            }

            chicoFeelingsModel.NomeMusica += " SUDO!";

            _data.Add(chicoFeelingsModel);

            return Ok();
        }
    }
}