using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;

namespace Jellyfin.Api.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class ClientLogController : ControllerBase
    {
        private readonly string _logDirectoryPath = "/var/log/jellyfin";

        [HttpPost("Document")]
        public async Task<IActionResult> WriteDocumentAsync(
            [FromHeader(Name = "X-Emby-Authorization")] string clientName, 
            [FromQuery] string clientVersion, 
            IFormFile fileContents)
        {
            // clientName и clientVersion контролируются злоумышленником (RemoteFlowSource)
            var fileName = $"upload_{clientName}_{clientVersion}_{DateTime.UtcNow:yyyyMMddHHmmss}.log";
            
            // УЯЗВИМОСТЬ: Path.Combine без санитизации
            var logFilePath = Path.Combine(_logDirectoryPath, fileName);
            
            // Имитация записи
            // await using var fileStream = new FileStream(logFilePath, FileMode.CreateNew);
            // await fileContents.CopyToAsync(fileStream);
            
            return Ok(fileName);
        }
    }
}
