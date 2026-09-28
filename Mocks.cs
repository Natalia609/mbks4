using System;
using System.IO;
using System.Threading.Tasks;

// Помещаем интерфейсы в то же пространство имен, что и оригинальный класс,
// чтобы компилятор нашел их без дополнительных директив 'using'
namespace MediaBrowser.Controller.ClientEvent
{
    public interface IClientEventLogger
    {
        Task<string> WriteDocumentAsync(string clientName, string clientVersion, Stream fileContents);
    }

    public interface IServerApplicationPaths
    {
        string LogDirectoryPath { get; }
        string ProgramDataPath { get; }
    }
}
