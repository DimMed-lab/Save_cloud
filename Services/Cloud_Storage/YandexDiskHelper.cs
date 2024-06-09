using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using YandexDisk.Client;
using YandexDisk.Client.Clients;
using YandexDisk.Client.Http;
using YandexDisk.Client.Protocol;
using YandexDisk.Client.Http;
using System.Net.Http;

namespace Save_cloud.Services.Cloud_Storage
{
    public class YandexDiskHelper:ICloudStorageHelper
    {
        private readonly string _token;
        private readonly string _storageFolder;
        private readonly HttpClient _httpClient;
        private readonly string _apiBaseUrl = "https://cloud-api.yandex.net/v1/disk/resources";
        private readonly string _apiTrashUrl = "https://cloud-api.yandex.net/v1/disk/trash/resources";

        public YandexDiskHelper(string token, string storageFolder)
        {
            _token = token;
            _httpClient = new HttpClient(); // Инициализация HttpClient
            // Задаем заголовок с авторизационным токеном
            _httpClient.DefaultRequestHeaders.Add("Authorization", _token);
            _storageFolder = storageFolder;
        }

        public async Task UploadFileAsync(string localFilePath, string remoteFilePath)
        {
            try
            {
                var api = new DiskHttpApi(_token);

                // Проверяем, существует ли папка на Яндекс.Диске
                //var folderData = await api.MetaInfo.GetInfoAsync(new ResourceRequest { Path = remoteFilePath });
                //if (!folderData.Embedded.Items.Any(i => i.Type == YandexDisk.Client.Protocol.ResourceType.Dir && i.Name.Equals(_storageFolder)))
                //{
                //    await api.Commands.CreateDictionaryAsync(remoteFilePath);
                //}

                // Загружаем файл на Яндекс.Диск
                var link = await api.Files.GetUploadLinkAsync(remoteFilePath + Path.GetFileName(localFilePath), overwrite: false);
                using (var fs = File.OpenRead(localFilePath))
                {
                    await api.Files.UploadAsync(link, fs);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                throw;
            }
        }

        public async Task DownloadFileAsync(string remoteFilePath, string localFolderPath)
        {
            try
            {
                var api = new DiskHttpApi(_token);

                // Скачиваем файл с Яндекс.Диска
                await api.Files.DownloadFileAsync(remoteFilePath, Path.Combine(localFolderPath, Path.GetFileName(remoteFilePath)));
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                throw;
            }
        }

        public async Task DeleteFileAsync(string path)
        {
            var queryParams = $"path={(_storageFolder + path)}&permanently={false}";
            var uri = $"{_apiBaseUrl}?{queryParams}";
            var request = new HttpRequestMessage(HttpMethod.Delete, uri);
            var response = await _httpClient.SendAsync(request);
            if (response.IsSuccessStatusCode)
            {
                Console.WriteLine("Resource deleted successfully.");
            }
            else
            {
                var errorMessage = await response.Content.ReadAsStringAsync();
                Console.WriteLine($"Error deleting resource: {errorMessage}");
            }
            uri = $"{_apiTrashUrl}?";
            request = new HttpRequestMessage(HttpMethod.Delete, uri);
            response = await _httpClient.SendAsync(request);
            if (response.IsSuccessStatusCode)
            {
                Console.WriteLine("Resource deleted from trashbin successfully.");
            }
            else
            {
                var errorMessage = await response.Content.ReadAsStringAsync();
                Console.WriteLine($"Error deleting resource: {errorMessage}");
            }
        }


    }
}
