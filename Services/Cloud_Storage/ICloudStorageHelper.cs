namespace Save_cloud.Services.Cloud_Storage
{
    public interface ICloudStorageHelper
    {
        Task UploadFileAsync(string localFilePath, string remoteFolderPath);
        Task DownloadFileAsync(string remoteFilePath, string localFolderPath);
        Task DeleteFileAsync(string remoteFilePath);
    }
}
