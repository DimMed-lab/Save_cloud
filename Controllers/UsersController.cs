using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Save_cloud.Data;
using Save_cloud.Models;
using Save_cloud.Services.Cloud_Storage;
using System.Security.Cryptography;
using Save_cloud.Services.Cryptography;
using System.Diagnostics;


namespace Save_cloud.Controllers
{
    public class UsersController : Controller
    {
        private readonly UsersDbContext _context;
        private readonly ICloudStorageHelper _cloudStorageService;
        private readonly string _storageFolder;
        private readonly bool _allowNewAdmins;
        private readonly ILogger<UsersController> _logger;
        private static readonly object _lock = new object();

        public UsersController(UsersDbContext context, ICloudStorageHelper cloudStorageService, IConfiguration configuration, ILogger<UsersController> logger)
        {
            _context = context;
            _cloudStorageService = cloudStorageService;
            _storageFolder = configuration.GetValue<string>("YandexDisk:Folder");
            _allowNewAdmins = configuration.GetValue<bool>("AllowNewAdmins");
            _logger = logger;
        }



        // GET: Users
        public async Task<IActionResult> Index()
        {
            return View(await _context.Users.ToListAsync());
        }


        [AllowAnonymous]
        public IActionResult Login()
        {
            return View();
        }

        //[Authorize(Roles ="User")]

        [HttpPost]
        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return RedirectToAction("Index", "Users");
        }


        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

        [AllowAnonymous]
        public IActionResult Register()
        {
            return View();
        }

        public IActionResult FileNotFound()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> DeleteAccount()
        {
            // Получить текущего пользователя
            var currentUser = await _context.Users.FirstOrDefaultAsync(u => u.Username == User.Identity.Name);

            if (currentUser != null)
            {
                // Удалить текущего пользователя из базы данных
                _context.Users.Remove(currentUser);
                await _context.SaveChangesAsync();

                // Выполнить выход пользователя из системы
                await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

                return RedirectToAction("Index", "Users"); // Перенаправить на главную страницу
            }

            return RedirectToAction("Index", "Users"); // Если пользователь не найден, перенаправить на главную страницу пользователя
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register([Bind("Id,Username,PasswordHash,Role,Salt")] Users users)
        {
            if (ModelState.IsValid)
            {
                if ((users.Role == UserRole.Admin) && _allowNewAdmins == false) { return View("AdminNotCreated"); }
                // Используем транзакцию для обеспечения атомарности операций
                using (var transaction = await _context.Database.BeginTransactionAsync())
                {
                    try
                    {
                        // Проверяем, существует ли пользователь с таким именем уже в базе данных
                        var existingUser = await _context.Users.FirstOrDefaultAsync(u => u.Username == users.Username);
                        if (existingUser != null)
                        {
                            // Если пользователь существует, добавляем сообщение об ошибке в ModelState
                            ModelState.AddModelError("Username", "A user with the same name already exists");
                            return View(users); // Возвращаем представление с сообщением об ошибке
                        }
                        string salt = Guid.NewGuid().ToString();
                        users.Id = Guid.NewGuid().ToString();
                        users.Salt = salt;
                        users.PasswordHash = SHA256Encrypt.HashPassword(users.PasswordHash, salt);
                        _context.Add(users);
                        await _context.SaveChangesAsync();
                        await transaction.CommitAsync(); // Фиксируем транзакцию
                        return RedirectToAction("Index", "Users");
                    }
                    catch (Exception ex) 
                    { 
                        await transaction.RollbackAsync(); // Откатываем транзакцию в случае ошибки
                ModelState.AddModelError("", "An error occurred while registering the user: " + ex.Message);
                return View(users);
                    }
                }
            }
            return View(users);
        }


        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(string username, string password)
        {
            if(!string.IsNullOrEmpty(username)&& !string.IsNullOrEmpty(password))
            {
                // Найти пользователя в базе данных по имени пользователя
                var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == username);

                if (user != null)
                {
                    // Проверить хеш пароля
                    if (SHA256Encrypt.VerifyPassword(password, user.PasswordHash, user.Salt))
                    {
                        // Аутентификация успешна
                        // Устанавливаем информацию о пользователе в сессии или куках
                        var claims = new List<Claim>
                        {
                            new Claim(ClaimTypes.Name, user.Username),
                            new Claim(ClaimTypes.Role, user.Role.ToString()) // Здесь Role должно быть строкой или перечислением
                        };

                        var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                        var authProperties = new AuthenticationProperties
                        {
                            IsPersistent = false // Настройте, если хотите, чтобы пользователь оставался аутентифицированным после закрытия браузера
                        };

                        await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(claimsIdentity), authProperties);

                        return RedirectToAction("CloudStorage", "Users"); // Перенаправление на главную страницу после успешной аутентификации
                    }
                }
            }
            ModelState.AddModelError(string.Empty, "Invalid username or password");
            return View();
        }

        public class SHA256Encrypt
        {
            public static string HashPassword(string password, string salt)
            {
                using (var sha256hash = SHA256.Create())
                {
                    byte[] inputBytes = System.Text.Encoding.ASCII.GetBytes(password + salt);
                    byte[] hashBytes = sha256hash.ComputeHash(inputBytes);
                    return Convert.ToHexString(hashBytes);
                }
            }
            // Метод для проверки пароля
            public static bool VerifyPassword(string password, string passwordHash, string salt)
            {
                using (var sha256 = SHA256.Create())
                {
                    // Хеширование введенного пароля с использованием соли
                    string hashedPassword = HashPassword(password, salt);
                    // Сравнение хешей паролей
                    return string.Equals(hashedPassword, passwordHash);
                }
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create([Bind("Id,Username,PasswordHash,Role,Salt")] Users users)
        {
            if (ModelState.IsValid)
            {
                _context.Add(users);
                await _context.SaveChangesAsync();
                return RedirectToAction(nameof(Index));
            }
            return RedirectToAction("CloudStorage", "Users");
        }

        private bool UsersExists(string id)
        {
            return _context.Users.Any(e => e.Id == id);
        }


        public async Task<IActionResult> CloudStorage(string searchQuery, string sortOrder, int? page)
        {
            var currentUser = await _context.Users.FirstOrDefaultAsync(u => u.Username == User.Identity.Name);

            if (currentUser == null)
            {
                return RedirectToAction("Login", "Users");
            }

            var query = from file in _context.Files
                        join access in _context.FileAccesses
                        on file.FileID equals access.FileID
                        where (access.UserID == currentUser.Id && access.AccessType.HasFlag(AccessType.Read))
                            || currentUser.Role == UserRole.Admin
                        select file;

            if (!string.IsNullOrEmpty(searchQuery))
            {
                query = query.Where(f => f.FileName.Contains(searchQuery));
            }

            switch (sortOrder)
            {
                case "name":
                    query = query.OrderBy(f => f.FileName);
                    break;
                case "date":
                    query = query.OrderByDescending(f => f.UploadDate);
                    break;
                default:
                    query = query.OrderByDescending(f => f.UploadDate);
                    break;
            }

            var pageSize = 10; // Количество элементов на странице
            var pageNumber = page ?? 1; // Номер текущей страницы

            var sortedFiles = await query.ToListAsync();

            var uniqueFiles = sortedFiles.GroupBy(f => f.FileID).Select(g => g.First());

            var paginatedFiles = uniqueFiles.Skip((pageNumber - 1) * pageSize).Take(pageSize).ToList();

            ViewBag.TotalPages = (int)Math.Ceiling((double)uniqueFiles.Count() / pageSize);
            ViewBag.CurrentPage = pageNumber;

            return View(paginatedFiles);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> CloudStoragePost(string searchQuery)
        {
            return RedirectToAction("CloudStorage", new { searchQuery });
        }

        [HttpPost]
        public async Task<IActionResult> CloudStorage()
        {
            if (Request.ContentType.StartsWith("multipart/form-data") && Request.Form.Files.Count > 0)
            {
                var file = Request.Form.Files[0];
                if (file != null && file.Length > 0)
                {
                    var currentUser = await _context.Users.FirstOrDefaultAsync(u => u.Username == User.Identity.Name);

                    if (currentUser == null)
                    {
                        return RedirectToAction("Login", "Users");
                    }

                    // Генерируем ключ и вектор инициализации
                    byte[] key = GenerateRandomBytes(32); // 256 бит
                    byte[] iv = GenerateRandomBytes(16); // 128 бит

                    AesEncryption encryptionService = new AesEncryption(key, iv);

                    // Создаем новое имя для зашифрованного файла
                    string encryptedFileName = Guid.NewGuid().ToString() + Path.GetExtension(file.FileName);

                    // Полный путь к зашифрованному файлу
                    string encryptedFilePath = Path.Combine(Path.GetTempPath(), encryptedFileName);
                    // Temporary file path with original name and extension
                    var tempFilePath = Path.Combine(Path.GetTempPath(), file.FileName);


                    using (var inputStream = file.OpenReadStream())
                    {
                        using (var fileStream = System.IO.File.Create(tempFilePath))
                        {
                            await inputStream.CopyToAsync(fileStream);
                        } // Поток fileStream автоматически закрывается здесь
                    }

                    // Шифруем содержимое файла и сохраняем зашифрованный файл
                    encryptionService.EncryptFile(tempFilePath, encryptedFilePath);

                    try
                    {
                        string fileHash = await CalculateFileHashAsync(tempFilePath);

                        // Создание нового объекта Files
                        var newFile = new Files
                        {
                            FileID = encryptedFileName, // Генерация нового GUID
                            FileName = file.FileName, // Используем новое имя зашифрованного файла
                            FileHash = fileHash, //GetFileHash(tempFilePath), // Получение хеша файла
                            EncryptionKey = Convert.ToBase64String(key), // Преобразование ключа в строку для сохранения
                            InitializationVector = Convert.ToBase64String(iv), // Преобразование вектора инициализации в строку для сохранения
                            OwnerID = currentUser.Id, // Присвоение ID текущего пользователя владельцем файла
                            UploadDate = DateTime.Now,
                        };

                        var newFileAccess = new Save_cloud.Models.FileAccess
                        {
                            AccessID = Guid.NewGuid().ToString(),
                            FileID = newFile.FileID,
                            UserID = currentUser.Id,
                            AccessType = AccessType.All
                        };
                        // Upload file to cloud storage
                        await _cloudStorageService.UploadFileAsync(encryptedFilePath, _storageFolder);

                        // Добавление нового файла в контекст базы данных
                        _context.Files.Add(newFile);

                        // Добавление нового файла в контекст базы данных
                        _context.FileAccesses.Add(newFileAccess);

                        await _context.SaveChangesAsync(); // Сохранение изменений в базе данных
                    }
                    catch (Exception ex)
                    {
                        ModelState.AddModelError(string.Empty, "File upload failed: " + ex.Message);
                    }
                    finally
                    {
                        if (System.IO.File.Exists(encryptedFilePath))
                        {
                            System.IO.File.Delete(encryptedFilePath);
                        }
                        if (System.IO.File.Exists(tempFilePath))
                        {
                            System.IO.File.Delete(tempFilePath);
                        }
                    }
                }
            }
            return RedirectToAction("CloudStorage");
        }

        public async Task<IActionResult> Download(string fileId)
        {
            string decryptedFilePath = string.Empty;
            string tempFilePath = string.Empty;
            try { 
                var file = await _context.Files.FirstOrDefaultAsync(f => f.FileID == fileId);

                string remoteFolderPath = $"disk:{_storageFolder}"+file.FileID;
                string tempFileName = file.FileID;

                // Путь к файлу на сервере
                tempFilePath = Path.Combine(Path.GetTempPath(),file.FileID);
                decryptedFilePath = Path.Combine(Path.GetTempPath(), file.FileName);
                if (file == null)
                {
                    return View("FileNotFound"); // Возвращаем представление с сообщением об ошибке
                }
                // Получаем текущего пользователя из контекста запроса
                var currentUser = await _context.Users.FirstOrDefaultAsync(u => u.Username == User.Identity.Name);
                if (currentUser == null)
                {
                    return RedirectToAction("Login", "Users"); // Перенаправляем на страницу входа, если пользователь не аутентифицирован
                }

                if (currentUser.Role != UserRole.Admin)
                {
                    // Проверяем доступ пользователя к файлу, если он не администратор
                    var fileAccessList = await _context.FileAccesses
                        .Where(fa => fa.FileID == file.FileID && fa.UserID == currentUser.Id)
                        .ToListAsync();

                    if (fileAccessList.Count == 0 || !fileAccessList.Any(fa => fa.AccessType.HasFlag(AccessType.Read)))
                    {
                        return Forbid(); // Если у пользователя нет доступа к чтению файла, возвращаем ошибку 403
                    }
                }

                if (file.EncryptionKey == null)
                {
                    // Обработка ситуации, когда ключ шифрования отсутствует
                    ModelState.AddModelError(string.Empty, "Encryption key is missing.");
                    return View("Error");
                }
                if (file.InitializationVector == null)
                {
                    // Обработка ситуации, когда ключ шифрования отсутствует
                    ModelState.AddModelError(string.Empty, "Initialization vector is missing.");
                    return View("Error");
                }
                await _cloudStorageService.DownloadFileAsync(remoteFolderPath, Path.GetTempPath());
                byte[] key = Convert.FromBase64String(file.EncryptionKey); // 256 бит
                byte[] iv = Convert.FromBase64String(file.InitializationVector); // 128 бит
                AesEncryption encryptionService = new AesEncryption(key, iv);
                encryptionService.DecryptFile(tempFilePath, decryptedFilePath);

                string fileHash = await CalculateFileHashAsync(decryptedFilePath);
                if(fileHash == file.FileHash)
                {
                    // Проверяем существует ли файл
                    if (!System.IO.File.Exists(decryptedFilePath))
                    {
                        ModelState.AddModelError(string.Empty, "File not found or has been deleted.");
                        return View("FileNotFound"); // Возвращаем представление с сообщением об ошибке
                    }
                    // Чтение файла в виде массива байтов
                    byte[] fileBytes = await System.IO.File.ReadAllBytesAsync(decryptedFilePath);
                    // Определение MIME типа файла
                    string mimeType = "application/octet-stream";
                    return File(fileBytes, mimeType, file.FileName);
                }
                else { throw new Exception(message: "The file hashes do not match."); }
            }
            catch (Exception ex)
            {
                ModelState.AddModelError(string.Empty, "File download failed: " + ex.Message);
                return View("HashesNotMatch"); // Возвращаем представление с сообщением об ошибке
            }
            finally
            {
                if (System.IO.File.Exists(decryptedFilePath))
                {
                    System.IO.File.Delete(decryptedFilePath);
                }
                if (System.IO.File.Exists(tempFilePath))
                {
                    System.IO.File.Delete(tempFilePath);
                }
            }
        }

        [HttpGet]
        public async Task<IActionResult> Edit(string fileId, int page = 1, string search = "")
        {
            int pageSize = 12; // Количество пользователей на одной странице
                               // Получить информацию о файле из базы данных
            AccessType userAccessType;
            var file = await _context.Files.FirstOrDefaultAsync(f => f.FileID == fileId);
            if (file == null)
            {
                return NotFound(); // Если файл не найден, возвращаем ошибку 404
            }
            // Проверяем доступ пользователя к изменению файла
            var currentUser = await _context.Users.FirstOrDefaultAsync(u => u.Username == User.Identity.Name);
            if (currentUser == null)
            {
                return RedirectToAction("Login", "Users");
            }
            if (currentUser.Role != UserRole.Admin)
            {
                // Получить все записи прав доступа для данного файла и текущего пользователя
                var fileAccesses = await _context.FileAccesses
                    .Where(fa => fa.FileID == fileId && fa.UserID == currentUser.Id)
                    .ToListAsync();

                // Объединить все типы доступа в один флаг
                userAccessType = fileAccesses.Any() ? fileAccesses.Select(fa => fa.AccessType).Aggregate((AccessType)0, (current, accessType) => current | accessType) : AccessType.None;
            }
            else { userAccessType = AccessType.All; }
            // Получить общее количество пользователей
            var totalUsers = _context.Users.AsQueryable();
            // Применить фильтр для поиска пользователей
            if (!string.IsNullOrEmpty(search))
            {
                totalUsers = totalUsers.Where(u => u.Username.Contains(search));
            }
            // Вычислить общее количество страниц
            int totalPages = (int)Math.Ceiling((double)totalUsers.Count() / pageSize);

            // Получить список пользователей для текущей страницы
            var users = await totalUsers
                .Skip((page - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync();
            // Передать данные о файле и доступные пользователи в представление
            ViewBag.FileId = fileId;
            ViewBag.FileName = Path.GetFileNameWithoutExtension(file.FileName);
            ViewBag.Users = users;
            ViewBag.TotalPages = totalPages;
            ViewBag.CurrentPage = page;
            ViewBag.Accesses = userAccessType;
            if (userAccessType.HasFlag(AccessType.Modify)|| userAccessType.HasFlag(AccessType.Write)|| userAccessType.HasFlag(AccessType.Share)) 
            {
                return View();
            }
            return RedirectToAction("CloudStorage", "Users");
        }



        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(string fileId, string newFileName, IFormFile newFile, List<string> selectedUsers, List<string> accessType)
        {
            var currentUser = await _context.Users.FirstOrDefaultAsync(u => u.Username == User.Identity.Name);
            if (currentUser == null)
            {
                return RedirectToAction("Login", "Users");
            }
            var file = await _context.Files.FirstOrDefaultAsync(f => f.FileID == fileId);
            if (file == null)
            {
                return NotFound();
            }
            string encryptedFileName = file.FileID;
            string encryptedFilePath = Path.Combine(Path.GetTempPath(), encryptedFileName);
            var tempFilePath = Path.Combine(Path.GetTempPath(), file.FileName);
            // Обработка загружаемого файла
            if (newFile != null && newFile.Length > 0)
            {
                try
                {

                    await _cloudStorageService.DeleteFileAsync(fileId);
                    // Обновить информацию о файле в базе данных
                    byte[] key = Convert.FromBase64String(file.EncryptionKey); // 256 бит
                    byte[] iv = Convert.FromBase64String(file.InitializationVector); // 128 бит

                    // Загрузить новый файл
                    using (var inputStream = newFile.OpenReadStream())
                    {
                        using (var fileStream = System.IO.File.Create(tempFilePath))
                        {
                            await inputStream.CopyToAsync(fileStream);
                        } // Поток fileStream автоматически закрывается здесь
                    }

                    AesEncryption encryptionService = new AesEncryption(key, iv);
                    encryptionService.EncryptFile(tempFilePath, encryptedFilePath);
                    string fileHash = await CalculateFileHashAsync(encryptedFilePath);

                    // Обновить информацию о файле
                    file.FileHash = fileHash; // Обновить хеш файла
                    file.UploadDate = DateTime.Now; // Обновить дату загрузки

                    await _cloudStorageService.UploadFileAsync(encryptedFilePath, _storageFolder);

                    await _context.SaveChangesAsync(); // Сохранить изменения в базе данных
                }
                catch (Exception ex)
                {
                    ModelState.AddModelError(string.Empty, "File upload failed: " + ex.Message);
                    // Обработка ошибок загрузки файла
                    return View("Error");
                }
                finally
                {
                    // Удалить старый файл из временной папки
                    if (System.IO.File.Exists(encryptedFilePath))
                    {
                        System.IO.File.Delete(encryptedFilePath);
                    }
                    // Удалить старый файл из временной папки
                    if (System.IO.File.Exists(tempFilePath))
                    {
                        System.IO.File.Delete(tempFilePath);
                    }
                }
            }
            if (currentUser.Role != UserRole.Admin)
            {
                var fileAccess = await _context.FileAccesses.FirstOrDefaultAsync(fa => fa.FileID == fileId && fa.UserID == currentUser.Id && fa.AccessType.HasFlag(AccessType.Modify));
                if (fileAccess == null)
                {
                    return Forbid();
                }
            }
            string extension = Path.GetExtension(file.FileName);
            newFileName += extension;
            file.FileName = newFileName;
            _context.Files.Update(file);
            // Обновить права доступа для выбранных пользователей
            foreach (var userId in selectedUsers)
            {
                if (((userId != file.OwnerID) && (userId != currentUser.Id)) || (currentUser.Role == UserRole.Admin))
                {
                    // Проверяем, является ли текущий пользователь администратором или не является ли он владельцем файла или текущим пользователем
                    AccessType access = AccessType.None; // Устанавливаем права доступа на None по умолчанию
                    foreach (var type in accessType)
                    {
                        switch (type)
                        {
                            case "Read":
                                access |= AccessType.Read;
                                break;
                            case "Write":
                                access |= AccessType.Write;
                                break;
                            case "Modify":
                                access |= AccessType.Modify;
                                break;
                            case "Delete":
                                access |= AccessType.Delete;
                                break;
                            case "Share":
                                access |= AccessType.Share;
                                break;
                                // Добавьте новые типы доступа, если необходимо
                        }
                    }
                    if (access == AccessType.None)
                    {
                        // Если выбраны права доступа None, удаляем все существующие доступы пользователя к файлу
                        var existingAccesses = await _context.FileAccesses
                            .Where(fa => fa.FileID == fileId && fa.UserID == userId)
                            .ToListAsync();

                        _context.FileAccesses.RemoveRange(existingAccesses);
                    }
                    else
                    {
                        // Если выбраны другие типы доступа, добавляем или обновляем соответствующие доступы
                        var existingAccess = await _context.FileAccesses
                            .FirstOrDefaultAsync(fa => fa.FileID == fileId && fa.UserID == userId);

                        if (existingAccess != null)
                        {
                            // Если доступ уже существует, обновляем его
                            existingAccess.AccessType = access;
                        }
                        else
                        {
                            // Если доступа нет, создаем новый
                            var newAccess = new Save_cloud.Models.FileAccess
                            {
                                AccessID = Guid.NewGuid().ToString(),
                                FileID = fileId,
                                UserID = userId,
                                AccessType = access
                            };
                            _context.FileAccesses.Add(newAccess);
                        }
                    }
                }
            }
            await _context.SaveChangesAsync(); // Сохранить изменения в базе данных
            return RedirectToAction("Edit", new { fileId = fileId });
        }


        [HttpGet]
        public async Task<IActionResult> SearchUsers(string fileId, string search)
        {
            var currentUser = await _context.Users.FirstOrDefaultAsync(u => u.Username == User.Identity.Name);
            if (currentUser == null)
            {
                return RedirectToAction("Login", "Users");
            }

            var foundUsers = await _context.Users
                .Where(u => u.Username.Contains(search))
                .ToListAsync();

            return PartialView("_UserSearchResults", foundUsers);
        }



        [HttpGet, ActionName("DeleteConfirmed")]
        public async Task<IActionResult> DeleteConfirmed(string fileId)
        {
            var currentUser = await _context.Users.FirstOrDefaultAsync(u => u.Username == User.Identity.Name);
            if (currentUser == null)
            {
                return RedirectToAction("Login", "Users");
            }
            // Проверяем доступ пользователя к удалению файла
            var fileAccess = await _context.FileAccesses.FirstOrDefaultAsync(fa => fa.FileID == fileId && fa.UserID == currentUser.Id && fa.AccessType.HasFlag(AccessType.Delete));
            if (fileAccess == null)
            {
                return Forbid();
            }
            var file = await _context.Files.FirstOrDefaultAsync(f => f.FileID == fileId);
            if (file == null)
            {
                return NotFound();
            }
            try
            {
                _context.Files.Remove(file);
                await _context.SaveChangesAsync();
            }
            catch (Exception ex)
            {
                ModelState.AddModelError(string.Empty, "An error occurred while deleting the file: " + ex.Message);
                return View("Error");
            }
            await _cloudStorageService.DeleteFileAsync(fileId);
            return RedirectToAction("CloudStorage");

        }




        // Генерация случайных байтов для ключа и вектора инициализации
        private static byte[] GenerateRandomBytes(int length)
        {
            using (var rng = new RNGCryptoServiceProvider())
            {
                byte[] randomBytes = new byte[length];
                rng.GetBytes(randomBytes);
                return randomBytes;
            }
        }

        private async Task<string> CalculateFileHashAsync(string filePath)
        {
            using (var md5 = MD5.Create())
            {
                using (var stream = System.IO.File.OpenRead(filePath))
                {
                    return await Task.Run(() =>
                    {
                        byte[] hashBytes = md5.ComputeHash(stream);
                        return BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
                    });
                }
            }
        }
    }
}

