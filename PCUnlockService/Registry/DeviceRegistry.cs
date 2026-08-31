// Feature: pc-unlock
// DeviceRegistry — DPAPI-encrypted, atomically-written device record store.
// Requirements: 3.4, 3.5, 8.3, 9.2, 9.4

using System.Security.Cryptography;
using System.Text.Json;
using PCUnlockService.Pairing;

namespace PCUnlockService.Registry;

/// <summary>
/// Implements <see cref="IDeviceRegistry"/> using a DPAPI-encrypted JSON file.
/// File format: <c>magic[4] + version[4] + blob_len[4] + DPAPI blob</c> where
/// the blob decrypts to a UTF-8 JSON array of <see cref="DeviceRecord"/> objects.
/// File path: <c>%APPDATA%\PCUnlock\devices.dat</c> (per-user).
/// </summary>
public sealed class DeviceRegistry : IDeviceRegistry
{
    // -------------------------------------------------------------------------
    // Constants
    // -------------------------------------------------------------------------

    private static readonly byte[] Magic = { 0x50, 0x43, 0x4B, 0x52 }; // "PCKR"
    private const int FormatVersion = 1;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = false,
        PropertyNameCaseInsensitive = true,
    };

    // -------------------------------------------------------------------------
    // State
    // -------------------------------------------------------------------------

    private readonly string _filePath;

    // -------------------------------------------------------------------------
    // Construction
    // -------------------------------------------------------------------------

    /// <summary>
    /// Creates a <see cref="DeviceRegistry"/> using the default
    /// <c>%APPDATA%\PCUnlock\devices.dat</c> path.
    /// </summary>
    public DeviceRegistry()
        : this(DefaultFilePath()) { }

    /// <summary>
    /// Creates a <see cref="DeviceRegistry"/> using a custom file path.
    /// Useful for testing.
    /// </summary>
    public DeviceRegistry(string filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath))
            throw new ArgumentException("File path must not be empty.", nameof(filePath));
        _filePath = filePath;
    }

    // -------------------------------------------------------------------------
    // IDeviceRegistry
    // -------------------------------------------------------------------------

    /// <inheritdoc/>
    public IReadOnlyList<DeviceRecord> ReadAll()
    {
        if (!File.Exists(_filePath))
            return Array.Empty<DeviceRecord>();

        try
        {
            byte[] fileBytes = File.ReadAllBytes(_filePath);
            byte[] jsonBytes = Decrypt(fileBytes);
            var records = JsonSerializer.Deserialize<List<DeviceRecord>>(jsonBytes, JsonOptions);
            return records ?? Array.Empty<DeviceRecord>();
        }
        catch (DeviceRegistryException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new DeviceRegistryException("Failed to read Device Registry.", ex);
        }
    }

    /// <inheritdoc/>
    public void Write(IReadOnlyList<DeviceRecord> records)
    {
        ArgumentNullException.ThrowIfNull(records);

        try
        {
            byte[] jsonBytes = JsonSerializer.SerializeToUtf8Bytes(records, JsonOptions);
            byte[] fileBytes = Encrypt(jsonBytes);
            AtomicWrite(fileBytes);
        }
        catch (DeviceRegistryException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new DeviceRegistryException("Failed to write Device Registry.", ex);
        }
    }

    /// <inheritdoc/>
    public void Append(DeviceRecord record)
    {
        ArgumentNullException.ThrowIfNull(record);
        var existing = ReadAll().ToList();
        existing.Add(record);
        Write(existing);
    }

    /// <inheritdoc/>
    public void Remove(Guid deviceId)
    {
        var existing = ReadAll().ToList();
        int before = existing.Count;
        existing.RemoveAll(r => r.DeviceId == deviceId);

        if (existing.Count == before)
            throw new DeviceRegistryException($"Device not found in registry: {deviceId}");

        Write(existing);
    }

    /// <inheritdoc/>
    public bool Contains(Guid deviceId) =>
        ReadAll().Any(r => r.DeviceId == deviceId);

    /// <inheritdoc/>
    public DeviceRecord? Get(Guid deviceId) =>
        ReadAll().FirstOrDefault(r => r.DeviceId == deviceId);

    /// <inheritdoc/>
    public bool VerifyIntegrity()
    {
        try
        {
            var records = ReadAll();
            return records.All(r =>
                r.DeviceId != Guid.Empty &&
                !string.IsNullOrEmpty(r.DeviceName) &&
                r.PublicKeyDER.Length > 0);
        }
        catch
        {
            return false;
        }
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /// <summary>Encrypts JSON bytes using DPAPI (per-user scope).</summary>
    private static byte[] Encrypt(byte[] jsonBytes)
    {
        byte[] blob = ProtectedData.Protect(
            jsonBytes,
            optionalEntropy: null,
            scope: DataProtectionScope.CurrentUser);

        // Build file: magic[4] + version[4 LE] + blob_len[4 LE] + blob
        using var ms = new MemoryStream();
        ms.Write(Magic);
        ms.Write(BitConverter.GetBytes(FormatVersion));
        ms.Write(BitConverter.GetBytes(blob.Length));
        ms.Write(blob);
        return ms.ToArray();
    }

    /// <summary>Decrypts DPAPI file bytes to JSON bytes.</summary>
    private static byte[] Decrypt(byte[] fileBytes)
    {
        if (fileBytes.Length < 12)
            throw new DeviceRegistryException("Device Registry file is too short to be valid.");

        // Validate magic
        for (int i = 0; i < 4; i++)
        {
            if (fileBytes[i] != Magic[i])
                throw new DeviceRegistryException("Device Registry file has invalid magic bytes (REGISTRY_CORRUPT).");
        }

        int blobLen = BitConverter.ToInt32(fileBytes, 8);
        if (fileBytes.Length < 12 + blobLen)
            throw new DeviceRegistryException("Device Registry file is truncated.");

        byte[] blob = fileBytes[12..(12 + blobLen)];

        try
        {
            return ProtectedData.Unprotect(blob, null, DataProtectionScope.CurrentUser);
        }
        catch (CryptographicException ex)
        {
            throw new DeviceRegistryException("Failed to decrypt Device Registry (REGISTRY_CORRUPT).", ex);
        }
    }

    /// <summary>Writes <paramref name="data"/> atomically via a temp-then-rename.</summary>
    private void AtomicWrite(byte[] data)
    {
        string? directory = Path.GetDirectoryName(_filePath);
        if (!string.IsNullOrEmpty(directory))
            Directory.CreateDirectory(directory);

        string tempPath = Path.Combine(
            directory ?? Path.GetTempPath(),
            Path.GetRandomFileName());

        try
        {
            File.WriteAllBytes(tempPath, data);
            File.Move(tempPath, _filePath, overwrite: true);
        }
        catch
        {
            try { File.Delete(tempPath); } catch { /* best-effort cleanup */ }
            throw;
        }
    }

    private static string DefaultFilePath() =>
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "PCUnlock",
            "devices.dat");
}
