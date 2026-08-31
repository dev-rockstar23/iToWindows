// Feature: pc-unlock
// PairingPayload — QR code payload transmitted from PC to iPhone during pairing.
// Requirements: 6.1, 6.3

using System.Text.Json.Serialization;

namespace PCUnlockService.Pairing;

/// <summary>
/// The JSON payload encoded into the pairing QR code.
/// </summary>
/// <remarks>
/// Wire format:
/// <code>
/// { "v": 1, "pcId": "&lt;base64url-pcIdentityToken&gt;", "code": "A3X7KQ", "svc": "&lt;base64url-BLE-service-UUID&gt;" }
/// </code>
/// <list type="bullet">
///   <item><c>v</c>   — protocol version (always 1).</item>
///   <item><c>pcId</c> — Base64Url-encoded 16-byte <c>pcIdentityToken</c>.</item>
///   <item><c>code</c> — 6-character alphanumeric uppercase Pairing_Code.</item>
///   <item><c>svc</c>  — Base64Url-encoded bytes of the BLE Pairing service UUID.</item>
/// </list>
/// </remarks>
public sealed record PairingPayload
{
    /// <summary>Protocol version. Currently 1.</summary>
    [JsonPropertyName("v")]
    public int V { get; init; }

    /// <summary>Base64Url-encoded 16-byte PC identity token.</summary>
    [JsonPropertyName("pcId")]
    public string PcId { get; init; } = string.Empty;

    /// <summary>6-character alphanumeric uppercase Pairing_Code.</summary>
    [JsonPropertyName("code")]
    public string Code { get; init; } = string.Empty;

    /// <summary>Base64Url-encoded bytes of the BLE Pairing service UUID.</summary>
    [JsonPropertyName("svc")]
    public string Svc { get; init; } = string.Empty;

    /// <summary>
    /// Creates a <see cref="PairingPayload"/> from raw values, encoding the
    /// binary fields as Base64Url strings.
    /// </summary>
    public static PairingPayload Create(
        byte[] pcIdentityToken,
        string pairingCode,
        Guid bleServiceUuid)
    {
        ArgumentNullException.ThrowIfNull(pcIdentityToken);
        ArgumentNullException.ThrowIfNull(pairingCode);

        return new PairingPayload
        {
            V     = 1,
            PcId  = Base64UrlEncode(pcIdentityToken),
            Code  = pairingCode,
            Svc   = Base64UrlEncode(bleServiceUuid.ToByteArray()),
        };
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /// <summary>Encodes <paramref name="bytes"/> as Base64Url (no padding).</summary>
    public static string Base64UrlEncode(byte[] bytes)
        => Convert.ToBase64String(bytes)
               .Replace('+', '-')
               .Replace('/', '_')
               .TrimEnd('=');

    /// <summary>Decodes a Base64Url string (with or without padding) to bytes.</summary>
    public static byte[] Base64UrlDecode(string value)
    {
        // Re-add padding removed during encoding.
        string padded = (value.Length % 4) switch
        {
            2 => value + "==",
            3 => value + "=",
            _ => value,
        };
        return Convert.FromBase64String(
            padded.Replace('-', '+').Replace('_', '/'));
    }
}
