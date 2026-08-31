// Feature: pc-unlock
// PipeMessages — JSON-serializable message types for the Named Pipe IPC channel.
// Requirements: 7.3, 8.1, 8.7

using System.Text.Json.Serialization;
using PCUnlockService.Pairing;

namespace PCUnlockService.Pipe;

// ---------------------------------------------------------------------------
// Requests (CP → Service)
// ---------------------------------------------------------------------------

public sealed record UnlockRequest
{
    [JsonPropertyName("type")]    public string Type        { get; init; } = "unlock_request";
    [JsonPropertyName("userId")]  public string UserId      { get; init; } = string.Empty;
    [JsonPropertyName("sessionHint")] public string? SessionHint { get; init; }
}

public sealed record RemoveDeviceRequest
{
    [JsonPropertyName("type")]     public string Type     { get; init; } = "remove_device";
    [JsonPropertyName("deviceId")] public string DeviceId { get; init; } = string.Empty;
}

public sealed record ListDevicesRequest
{
    [JsonPropertyName("type")] public string Type { get; init; } = "list_devices";
}

// ---------------------------------------------------------------------------
// Responses (Service → CP)
// ---------------------------------------------------------------------------

public sealed record UnlockResponse
{
    [JsonPropertyName("type")]   public string  Type   { get; init; } = "unlock_response";
    [JsonPropertyName("result")] public string  Result { get; init; } = "failure";
    [JsonPropertyName("reason")] public string? Reason { get; init; }
}

public sealed record RemoveDeviceResponse
{
    [JsonPropertyName("type")]  public string  Type  { get; init; } = "remove_device_response";
    [JsonPropertyName("ok")]    public bool    Ok    { get; init; }
    [JsonPropertyName("error")] public string? Error { get; init; }
}

public sealed record ListDevicesResponse
{
    [JsonPropertyName("type")]    public string         Type    { get; init; } = "list_devices_response";
    [JsonPropertyName("devices")] public DeviceRecord[] Devices { get; init; } = Array.Empty<DeviceRecord>();
}

public sealed record ServiceStatusEvent
{
    [JsonPropertyName("type")]        public string Type        { get; init; } = "status_event";
    [JsonPropertyName("available")]   public bool   Available   { get; init; }
    [JsonPropertyName("pairedCount")] public int    PairedCount { get; init; }
}
