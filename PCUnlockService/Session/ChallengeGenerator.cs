// Feature: pc-unlock
using PCUnlockService.Crypto;
using System.Buffers.Binary;
namespace PCUnlockService.Session;
public static class ChallengeGenerator {
    public const int ChallengeVersion = 1;
    public const int ChallengeTtlSeconds = 60;

    public static UnlockSession GenerateChallenge(string deviceId) => new() {
        SessionId = Guid.NewGuid(),
        Nonce = NonceGenerator.Generate(),
        ExpiresAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + ChallengeTtlSeconds,
        DeviceId = deviceId
    };

    // Returns canonical 57-byte encoding: [version:1][sessionId:16 BE][nonce:32][expiresAt:8 LE]
    public static byte[] EncodeChallenge(UnlockSession session) {
        var buf = new byte[57];
        buf[0] = (byte)ChallengeVersion;
        session.SessionId.ToByteArray().CopyTo(buf, 1);   // 16 bytes
        session.Nonce.CopyTo(buf, 17);                     // 32 bytes
        BinaryPrimitives.WriteInt64LittleEndian(buf.AsSpan(49), session.ExpiresAt); // 8 bytes
        return buf;
    }
}
