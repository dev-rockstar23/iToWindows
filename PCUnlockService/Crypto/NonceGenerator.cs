// Feature: pc-unlock
using System.Security.Cryptography;
namespace PCUnlockService.Crypto;
public static class NonceGenerator {
    public const int NonceLength = 32;
    public static byte[] Generate() => RandomNumberGenerator.GetBytes(NonceLength);
}
