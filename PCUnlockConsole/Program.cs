// Feature: pc-unlock — Development Console entry point
// Dispatches subcommands: keygen, sign, verify, ble-sim, pair
// Requirements: 12.1, 12.2, 12.3, 12.4, 12.5

using PCUnlockConsole.Commands;
using PCUnlockConsole.Commands.BleSim;

if (args.Length == 0)
{
    PrintUsage();
    return 1;
}

string subcommand = args[0].ToLowerInvariant();
string[] remaining = args[1..];

return subcommand switch
{
    "keygen"  => KeygenCommand.Run(remaining),
    "sign"    => SignCommand.Run(remaining),
    "verify"  => VerifyCommand.Run(remaining),
    "ble-sim" => RunBleSim(remaining),
    "pair"    => RunPair(remaining),
    "--help"  => PrintUsageAndReturn(),
    "-h"      => PrintUsageAndReturn(),
    _ => UnknownSubcommand(subcommand)
};

static int RunBleSim(string[] args)
{
    if (args.Length == 0)
    {
        Console.Error.WriteLine("Usage: pcunlock ble-sim peripheral|central");
        return 1;
    }

    return args[0].ToLowerInvariant() switch
    {
        "peripheral" => PCUnlockConsole.Commands.BleSim.BleSimPeripheralCommand
                            .RunAsync(args[1..]).GetAwaiter().GetResult(),
        "central"    => PCUnlockConsole.Commands.BleSim.BleSimCentralCommand
                            .RunAsync(args[1..]).GetAwaiter().GetResult(),
        _ => UnknownSubcommand($"ble-sim {args[0]}")
    };
}

static int RunPair(string[] args)
{
    return PairCommand.RunAsync(args).GetAwaiter().GetResult();
}

static int UnknownSubcommand(string name)
{
    Console.Error.WriteLine($"pcunlock: unknown subcommand '{name}'");
    Console.Error.WriteLine("Run 'pcunlock --help' for usage.");
    return 1;
}

static void PrintUsage()
{
    Console.Error.WriteLine("""
        pcunlock — PCUnlock development console

        Usage:
          pcunlock keygen [--out <keyfile>]
              Generate ECC P-256 key pair; print public key as hex uncompressed point;
              save private key to <keyfile> (default: pcunlock.key).

          pcunlock sign --challenge <hex> --key <keyfile>
              Sign challenge bytes with ECDSA-P256-SHA256; print DER signature as hex.

          pcunlock verify --challenge <hex> --sig <hex> --pubkey <hex>
              Verify DER signature against challenge and public key.
              Exit 0 on success, 1 on failure.

          pcunlock ble-sim peripheral|central
              Simulate iPhone BLE peripheral or PC BLE central role. (not yet implemented)

          pcunlock pair --role pc|iphone
              Run one side of the pairing flow. (not yet implemented)
        """);
}

static int PrintUsageAndReturn()
{
    PrintUsage();
    return 0;
}
