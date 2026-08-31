// Feature: pc-unlock
// PCUnlockWindowsService — Windows service host that wires all components together.
// Requirements: 8.1, 8.2, 8.3, 8.6, 8.7

using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using PCUnlockService.BLE;
using PCUnlockService.Crypto;
using PCUnlockService.Logging;
using PCUnlockService.Pipe;
using PCUnlockService.Registry;
using PCUnlockService.Session;

namespace PCUnlockService.ServiceHost;

/// <summary>
/// Windows service host that instantiates and starts all PCUnlock components.
/// </summary>
/// <remarks>
/// Component wiring:
/// - <see cref="ConsumedNonceStore"/> — loaded on start
/// - <see cref="DeviceRegistry"/>   — integrity checked on start
/// - <see cref="SecurityLogger"/>   — fires-and-forgets to Windows Event Log
/// - <see cref="BLECentral"/>       — scans on unlock request
/// - <see cref="SessionNonceManager"/> — generates challenges, validates responses
/// - <see cref="CNGCryptoVerifier"/> — verifies ECDSA-P256 signatures
/// - <see cref="PipeMessageDispatcher"/> — routes Named Pipe messages
/// - <see cref="NamedPipeServer"/>  — listens on \\.\pipe\PCUnlockService
/// </remarks>
public sealed class PCUnlockWindowsService : BackgroundService
{
    private readonly ILogger<PCUnlockWindowsService> _logger;
    private NamedPipeServer? _pipeServer;

    public PCUnlockWindowsService(ILogger<PCUnlockWindowsService> logger)
    {
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("PCUnlockService: starting.");

        // ── Construct components ─────────────────────────────────────────────
        var nonceStore      = new ConsumedNonceStore();
        var deviceRegistry  = new DeviceRegistry();
        var securityLogger  = new SecurityLogger("PCUnlock");
        var cryptoVerifier  = new CNGCryptoVerifier();

        // ── Load nonce store ─────────────────────────────────────────────────
        try
        {
            nonceStore.Load();
            _logger.LogInformation("PCUnlockService: nonce store loaded.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "PCUnlockService: failed to load nonce store.");
        }

        // ── Verify Device Registry integrity (Requirement 8.3) ──────────────
        if (!deviceRegistry.VerifyIntegrity())
        {
            _logger.LogError(
                "PCUnlockService: Device Registry integrity check failed (REGISTRY_CORRUPT). " +
                "Unlock requests will be rejected until the registry is repaired.");
        }
        else
        {
            _logger.LogInformation("PCUnlockService: Device Registry integrity verified.");
        }

        // ── Construct session manager and BLE central ────────────────────────
        var loggerFactory = LoggerFactory.Create(b => b.AddEventLog());
        var sessionLogger = loggerFactory.CreateLogger<SessionNonceManager>();
        var sessionManager = new SessionNonceManager(nonceStore, sessionLogger);

        var bleLogger  = loggerFactory.CreateLogger<BLECentral>();
        var bleCentral = new BLECentral(bleLogger);

        // ── Construct pipe dispatcher and server ─────────────────────────────
        var dispatcherLogger = loggerFactory.CreateLogger<PipeMessageDispatcher>();
        var dispatcher = new PipeMessageDispatcher(
            sessionManager,
            cryptoVerifier,
            nonceStore,
            deviceRegistry,
            securityLogger,
            bleCentral,
            dispatcherLogger);

        var pipeLogger = loggerFactory.CreateLogger<NamedPipeServer>();
        _pipeServer = new NamedPipeServer(dispatcher, pipeLogger);

        // ── Start Named Pipe Server ──────────────────────────────────────────
        _logger.LogInformation("PCUnlockService: starting Named Pipe server.");

        try
        {
            await _pipeServer.StartAsync(stoppingToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // Normal shutdown.
        }
        catch (Exception ex)
        {
            _logger.LogError(ex,
                "PCUnlockService: Named Pipe server failed to start (Requirement 8.2). " +
                "Service will stop.");
            throw;
        }
        finally
        {
            // ── Flush nonce store on shutdown ────────────────────────────────
            _logger.LogInformation("PCUnlockService: stopping.");
            bleCentral.Dispose();
        }
    }

    public override void Dispose()
    {
        _pipeServer?.Stop();
        base.Dispose();
    }
}
