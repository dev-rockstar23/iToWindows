// Feature: pc-unlock
// PCUnlockService — Windows service entry point.
// Wires all components and runs as a Windows Service via SCM.
// Requirements: 8.1, 8.2, 8.6

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using PCUnlockService.ServiceHost;

var host = Host.CreateDefaultBuilder(args)
    .UseWindowsService(options =>
    {
        options.ServiceName = "PCUnlockService";
    })
    .ConfigureServices(services =>
    {
        services.AddHostedService<PCUnlockWindowsService>();
    })
    .Build();

await host.RunAsync();
