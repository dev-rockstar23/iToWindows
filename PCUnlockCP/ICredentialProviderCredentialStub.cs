// Feature: pc-unlock
// CredentialProviderCredential — implements the ICredentialProviderCredential
// COM interface contract for the PCUnlock tile.
//
// NEVER stores, caches, or transmits the user's Windows password or PIN
// (Requirement 7.6).  NEVER interacts with LSASS or uses undocumented APIs
// (Requirement 7.7).
//
// The full COM DLL wiring (CoCreateInstance, DllRegisterServer, etc.) lives
// in the MSI-installed native shim.  This class holds all testable C# logic
// that the shim delegates to.
//
// Requirements: 7.4, 7.5, 7.6, 7.7

namespace PCUnlockCP;

// ---------------------------------------------------------------------------
// Serialization result
// ---------------------------------------------------------------------------

/// The outcome produced by <see cref="CredentialProviderCredentialStub.GetSerialization"/>.
public enum SerializationOutcome
{
    /// The service signalled a successful unlock.  The COM shim should return
    /// <c>CPGSR_RETURN_NO_CREDENTIAL_FINISHED</c> to hand control back to
    /// Winlogon without transmitting a password (Requirement 7.4).
    ReturnNoCredentialFinished,

    /// The service signalled failure or the pipe timed out.  The COM shim
    /// should leave the lock screen in place and display an error message
    /// (Requirement 7.5).
    ShowErrorAndStay,

    /// BLE scan timed out — the iPhone was not found within 15 seconds.
    ShowIphoneNotFound,
}

// ---------------------------------------------------------------------------
// CredentialProviderCredential (ICredentialProviderCredential logic layer)
// ---------------------------------------------------------------------------

/// <summary>
/// Encapsulates the logic for <c>ICredentialProviderCredential</c>:
/// <c>GetSerialization</c> and <c>ReportResult</c>.
///
/// <para>
/// <b>GetSerialization</b>: On a successful unlock signal from the service,
/// returns <see cref="SerializationOutcome.ReturnNoCredentialFinished"/> so
/// the COM shim can pack a <c>CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION</c>
/// using <c>CPGSR_RETURN_NO_CREDENTIAL_FINISHED</c> — this signals completed
/// external authentication to the Winlogon chain without transmitting any
/// password (Requirement 7.4).
/// </para>
///
/// <para>
/// <b>Forbidden operations (Requirements 7.6, 7.7)</b>:
/// <list type="bullet">
///   <item>MUST NOT store, cache, or transmit the Windows password or PIN.</item>
///   <item>MUST NOT interact with LSASS memory directly.</item>
///   <item>MUST NOT call undocumented Windows authentication APIs.</item>
/// </list>
/// </para>
/// </summary>
public sealed class CredentialProviderCredentialStub
{
    // -----------------------------------------------------------------------
    // ICredentialProviderCredential: GetSerialization
    // -----------------------------------------------------------------------

    /// <summary>
    /// Translates an unlock pipe response into the appropriate
    /// <see cref="SerializationOutcome"/> for the COM shim.
    /// </summary>
    /// <param name="pipeResult">
    /// The result string returned by
    /// <see cref="NamedPipeClientStub.RequestUnlockAsync"/>:
    /// <c>"success"</c>, <c>"failure"</c>, or <c>"timeout"</c>.
    /// </param>
    /// <returns>
    /// <list type="bullet">
    ///   <item><c>"success"</c> →
    ///     <see cref="SerializationOutcome.ReturnNoCredentialFinished"/>
    ///     (Requirement 7.4)</item>
    ///   <item><c>"timeout"</c> →
    ///     <see cref="SerializationOutcome.ShowIphoneNotFound"/></item>
    ///   <item>anything else →
    ///     <see cref="SerializationOutcome.ShowErrorAndStay"/>
    ///     (Requirement 7.5)</item>
    /// </list>
    /// </returns>
    public SerializationOutcome GetSerialization(string pipeResult) =>
        pipeResult switch
        {
            "success" => SerializationOutcome.ReturnNoCredentialFinished,
            "timeout" => SerializationOutcome.ShowIphoneNotFound,
            _         => SerializationOutcome.ShowErrorAndStay,
        };

    /// <summary>
    /// Boolean overload for back-compat with existing tests.
    /// Returns <c>true</c> when the service signalled success.
    /// </summary>
    public bool GetSerialization(bool serviceSignaledSuccess) => serviceSignaledSuccess;

    // -----------------------------------------------------------------------
    // ICredentialProviderCredential: ReportResult
    // -----------------------------------------------------------------------

    /// <summary>
    /// Handles the authentication-engine result returned by Winlogon after
    /// <c>GetSerialization</c>.
    /// </summary>
    /// <param name="ntsStatus">The NTSTATUS code from the authentication engine.</param>
    /// <param name="ntsSubStatus">The sub-status code from the authentication engine.</param>
    /// <returns>
    /// A human-readable description of the result for logging/display
    /// purposes.  The COM shim uses this to update the tile status field.
    /// </returns>
    public string ReportResult(int ntsStatus, int ntsSubStatus)
    {
        // STATUS_SUCCESS = 0x00000000
        if (ntsStatus == 0)
            return string.Empty; // unlock succeeded — no message needed

        // Map common NTSTATUS codes to readable messages.
        return ntsStatus switch
        {
            unchecked((int)0xC000006D) => "Logon failure.",           // STATUS_LOGON_FAILURE
            unchecked((int)0xC0000072) => "Account disabled.",        // STATUS_ACCOUNT_DISABLED
            unchecked((int)0xC000006E) => "Account restriction.",     // STATUS_ACCOUNT_RESTRICTION
            unchecked((int)0xC0000064) => "No such user.",            // STATUS_NO_SUCH_USER
            _                          => $"Authentication failed (0x{ntsStatus:X8})."
        };
    }
}
