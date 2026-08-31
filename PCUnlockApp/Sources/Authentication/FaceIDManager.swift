// Feature: pc-unlock
// FaceIDManager — wraps LocalAuthentication.LAContext for biometric gating.
// Requirements: 2.1, 2.2, 2.3

import Foundation
import LocalAuthentication

// MARK: - Protocol

/// Defines the contract for performing Face ID / biometric authentication.
///
/// All downstream signing is conditioned on a `.success` result.
/// Biometric data never leaves the device.
public protocol FaceIDManaging {
    /// Performs biometric authentication and returns the result.
    ///
    /// - Parameter reason: A human-readable explanation shown to the user.
    /// - Returns: `.success(())` when authentication succeeds, or
    ///            `.failure(LAError)` for any failure condition.
    func authenticate(reason: String) async -> Result<Void, LAError>
}

// MARK: - Concrete implementation

/// Wraps `LAContext` to perform Face ID authentication via the
/// `LocalAuthentication` framework.
///
/// Biometric data and results are never surfaced to callers — only a typed
/// `Result<Void, LAError>` is returned.
public final class FaceIDManager: FaceIDManaging {

    private let context: LAContext

    /// Creates a `FaceIDManager`.
    ///
    /// - Parameter context: The `LAContext` to use.  Defaults to a fresh
    ///   context.  Inject a custom context during testing.
    public init(context: LAContext = LAContext()) {
        self.context = context
    }

    public func authenticate(reason: String) async -> Result<Void, LAError> {
        await withCheckedContinuation { continuation in
            context.evaluatePolicy(
                .deviceOwnerAuthenticationWithBiometrics,
                localizedReason: reason
            ) { success, error in
                if success {
                    continuation.resume(returning: .success(()))
                } else {
                    let laError = (error as? LAError)
                        ?? LAError(.authenticationFailed)
                    continuation.resume(returning: .failure(laError))
                }
            }
        }
    }
}
