import Foundation
import SwiftProtobuf

public enum FileDefenderBridgeError: Error {
    case ffiError(String)
    case decodeError(String)
}

public struct FileDefenderOutput {
    public let verdict: Int32
    public let rebuiltFile: Data
    public let metadata: File_Defender_Ffi_Metadata
}

public final class FileDefenderBridge {
    public init() {}

    public func defend(data: Data, fileName: String?, tenantId: String?) throws -> FileDefenderOutput {
        let fileNameCString = fileName?.cString(using: .utf8)
        let tenantCString = tenantId?.cString(using: .utf8)

        return try data.withUnsafeBytes { rawBuffer in
            let inputPtr = rawBuffer.bindMemory(to: UInt8.self).baseAddress
            let inputLen = rawBuffer.count

            let result: FfiDefendResult = fileNameCString?.withUnsafeBufferPointer { nameBuffer in
                tenantCString?.withUnsafeBufferPointer { tenantBuffer in
                    file_defender_client_defend_default(
                        inputPtr,
                        inputLen,
                        nameBuffer.baseAddress,
                        tenantBuffer.baseAddress
                    )
                } ?? file_defender_client_defend_default(
                    inputPtr,
                    inputLen,
                    nameBuffer.baseAddress,
                    nil
                )
            } ?? tenantCString?.withUnsafeBufferPointer { tenantBuffer in
                file_defender_client_defend_default(
                    inputPtr,
                    inputLen,
                    nil,
                    tenantBuffer.baseAddress
                )
            } ?? file_defender_client_defend_default(
                inputPtr,
                inputLen,
                nil,
                nil
            )

            defer {
                file_defender_free_buffer(result.output_ptr, result.output_len, result.output_cap)
                file_defender_free_buffer(result.metadata_proto_ptr, result.metadata_proto_len, result.metadata_proto_cap)
                file_defender_free_buffer(result.error_proto_ptr, result.error_proto_len, result.error_proto_cap)
            }

            if result.status_code != file_defender_ffi_status_ok() {
                let errorBytes = Data(bytes: result.error_proto_ptr, count: result.error_proto_len)
                let decoded = try? File_Defender_Ffi_Error(serializedBytes: errorBytes)
                let message = decoded?.message ?? "unknown ffi error"
                throw FileDefenderBridgeError.ffiError(message)
            }

            let rebuilt = Data(bytes: result.output_ptr, count: result.output_len)
            let metadataBytes = Data(bytes: result.metadata_proto_ptr, count: result.metadata_proto_len)
            let metadata: File_Defender_Ffi_Metadata
            do {
                metadata = try File_Defender_Ffi_Metadata(serializedBytes: metadataBytes)
            } catch {
                throw FileDefenderBridgeError.decodeError("failed to decode metadata protobuf")
            }

            return FileDefenderOutput(
                verdict: result.verdict,
                rebuiltFile: rebuilt,
                metadata: metadata
            )
        }
    }
}
