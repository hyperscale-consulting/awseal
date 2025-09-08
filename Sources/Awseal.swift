import ArgumentParser
import AWSSSO
import AWSSSOOIDC
import Foundation
import CryptoKit
import LocalAuthentication
import Security

enum AwsealError: Error, LocalizedError {
    case generic(String)
    case keyAlreadyExists
    case clientRegistration(String)
    case notLoggedIn

    var errorDescription: String? {
        switch self {
            case .generic(let s): return s
            case .keyAlreadyExists: return "Attempt to generate key that already exists"
            case .clientRegistration(let s): return "Unable to register client \(s)"
            case .notLoggedIn: return "No active SSO credentials found, please run `awseal login` to login."
        }
    }
}

struct EnclaveKeyManager {

    static func generateKey(label: String) throws -> KeyMetadata {
        let la = LAContext()
        la.localizedReason = "Create a Secure Enclave key for awseal (label: \(label))"

        var error: Unmanaged<CFError>?
        let flags: SecAccessControlCreateFlags = [.privateKeyUsage, .userPresence]

        guard let ac = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            flags,
            &error
        ) else {
            let msg = (error?.takeRetainedValue() as Error?)?.localizedDescription ?? "unknown"
            throw AwsealError.generic("Failed to create SecAccessControl: \(msg)")
        }
        let priv = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            accessControl: ac,
            authenticationContext: la
        )

        let persistentRef = priv.dataRepresentation
        let pubX963 = priv.publicKey.x963Representation

        return KeyMetadata(
            id: UUID(),
            label: label,
            createdAt: Date(),
            keyPersistentRef: persistentRef,
            publicKeyX963: pubX963
        )
    }

    static func openPrivateKey(_ md: KeyMetadata, reason: String) throws -> SecureEnclave.P256.KeyAgreement.PrivateKey {
        let la = LAContext()
        la.localizedReason = reason
        return try SecureEnclave.P256.KeyAgreement.PrivateKey(
            dataRepresentation: md.keyPersistentRef,
            authenticationContext: la
        )
    }
}

struct KeyMetadata: Codable {
    let id: UUID
    var label: String
    let createdAt: Date
    let keyPersistentRef: Data
    let publicKeyX963: Data
}

final class KeyDB {
    private let fileURL: URL
    private var items: [KeyMetadata] = []

    init() throws {
        let home = FileManager.default.homeDirectoryForCurrentUser
        let dir = home.appendingPathComponent(".awseal", isDirectory: true)
        self.fileURL = dir.appendingPathComponent("keys.json", isDirectory: false)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        try load()
    }

    private func load() throws {
        guard FileManager.default.fileExists(atPath: fileURL.path) else {
            self.items = []
            return
        }
        let data = try Data(contentsOf: fileURL)
        let dec = JSONDecoder()
        dec.dateDecodingStrategy = .iso8601
        dec.dataDecodingStrategy = .base64
        self.items = try dec.decode([KeyMetadata].self, from: data)
    }

    private func save() throws {
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        enc.dateEncodingStrategy = .iso8601
        enc.dataEncodingStrategy = .base64
        let data = try enc.encode(items)
        try data.write(to: fileURL, options: [.atomic])
    }

    func list() -> [KeyMetadata] { items }

    func add(_ item: KeyMetadata) throws {
        if items.contains(where: { $0.label == item.label }) {
            throw AwsealError.keyAlreadyExists
        }
        items.append(item)
        try save()
    }

    func resolve(_ label: String) -> KeyMetadata? {
        return items.first { $0.label == label }
    }
}

struct Envelope: Codable {
    let version: Int = 1
    let keyId: UUID
    let encapsulatedKey: Data
    let ciphertext: Data

    private enum CodingKeys: String, CodingKey {
        case keyId, encapsulatedKey, ciphertext
    }
}

let keyLabel = "consulting.hyperscale.awseal.key"
let protocolInfo = "awseal key agreement".data(using: .utf8)!
let ciphersuite = HPKE.Ciphersuite.P256_SHA256_AES_GCM_256

func genKey() throws -> KeyMetadata {
    let db = try KeyDB()
    if db.resolve(keyLabel) != nil {
        throw AwsealError.keyAlreadyExists
    }
    let md = try EnclaveKeyManager.generateKey(label: keyLabel)
    try db.add(md)
    return md
}

func saveEncrypted(plaintext: Data, to: URL) throws {
    let db = try KeyDB()
    let md: KeyMetadata
    if let existing = db.resolve(keyLabel) {
        md = existing
    } else {
        md = try genKey()
    }

    let enclavePub = try P256.KeyAgreement.PublicKey(x963Representation: md.publicKeyX963)
    var hpke = try HPKE.Sender(recipientKey: enclavePub, ciphersuite: ciphersuite, info: protocolInfo)
    let ciphertext = try hpke.seal(plaintext)
    let encapsulatedKey = hpke.encapsulatedKey

    let env = Envelope(
        keyId: md.id,
        encapsulatedKey: encapsulatedKey,
        ciphertext: ciphertext
    )

    let enc = JSONEncoder()
    enc.outputFormatting = [.prettyPrinted, .sortedKeys]
    enc.dataEncodingStrategy = .base64
    let out = try enc.encode(env)
    try out.write(to: to, options: [.atomic])
}

func loadDecrypted(from: URL) throws -> Data {
    let recoveryInstructions = "Delete ~/.awseal/keys.json if it exsists and run `awseal login` again."
    let db = try KeyDB()
    guard let md = db.resolve(keyLabel) else {
        throw AwsealError.generic("Key not found in database. \(recoveryInstructions)")
    }

    let envelopeData = try Data(contentsOf: from)
    let dec = JSONDecoder()
    dec.dataDecodingStrategy = .base64
    let envelope = try dec.decode(Envelope.self, from: envelopeData)

    guard envelope.keyId == md.id else {
        throw AwsealError.generic("Envelope key ID (\(envelope.keyId)) doesn't match requested key (\(md.id)). \(recoveryInstructions)")
    }

    let priv = try EnclaveKeyManager.openPrivateKey(md, reason: "decrypt AWS credentials")

    var hpke = try HPKE.Recipient(
        privateKey: priv,
        ciphersuite: ciphersuite,
        info: protocolInfo,
        encapsulatedKey: envelope.encapsulatedKey
    )
    let plaintext = try hpke.open(envelope.ciphertext)
    
    return plaintext
}

struct AWSEALProfile: Codable {
    let ssoStartUrl: String
    let roleName: String
    let accountId: String
    let region: String
    let ssoRegion: String
}

struct AWSEALConfig: Codable {
    let profiles: [String: AWSEALProfile]

    static func load(from url: URL) throws -> AWSEALConfig {
        let data = try Data(contentsOf: url)
        let decoder = JSONDecoder()
        let rawProfiles = try decoder.decode([String: AWSEALProfile].self, from: data)
        return AWSEALConfig(profiles: rawProfiles)
    }

    func profile(named name: String) throws -> AWSEALProfile {
        guard let profile = profiles[name] else {
            throw AwsealError.generic("Profile \(name) not found")
        }
        return profile
    }
}

func loadConfig() throws -> AWSEALConfig {
    let home = FileManager.default.homeDirectoryForCurrentUser
    let configURL = home.appendingPathComponent(".awseal/config.json")
    let config = try AWSEALConfig.load(from: configURL)
    return config
}

struct Creds: Codable {
    var ssoCreds: SsoCreds
    var roleCreds: RoleCreds?
}

struct RoleCreds: Codable {
    var accessKeyId: String
    var secretAccessKey: String
    var sessionToken: String
    var expiration: Date

    var hasExpired: Bool {
        let buffer: TimeInterval = 5 // seconds
        return Date() > expiration.addingTimeInterval(-buffer)
    }
}

struct SsoCreds: Codable {
    var clientId: String
    var clientSecret: String
    var accessToken: String?
    var refreshToken: String?
}

func ssoLogin(
    oidc: SSOOIDCClient,
    profile: String,
    ssoCreds: SsoCreds,
    ssoStartUrl: String
) async throws -> SsoCreds {
    let startDeviceAuthorizationInput = StartDeviceAuthorizationInput(
        clientId: ssoCreds.clientId, clientSecret: ssoCreds.clientSecret, startUrl: ssoStartUrl
    )
    let resp = try await oidc.startDeviceAuthorization(input: startDeviceAuthorizationInput)

    guard
        let deviceCode = resp.deviceCode,
        let userCode = resp.userCode
    else {
        throw AwsealError.generic("Missing required fields in device authorization response")
    }

    let expiresIn = resp.expiresIn
    let verificationUri = resp.verificationUri
    let verificationUriComplete = resp.verificationUriComplete
    let interval = resp.interval

    print("""
    To complete SSO login, open the following URL in your browser and confirm / enter the code (\(userCode)) if required:

      \(verificationUriComplete ?? verificationUri ?? "<no verification URL>")
    """)

    if let urlString = verificationUriComplete ?? verificationUri,
       let url = URL(string: urlString) {
        _ = try? Process.run(URL(fileURLWithPath: "/usr/bin/open"), arguments: [url.absoluteString])
    }

    let start = Date()
    while Date().timeIntervalSince(start) < Double(expiresIn) {
        do {
            let createTokenInput = CreateTokenInput(
                clientId: ssoCreds.clientId,
                clientSecret: ssoCreds.clientSecret,
                deviceCode: deviceCode,
                grantType: "urn:ietf:params:oauth:grant-type:device_code"
            )
            let tok = try await oidc.createToken(
                input: createTokenInput
            )

            if let accessToken = tok.accessToken {
                var updatedCreds = ssoCreds
                updatedCreds.accessToken = accessToken
                if let refreshToken = tok.refreshToken {
                    updatedCreds.refreshToken = refreshToken
                }
                return updatedCreds
            }
        } catch is AuthorizationPendingException, is SlowDownException {
            try await Task.sleep(nanoseconds: UInt64(interval) * 1_000_000_000)
            continue
        } catch {
            throw error
        }
    }
    throw AwsealError.generic("Device authorization timed out.")
}

func loadCreds(profile: String) throws -> Creds? {
    let homeDir = FileManager.default.homeDirectoryForCurrentUser
    let fileURL = homeDir.appendingPathComponent(".awseal/\(profile)")

    guard FileManager.default.fileExists(atPath: fileURL.path) else {
        return nil
    }

    let data = try loadDecrypted(from: fileURL)
    return try JSONDecoder().decode(Creds.self, from: data)
}

func saveCreds(profile: String, creds: Creds) throws {
    let homeDir = FileManager.default.homeDirectoryForCurrentUser
    let dirURL = homeDir.appendingPathComponent(".awseal")

    if !FileManager.default.fileExists(atPath: dirURL.path) {
        do {
            try FileManager.default.createDirectory(at: dirURL, withIntermediateDirectories: true)
        } catch {
            throw AwsealError.generic("Unable to create directory ~/.awseal")
        }
    }

    let fileURL = dirURL.appendingPathComponent(profile)

    let data = try JSONEncoder().encode(creds)
    try saveEncrypted(plaintext: data, to: fileURL)
}

func registerClient(oidc: SSOOIDCClient, profile: String) async throws -> SsoCreds {
    let input = RegisterClientInput(
        clientName: "awseal-\(profile)",
        clientType: "public",
        grantTypes: [
            "urn:ietf:params:oauth:grant-type:device_code",
            "refresh_token",
        ],
        scopes: ["sso:account:access"]
    )
    let resp = try await oidc.registerClient(input: input)

    guard let clientId = resp.clientId else {
        throw AwsealError.clientRegistration("no clientId returned")
    }
    guard let clientSecret = resp.clientSecret else {
        throw AwsealError.clientRegistration("no clientSecret returned")
    }
    let ssoCreds = SsoCreds(clientId: clientId, clientSecret: clientSecret)

    return ssoCreds
}

func refreshAccessToken(profile: String, oidc: SSOOIDCClient, ssoCreds: SsoCreds) async throws -> (String, String) {
    guard let refreshToken = ssoCreds.refreshToken else {
        throw AwsealError.notLoggedIn
    }
    let createTokenInput = CreateTokenInput(
        clientId: ssoCreds.clientId,
        clientSecret: ssoCreds.clientSecret,
        grantType: "refresh_token",
        refreshToken: refreshToken
    )
    do {
        let tok = try await oidc.createToken(
            input: createTokenInput
        )

        if let accessToken = tok.accessToken {
            var updatedCreds = ssoCreds
            updatedCreds.accessToken = accessToken
            if let refreshToken = tok.refreshToken {
                updatedCreds.refreshToken = refreshToken
            }
            return (accessToken, refreshToken)
        }
        throw AwsealError.notLoggedIn
    } catch is ExpiredTokenException {
        throw AwsealError.notLoggedIn
    }
}

func getRoleCreds(sso: SSOClient, accessToken: String, accountId: String, roleName: String) async throws -> RoleCreds {
    let input = GetRoleCredentialsInput(accessToken: accessToken, accountId: accountId, roleName: roleName)
    let response = try await sso.getRoleCredentials(input: input)
    guard let roleCreds = response.roleCredentials else {
        throw AwsealError.notLoggedIn
    }

    let expiration = Date(timeIntervalSince1970: TimeInterval(roleCreds.expiration / 1000))
    return RoleCreds(
        accessKeyId: roleCreds.accessKeyId!,
        secretAccessKey: roleCreds.secretAccessKey!,
        sessionToken: roleCreds.sessionToken!,
        expiration: expiration
    )
}

func fetchRoleCreds(
    profile: String, oidc: SSOOIDCClient, sso: SSOClient, region: String, accountId: String, roleName: String
) async throws -> RoleCreds {

    guard var creds = try loadCreds(profile: profile) else {
        throw AwsealError.notLoggedIn
    }
    
    if let roleCreds = creds.roleCreds {
        if !roleCreds.hasExpired {
            return roleCreds
        }
    }
    // role creds not present or expired

    guard let accessToken = creds.ssoCreds.accessToken else {
        throw AwsealError.notLoggedIn
    }

    var roleCreds: RoleCreds
    do {
        roleCreds = try await getRoleCreds(
            sso: sso,
            accessToken: accessToken,
            accountId: accountId,
            roleName: roleName
        )
    } catch is UnauthorizedException {
        let (accessToken, refreshToken) = try await refreshAccessToken(
            profile: profile,
            oidc: oidc,
            ssoCreds: creds.ssoCreds
        )
        creds.ssoCreds.accessToken = accessToken
        creds.ssoCreds.refreshToken = refreshToken
        roleCreds = try await getRoleCreds(
            sso: sso,
            accessToken: accessToken,
            accountId: accountId,
            roleName: roleName
        )
    }
    creds.roleCreds = roleCreds
    try saveCreds(profile: profile, creds: creds)
    return roleCreds
}

func formatExpiration(_ expiration: Int) -> String {
    let date = Date(timeIntervalSince1970: TimeInterval(expiration / 1000))
    let formatter = ISO8601DateFormatter()
    return formatter.string(from: date)
}

func printRoleCredentials(creds: RoleCreds) {
    struct RoleCredsOutput: Codable {
        let version: Int
        let accessKeyId: String
        let secretAccessKey: String
        let sessionToken: String
        let expiration: String

        enum CodingKeys: String, CodingKey {
            case version = "Version"
            case accessKeyId = "AccessKeyId"
            case secretAccessKey = "SecretAccessKey"
            case sessionToken = "SessionToken"
            case expiration = "Expiration"
        }
    }

    let output = RoleCredsOutput(
        version: 1,
        accessKeyId: creds.accessKeyId,
        secretAccessKey: creds.secretAccessKey,
        sessionToken: creds.sessionToken,
        expiration: ISO8601DateFormatter().string(from: creds.expiration)
    )

    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted]

    if let jsonData = try? encoder.encode(output),
       let jsonString = String(data: jsonData, encoding: .utf8) {
        print(jsonString)
    }
}

@main
struct Awseal: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "An AWS CLI credential_process using AWS SSO to mint credentials while storing secrets under a Secure Enclave key.",
        version: "0.3.0",
        subcommands: [Login.self, FetchRoleCreds.self]
    )
}

struct Options: ParsableArguments {
    @Option(name: [.long, .customShort("p")], help: "The profile to use.")
    var profile = "default"
}

extension Awseal {
    struct Login: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Login to AWS SSO."
        )

        @OptionGroup var options: Options

        func run() async throws {
            let config = try loadConfig()
            let profileConfig = try config.profile(named: options.profile)
            let oidc = try SSOOIDCClient(region: profileConfig.ssoRegion)
            var creds: Creds
            if let existing = try loadCreds(profile: options.profile) {
                creds = existing
            } else {
                let ssoCreds = try await registerClient(oidc: oidc, profile: options.profile)
                creds = Creds(ssoCreds: ssoCreds)
            }

            var ssoCreds: SsoCreds
            do {
                ssoCreds = try await ssoLogin(
                    oidc: oidc,
                    profile: options.profile,
                    ssoCreds: creds.ssoCreds,
                    ssoStartUrl: profileConfig.ssoStartUrl
                )
            } catch is InvalidClientException, is UnauthorizedException {
                ssoCreds = try await registerClient(oidc: oidc, profile: options.profile)
                creds = Creds(ssoCreds: ssoCreds)
                ssoCreds = try await ssoLogin(
                    oidc: oidc,
                    profile: options.profile,
                    ssoCreds: creds.ssoCreds,
                    ssoStartUrl: profileConfig.ssoStartUrl
                )
            }
            creds.ssoCreds = ssoCreds
            try saveCreds(profile: options.profile, creds: creds)
        }
    }

    struct FetchRoleCreds: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Fetch and print role credentials for AWS CLI credential_process use."
        )

        @OptionGroup var options: Options

        func run() async throws {
            let config = try loadConfig()
            let profileConfig = try config.profile(named: options.profile)
            let oidc = try SSOOIDCClient(region: profileConfig.ssoRegion)
            let sso = try SSOClient(region: profileConfig.region)
            let creds = try await fetchRoleCreds(
                profile: options.profile,
                oidc: oidc,
                sso: sso,
                region: profileConfig.region,
                accountId: profileConfig.accountId,
                roleName: profileConfig.roleName
            )
            printRoleCredentials(creds: creds)
        }
    }

}
