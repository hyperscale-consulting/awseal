# awseal 🔐

A secure AWS credential manager that protects your AWS credentials using
Apple's Secure Enclave. Inspired by
[Secretive](https://github.com/maxgoedjen/secretive), `awseal` protects you AWS
credentials from malicious code by ensuring they can only be accessed with your
explicit permission.

## 🚨 The Problem

Traditional AWS credential storage methods are vulnerable to credential theft:

- Credentials stored in plain text files can be read by any process
- Environment variables can be accessed by child processes
- Malicious code can easily exfiltrate your AWS access keys or cached AWS SSO credentials

## 🛡️ The Solution

`awseal` leverages Apple's Secure Enclave to provide hardware-backed security
for your AWS credentials:

- **Secure Storage**: AWS credentials are encrypted using keys stored in the
Secure Enclave
- **User Presence Required**: Access to credentials requires biometric
authentication (Touch ID, Face ID) or device passcode
- **Malware Protection**: Even if malicious code runs on your system, it cannot
access your AWS credentials without your physical presence
- **Seamless Integration**: Works transparently with the AWS CLI via `credential_process`

## ✨ Features

- **Secure Authentication**: Login once with `awseal login` and your
credentials are safely stored
- **Automatic Credential Rotation**: Fresh role credentials are minted
on-demand when needed
- **Multiple Profile Support**: Configure different AWS accounts and roles
- **Hardware Security**: Leverages Apple's Secure Enclave for cryptographic operations
- **Touch ID Integration**: Biometric authentication for credential access

## 🚀 Installation

```bash
brew tap hyperscale-consulting/hyperscale
brew install awseal
```

## 📖 Quick Start

### 1. Configure awseal

`awseal` is configured via `~/.awseal/config.json`:

```json
{
  "default": {
    "ssoStartUrl": "https://xxx.awsapps.com/start/#",
    "ssoRegion": "eu-west-2",
    "region": "eu-west-2",
    "accountId": "123456789012",
    "roleName": "MyRole"
  },
  "dev": {
    "ssoStartUrl": "https://xxx.awsapps.com/start/#",
    "ssoRegion": "eu-west-2",
    "region": "eu-west-2",
    "accountId": "123456789012",
    "roleName": "Developer"
  }
}
```

The top level attributes are the profiles you can reference through
`--profile`. The default profile is used if this option is omitted. The
available configuration options for each profile are:

- **ssoStartUrl**: Your organization's AWS SSO start URL
- **ssoRegion**: AWS region where SSO is configured
- **region**: Default AWS region for API calls
- **accountId**: Your AWS account ID
- **roleName**: The role you want to assume

### 2. Login to AWS SSO

```bash
awseal login
```

This will:

- Open your browser for AWS SSO authentication
- Store your SSO credentials encrypted under the Secure Enclave
- Require Touch ID/Face ID to access the stored credentials

### 3. Configure AWS CLI

Configure the AWS CLI to use `awseal` as an external credential provider by
setting `awseal` as the `credential_process` for each profile you want to use
it with in `~/.aws/config`:

```ini
[default]
credential_process = awseal fetch-role-creds

[my-profile]
credential_process = awseal fetch-role-creds --profile my-profile
```

### 4. Use AWS CLI Normally

```bash
# Credentials are automatically fetched and rotated
aws s3 ls
aws ec2 describe-instances
```

## 🔒 Security Architecture

### Secure Enclave Integration

`awseal` uses Apple's Secure Enclave to generate and store cryptographic keys:

1. **Key Generation**: A P-256 key pair is generated in the Secure Enclave
   during first use
2. **Access Control**: Keys are protected with `userPresence` requirement
3. **Credential Encryption**: AWS SSO credentials are encrypted using HPKE
   (Hybrid Public Key Encryption) with the P256-SHA256-AES-GCM-256 ciphersuite,
because the Secure Enclave only supports NIST P-256 elliptic curve keys
4. **Biometric Authentication**: Touch ID/Face ID required to access the
   encryption key

### Threat Model

`awseal` protects against:

- ✅ **Credential Theft**: Malicious code cannot read encrypted credentials
- ✅ **Key Extraction**: Private keys never leave the Secure Enclave
- ✅ **Unauthorized Access**: User presence required to access the Secure
Enclave key

## 🏗️ How It Works

1. **Login Phase** (`awseal login`):
   - Authenticate with AWS SSO via browser
   - Generate Secure Enclave key
   - Encrypt and store SSO credentials

2. **Credential Fetching** (`awseal fetch-role-creds`):
   - AWS CLI calls awseal via `credential_process`
   - awseal decrypts stored credentials (requires Touch ID/Face ID)
   - Role credentials are fetched from AWS SSO OIDC API and returned to AWS CLI
   - Role credentials are stored encrypted until they expire
   - Refresh tokens are used to keep access tokens short-lived for OIDC

3. **Security Guarantees**:
   - Credentials are never stored in plain text
   - Access requires physical user presence
   - Malicious code cannot bypass authentication

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE)
file for details.

## 🙏 Acknowledgments

- Inspired by [Secretive](https://github.com/maxgoedjen/secretive) for SSH key security
- Built on Apple's Secure Enclave and Local Authentication frameworks
- Uses AWS SSO OIDC for secure credential management

## 🔗 Related Projects

- [Secretive](https://github.com/maxgoedjen/secretive) - Secure SSH key
management using Secure Enclave
- [AWS CLI](https://aws.amazon.com/cli/) - Command line interface for AWS
- [AWS SSO](https://aws.amazon.com/single-sign-on/) - AWS Single Sign-On service

---
