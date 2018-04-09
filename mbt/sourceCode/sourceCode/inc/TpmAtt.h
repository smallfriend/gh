/*++

THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
PARTICULAR PURPOSE.

Copyright (c) Microsoft Corporation.  All rights reserved.

Module Name:

    TpmAtt.h

Author:

    Stefan Thom, stefanth@Microsoft.com, 2011/06/09

Abstract:

    Definitions, types and prototypes for TpmAtt.dll.

--*/

#ifdef _MSC_VER
#pragma once
#endif

#ifndef TPMATT_H
#define TPMATT_H

#define DllExport __declspec(dllexport)

// Platform attestation properties
#define PCP_ATTESTATION_PROPERTIES_CONTAINS_BOOT_COUNT (0x00000001)
#define PCP_ATTESTATION_PROPERTIES_CONTAINS_EVENT_COUNT (0x00000002)
#define PCP_ATTESTATION_PROPERTIES_EVENT_COUNT_NON_CONTIGUOUS (0x00000004)
#define PCP_ATTESTATION_PROPERTIES_INTEGRITY_SERVICES_DISABLED (0x00000008)
#define PCP_ATTESTATION_PROPERTIES_TRANSITION_TO_WINLOAD (0x00000010)
#define PCP_ATTESTATION_PROPERTIES_TRANSITION_TO_WINRESUME (0x00000020)
#define PCP_ATTESTATION_PROPERTIES_TRANSITION_TO_OTHER (0x00000040)
#define PCP_ATTESTATION_PROPERTIES_BOOT_DEBUG_ON (0x00000100)
#define PCP_ATTESTATION_PROPERTIES_OS_DEBUG_ON (0x00000200)
#define PCP_ATTESTATION_PROPERTIES_CODEINTEGRITY_OFF (0x00000400)
#define PCP_ATTESTATION_PROPERTIES_TESTSIGNING_ON (0x00000800)
#define PCP_ATTESTATION_PROPERTIES_BITLOCKER_UNLOCK (0x00001000)
#define PCP_ATTESTATION_PROPERTIES_OS_SAFEMODE (0x00002000)
#define PCP_ATTESTATION_PROPERTIES_OS_WINPE (0x00004000)
#define PCP_ATTESTATION_PROPERTIES_OS_HV (0x00008000)

// Key attestation properties
#define PCP_KEY_PROPERTIES_NON_MIGRATABLE (0x80000000)
#define PCP_KEY_PROPERTIES_PIN_PROTECTED (0x40000000)
#define PCP_KEY_PROPERTIES_PCR_PROTECTED (0x20000000)
#define PCP_KEY_PROPERTIES_SIGNATURE_KEY (0x00000001)
#define PCP_KEY_PROPERTIES_ENCRYPTION_KEY (0x00000002)
#define PCP_KEY_PROPERTIES_GENERIC_KEY (0x00000003)
#define PCP_KEY_PROPERTIES_STORAGE_KEY (0x00000004)
#define PCP_KEY_PROPERTIES_IDENTITY_KEY (0x00000005)

#define BCRYPT_PCP_KEY_MAGIC 'MPCP' // Platform Crypto Provider Magic

typedef enum PCP_KEY_FLAGS_WIN8 {
    PCP_KEY_FLAGS_WIN8_authRequired=0x00000001
} PCP_KEY_FLAGS_WIN8;

typedef enum PCP_KEY_FLAGS {
    PCP_KEY_FLAGS_authRequired = 0x00000001
} PCP_KEY_FLAGS;

#define PCPTYPE_TPM12 (0x00000001)
#define PCPTYPE_TPM20 (0x00000002)

typedef struct PCP_KEY_BLOB_WIN8 // Storage structure for 2.0 keys
{
    DWORD   magic;
    DWORD   cbHeader;
    DWORD   pcpType;
    DWORD   flags;
    ULONG   cbPublic;
    ULONG   cbPrivate; 
    ULONG   cbMigrationPublic;
    ULONG   cbMigrationPrivate;
    ULONG   cbPolicyDigestList;
    ULONG   cbPCRBinding;
    ULONG   cbPCRDigest;
    ULONG   cbEncryptedSecret;
    ULONG   cbTpm12HostageBlob;
} PCP_KEY_BLOB_WIN8, *PPCP_KEY_BLOB_WIN8;

typedef struct PCP_KEY_BLOB
{
    DWORD   magic;
    DWORD   cbHeader;
    DWORD   pcpType;
    DWORD   flags;
    ULONG   cbTpmKey;
} PCP_KEY_BLOB, *PPCP_KEY_BLOB;

#define PCP_PLATFORM_ATTESTATION_MAGIC 'SDAP' // Platform Attestation Data Structure
typedef struct _PCP_PLATFORM_ATTESTATION_BLOB {
  ULONG Magic;
  ULONG Platform;
  ULONG HeaderSize;
  ULONG cbPcrValues;
  ULONG cbQuote;
  ULONG cbSignature;
  ULONG cbLog;
} PCP_PLATFORM_ATTESTATION_BLOB, *PPCP_PLATFORM_ATTESTATION_BLOB;

#define PCP_KEY_ATTESTATION_MAGIC 'SDAK' // Key Attestation Data Structure
typedef struct _PCP_KEY_ATTESTATION_BLOB {
  ULONG Magic;
  ULONG Platform;
  ULONG HeaderSize;
  ULONG cbKeyAttest;
  ULONG cbSignature;
  ULONG cbKeyBlob;
} PCP_KEY_ATTESTATION_BLOB, *PPCP_KEY_ATTESTATION_BLOB;

// TPM info location
#define TPM_STATIC_CONFIG_DATA L"System\\CurrentControlSet\\services\\TPM"
#define TPM_STATIC_CONFIG_QUOTE_KEYS L"SYSTEM\\CurrentControlSet\\Services\\Tpm\\PlatformQuoteKeys"
#define TPM_STATIC_CONFIG_KEYATTEST_KEYS L"SYSTEM\\CurrentControlSet\\Services\\Tpm\\KeyAttestationKeys"
#define TPM_VOLATILE_CONFIG_DATA L"System\\CurrentControlSet\\Control\\IntegrityServices"

#if defined(__cplusplus)
extern "C" {
#endif

// Internal helper functions

DllExport HRESULT
TpmAttiShaHash(
    LPCWSTR pszAlgId,
    _In_reads_opt_(cbKey) PBYTE pbKey,
    UINT32 cbKey,
    _In_reads_(cbData) PBYTE pbData,
    UINT32 cbData,
    _Out_writes_to_opt_(cbResult, *pcbResult) PBYTE pbResult,
    UINT32 cbResult,
    _Out_ PUINT32 pcbResult);

DllExport void
TpmAttiReleaseHashProviders(
    );

DllExport HRESULT
TpmAttiGetTpmVersion(
    _Out_ PUINT32 pTpmVersion
    );

HRESULT
TpmAttiComputeSoftPCRs(
    _In_reads_(cbEventLog) PBYTE pbEventLog,
    UINT32 cbEventLog,
    _Out_writes_(AVAILABLE_PLATFORM_PCRS * SHA1_DIGEST_SIZE) PBYTE pbSwPcr,
    _Out_opt_ PUINT32 pPcrMask);

HRESULT
TpmAttiFilterLog(
    _In_reads_(cbEventLog) PBYTE pbEventLog,
    UINT32 cbEventLog,
    UINT32 pcrMask,
    _Out_writes_to_opt_(cbOutput, *pcbResult) PBYTE pbOutput,
    UINT32 cbOutput,
    _Out_ PUINT32 pcbResult
    );

// API functions

DllExport HRESULT
TpmAttPubKeyFromIdBinding(
    _In_reads_(cbIdBinding) PBYTE pbIdBinding,
    UINT32 cbIdBinding,
    BCRYPT_ALG_HANDLE hRsaAlg,
    _Out_ BCRYPT_KEY_HANDLE* phAikPub
    );

DllExport HRESULT
TpmAttGenerateActivation(
    BCRYPT_KEY_HANDLE hEkPub,
    _In_reads_(cbIdBinding) PBYTE pbIdBinding,
    UINT32 cbIdBinding,
    _In_reads_opt_(cbNonce) PBYTE pbNonce,
    UINT32 cbNonce,
    _In_reads_(cbSecret) PBYTE pbSecret,
    UINT16 cbSecret,
    _Out_writes_to_opt_(cbOutput, *pcbResult) PBYTE pbOutput,
    UINT32 cbOutput,
    _Out_ PUINT32 pcbResult
    );

DllExport HRESULT
TpmAttGeneratePlatformAttestation(
    NCRYPT_KEY_HANDLE hAik,
    UINT32 pcrMask,
    _In_reads_opt_ (cbNonce) PBYTE pbNonce,
    UINT32 cbNonce,
    _Out_writes_to_opt_(cbOutput, *pcbResult) PBYTE pbOutput,
    UINT32 cbOutput,
    _Out_ PUINT32 pcbResult
    );

DllExport HRESULT
TpmAttValidatePlatformAttestation(
    BCRYPT_KEY_HANDLE hAik,
    _In_reads_opt_ (cbNonce) PBYTE pbNonce,
    UINT32 cbNonce,
    _In_reads_ (cbAttestation) PBYTE pbAttestation,
    UINT32 cbAttestation
    );

DllExport HRESULT
TpmAttGetPlatformCounters(
    _Out_opt_ PUINT32 pOsBootCount,
    _Out_opt_ PUINT32 pOsResumeCount,
    _Out_opt_ PUINT64 pCurrentTpmBootCount,
    _Out_opt_ PUINT64 pCurrentTpmEventCount,
    _Out_opt_ PUINT64 pCurrentTpmCounterId,
    _Out_opt_ PUINT64 pInitialTpmBootCount,
    _Out_opt_ PUINT64 pInitialTpmEventCount,
    _Out_opt_ PUINT64 pInitialTpmCounterId
    );

DllExport HRESULT
TpmAttGetPlatformLogFromArchive(
    UINT32 OsBootCount,
    UINT32 OsResumeCount,
    _Out_writes_to_opt_(cbOutput, *pcbResult) PBYTE pbOutput,
    UINT32 cbOutput,
    _Out_ PUINT32 pcbResult
    );

DllExport HRESULT
TpmAttCreateAttestationfromLog(
    _In_reads_(cbLog) PBYTE pbLog,
    UINT32 cbLog,
    _In_reads_z_(MAX_PATH) PWSTR szAikNameRequested,
    _Outptr_result_z_ PWSTR* pszAikName,
    _Out_writes_all_opt_(20) PBYTE pbAikPubDigest,
    _Out_writes_to_opt_(cbOutput, *pcbResult) PBYTE pbOutput,
    UINT32 cbOutput,
    _Out_ PUINT32 pcbResult
    );

DllExport HRESULT
TpmAttGetPlatformAttestationProperties(
    _In_reads_(cbAttestation) PBYTE pbAttestation,
    UINT32 cbAttestation,
    _Out_opt_ PUINT64 pEventCount,
    _Out_opt_ PUINT64 pEventIncrements,
    _Out_opt_ PUINT64 pEventCounterId,
    _Out_opt_ PUINT64 pBootCount,
    _Out_opt_ PUINT32 pdwPropertyFlags
    );

DllExport HRESULT
TpmAttGenerateKeyAttestation(
    NCRYPT_KEY_HANDLE hAik,
    NCRYPT_KEY_HANDLE hKey,
    _In_reads_opt_(cbNonce) PBYTE pbNonce,
    UINT32 cbNonce,
    _Out_writes_to_opt_(cbOutput, *pcbResult) PBYTE pbOutput,
    UINT32 cbOutput,
    _Out_ PUINT32 pcbResult
    );

DllExport HRESULT
TpmAttCreateAttestationfromKey(
    NCRYPT_KEY_HANDLE hKey,
    _In_reads_z_(MAX_PATH) PWSTR szAikNameRequested,
    _Out_writes_z_(MAX_PATH) PWSTR szAikName,
    _Out_writes_all_opt_(20) PBYTE pbAikPubDigest,
    _Out_writes_to_opt_(cbOutput, *pcbResult) PBYTE pbOutput,
    UINT32 cbOutput,
    _Out_ PUINT32 pcbResult
    );

DllExport HRESULT
TpmAttValidateKeyAttestation(
    BCRYPT_KEY_HANDLE hAik,
    _In_reads_opt_(cbNonce) PBYTE pbNonce,
    UINT32 cbNonce,
    _In_reads_(cbAttestation) PBYTE pbAttestation,
    UINT32 cbAttestation,
    UINT32 pcrMask,
    _In_reads_opt_(cbPcrTable) PBYTE pcrTable,
    UINT32 cbPcrTable
    );

DllExport HRESULT
TpmAttGetKeyAttestationProperties(
    _In_reads_(cbAttestation) PBYTE pbAttestation,
    UINT32 cbAttestation,
    _Out_opt_ PUINT32 pPropertyFlags,
    BCRYPT_ALG_HANDLE hAlg,
    _Out_opt_ BCRYPT_KEY_HANDLE* phKey
    );

DllExport HRESULT
TpmAttWrapPlatformKey(
    NCRYPT_KEY_HANDLE hInKey,
    BCRYPT_KEY_HANDLE hStorageKey,
    UINT32 tpmVersion,
    UINT32 keyUsage,
    _In_reads_opt_(cbPIN) PBYTE pbPIN,
    UINT32 cbPIN,
    UINT32 pcrMask,
    _In_reads_opt_(cbPcrTable) PBYTE pcrTable,
    UINT32 cbPcrTable,
    _Out_writes_to_opt_(cbOutput, *pcbResult) PBYTE pbOutput,
    UINT32 cbOutput,
    _Out_ PUINT32 pcbResult
    );

#if defined(__cplusplus)
}
#endif

#endif //TPMATT_H
