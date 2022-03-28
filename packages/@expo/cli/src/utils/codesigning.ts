import {
  convertCertificatePEMToCertificate,
  convertKeyPairToPEM,
  convertCSRToCSRPEM,
  generateKeyPair,
  generateCSR,
  convertPrivateKeyPEMToPrivateKey,
  validateSelfSignedCertificate,
  signStringRSASHA256AndVerify,
} from '@expo/code-signing-certificates';
import { ExpoConfig } from '@expo/config';
import { promises as fs } from 'fs';
import { pki as PKI } from 'node-forge';
import path from 'path';
import { Dictionary, parseDictionary } from 'structured-headers';

import { fetchAsync } from '../api/rest/client';
import { APISettings } from '../api/settings';
import { ensureLoggedInAsync } from '../api/user/actions';
import * as Log from '../log';
import { createTemporaryProjectFile } from '../start/project/dotExpo';

export type CodeSigningInfo = {
  privateKey: string;
  certificateChain: string[];
};

type StoredCodeSigningInfo = {
  easProjectId: string | null;
  scopeKey: string | null;
  privateKey: string | null;
  certificateChain: string[] | null;
};

export async function getCodeSigningInfoAsync(
  projectRoot: string,
  exp: ExpoConfig,
  expectSignatureHeader: string | null,
  privateKeyPath: string | undefined
): Promise<CodeSigningInfo | null> {
  if (!expectSignatureHeader) {
    return null;
  }

  let parsedExpectSignature: Dictionary;
  try {
    parsedExpectSignature = parseDictionary(expectSignatureHeader);
  } catch {
    throw new Error('Invalid value for expo-expect-signature header');
  }

  const expectedKeyIdOuter = parsedExpectSignature.get('keyid');
  if (!expectedKeyIdOuter) {
    throw new Error('keyid not present in expo-expect-signature header');
  }

  const expectedKeyId = expectedKeyIdOuter[0];
  if (typeof expectedKeyId !== 'string') {
    throw new Error(`Invalid value for keyid in expo-expect-signature header: ${expectedKeyId}`);
  }

  const expectedAlg: string | null = null;
  const expectedAlgOuter = parsedExpectSignature.get('alg');
  if (expectedAlgOuter) {
    const expectedAlg = expectedAlgOuter[0];
    if (typeof expectedAlg !== 'string') {
      throw new Error('Invalid value for alg in expo-expect-signature header');
    }
  }

  if (expectedKeyId === 'expo-root') {
    return await getExpoRootDevelopmentCertificateAsync(projectRoot, exp);
  } else if (expectedKeyId === 'expo-go') {
    throw new Error('Invalid certificate requested: cannot sign with embedded keyid=expo-go key');
  } else {
    return await getProjectCodeSigningCertificateAsync(
      exp,
      privateKeyPath,
      expectedKeyId,
      expectedAlg
    );
  }
}

async function getExpoRootDevelopmentCertificateAsync(
  projectRoot: string,
  exp: ExpoConfig
): Promise<CodeSigningInfo | null> {
  const easProjectId = exp.extra?.eas?.projectId;
  const scopeKey = exp.extra?.scopeKey;
  if (!easProjectId || !scopeKey) {
    return null;
  }

  // 1. check for cached cert/pk matching projectId and scopeKey of project, if found and valid return PK and cert chain including expo-go cert
  const developmentCodeSigningInfoFromFile = await DevelopmentCodeSigningInfoFile.readAsync(
    projectRoot
  );
  const developmentCodeSigningInfo = validateCodeSigningInfo(
    developmentCodeSigningInfoFromFile,
    easProjectId,
    scopeKey
  );
  if (developmentCodeSigningInfo) {
    return developmentCodeSigningInfo;
  }

  // 2. if offline, return null
  if (APISettings.isOffline) {
    Log.warn('Offline and no cached development certificate found, unable to sign manifest');
    return null;
  }

  // 3. ensure logged in, generate PK, CSR, fetch and cache cert chain for projectId (overwriting existing dev cert in case projectId changed)
  return await getNewDevelopmentCodeSigningCertificateAsync(projectRoot, easProjectId, scopeKey);
}

async function getProjectCodeSigningCertificateAsync(
  exp: ExpoConfig,
  privateKeyPath: string | undefined,
  expectedKeyId: string,
  expectedAlg: string | null
): Promise<CodeSigningInfo | null> {
  // 1. get project code signing info (like eas-cli getCodeSigningInfoAsync)
  // 2. if code signing info present and keyid/alg matches, return certificate/PK
  return await getCodeSigningInfoFromProjectAsync(exp, privateKeyPath, expectedKeyId, expectedAlg);
}

async function getCodeSigningInfoFromProjectAsync(
  exp: ExpoConfig,
  privateKeyPath: string | undefined,
  expectedKeyId: string,
  expectedAlg: string | null
): Promise<CodeSigningInfo | null> {
  const codeSigningCertificatePath = exp.updates?.codeSigningCertificate;
  if (!codeSigningCertificatePath) {
    return null;
  }

  if (!privateKeyPath) {
    privateKeyPath = path.join(path.dirname(codeSigningCertificatePath), 'private-key.pem');
  }

  const codeSigningMetadata = exp.updates?.codeSigningMetadata;
  if (!codeSigningMetadata) {
    throw new Error(
      'Must specify codeSigningMetadata under the "updates" field of your app config file to use EAS code signing'
    );
  }

  const { alg, keyid } = codeSigningMetadata;
  if (!alg || !keyid) {
    throw new Error(
      'Must specify keyid and alg in the codeSigningMetadata field under the "updates" field of your app config file to use EAS code signing'
    );
  }

  if (expectedKeyId !== keyid) {
    throw new Error(`keyid mismatch: client=${expectedKeyId}, project=${keyid}`);
  }

  if (expectedAlg && expectedAlg !== alg) {
    throw new Error(`alg mismatch: client=${expectedAlg}, project=${alg}`);
  }

  return await getKeyAndCertificateFromPathsAsync({
    codeSigningCertificatePath,
    privateKeyPath,
  });
}

async function readFileAsync(path: string, errorMessage: string): Promise<string> {
  try {
    return await fs.readFile(path, 'utf8');
  } catch {
    throw new Error(errorMessage);
  }
}
async function getKeyAndCertificateFromPathsAsync({
  codeSigningCertificatePath,
  privateKeyPath,
}: {
  codeSigningCertificatePath: string;
  privateKeyPath: string;
}): Promise<CodeSigningInfo> {
  const [codeSigningCertificatePEM, privateKeyPEM] = await Promise.all([
    readFileAsync(
      codeSigningCertificatePath,
      `Code signing certificate cannot be read from path: ${codeSigningCertificatePath}`
    ),
    readFileAsync(
      privateKeyPath,
      `Code signing private key cannot be read from path: ${privateKeyPath}`
    ),
  ]);

  const privateKey = convertPrivateKeyPEMToPrivateKey(privateKeyPEM);
  const certificate = convertCertificatePEMToCertificate(codeSigningCertificatePEM);
  validateSelfSignedCertificate(certificate, {
    publicKey: certificate.publicKey as PKI.rsa.PublicKey,
    privateKey,
  });

  return {
    privateKey: privateKeyPEM,
    certificateChain: [codeSigningCertificatePEM],
  };
}

const DEVELOPMENT_CODE_SIGNING_SETTINGS_FILE_NAME = 'development-code-signing-settings.json';

const DevelopmentCodeSigningInfoFile = createTemporaryProjectFile<StoredCodeSigningInfo>(
  DEVELOPMENT_CODE_SIGNING_SETTINGS_FILE_NAME,
  {
    easProjectId: null,
    scopeKey: null,
    privateKey: null,
    certificateChain: null,
  }
);

function validateCodeSigningInfo(
  codeSigningInfo: StoredCodeSigningInfo,
  easProjectId: string,
  scopeKey: string
): CodeSigningInfo | null {
  if (codeSigningInfo.easProjectId !== easProjectId || codeSigningInfo.scopeKey !== scopeKey) {
    return null;
  }

  const { privateKey: privateKeyPEM, certificateChain: certificatePEMs } = codeSigningInfo;
  if (!privateKeyPEM || !certificatePEMs) {
    return null;
  }

  // const privateKey = convertPrivateKeyPEMToPrivateKey(privateKeyPEM);
  const certificateChain = certificatePEMs.map((certificatePEM) =>
    convertCertificatePEMToCertificate(certificatePEM)
  );

  // TODO(wschurman): maybe move to @expo/code-signing-certificates
  const leafCertificate = certificateChain[0];
  const now = new Date();
  if (leafCertificate.validity.notBefore > now || leafCertificate.validity.notAfter < now) {
    return null;
  }

  // TODO(wschurman): maybe do more validation

  return {
    certificateChain: certificatePEMs,
    privateKey: privateKeyPEM,
  };
}

async function getNewDevelopmentCodeSigningCertificateAsync(
  projectRoot: string,
  easProjectId: string,
  scopeKey: string
): Promise<CodeSigningInfo> {
  // generate PK, CSR, fetch and cache cert chain for projectId (overwriting existing dev cert in case projectId changed)
  await ensureLoggedInAsync();
  const keyPair = generateKeyPair();
  const keyPairPEM = convertKeyPairToPEM(keyPair);
  const csr = generateCSR(keyPair, `Development Certificate ${scopeKey}`);
  const csrPEM = convertCSRToCSRPEM(csr);
  const certificate = await getDevelopmentCertificateFromServerAsync(easProjectId, csrPEM);

  await DevelopmentCodeSigningInfoFile.setAsync(projectRoot, {
    easProjectId,
    scopeKey,
    privateKey: keyPairPEM.privateKeyPEM,
    certificateChain: [certificate],
  });

  return {
    certificateChain: [certificate],
    privateKey: keyPairPEM.privateKeyPEM,
  };
}

async function getDevelopmentCertificateFromServerAsync(
  easProjectId: string,
  csrPEM: string
): Promise<string> {
  const response = await fetchAsync(`projects/${easProjectId}/development-certificates`, {
    method: 'POST',
    body: JSON.stringify({
      csrPEM,
    }),
  });
  const buffer = await response.buffer();
  return buffer.toString('utf8');
}

export function signManifestString(
  stringifiedManifest: string,
  codeSigningInfo: CodeSigningInfo
): string {
  const privateKey = convertPrivateKeyPEMToPrivateKey(codeSigningInfo.privateKey);
  const certificate = convertCertificatePEMToCertificate(codeSigningInfo.certificateChain[0]);
  return signStringRSASHA256AndVerify(privateKey, certificate, stringifiedManifest);
}
