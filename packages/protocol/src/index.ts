export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type FindingStatus = 'OPEN' | 'VERIFIED' | 'RETESTING' | 'RESOLVED' | 'REVIEW_REQUESTED';

export interface EndpointRoute {
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH' | 'OPTIONS' | 'HEAD';
  path: string;
  filePath: string;
  lineNumber: number;
  handler?: string;
  authRequired: boolean;
  middleware?: string[];
  framework: string;
}

export interface VulnerabilityFinding {
  id: string;
  title: string;
  severity: Severity;
  status: FindingStatus;
  cwe: string;
  cvss: number;
  description: string;
  route: string;
  method: string;
  sourceFile: string;
  sourceLine: number;
  pocPayload: string;
  pocCommand: string;
  pocResponse?: string;
  remediation: string;
  verifiedAt: string;
  complianceTags: string[];
}

export interface AuthCredentials {
  accessToken: string;
  refreshToken?: string;
  userEmail: string;
  orgName: string;
  orgID: string;
  authMethod: 'sso' | 'api_key';
  expiresAt: string;
}

export interface RetestResult {
  findingId: string;
  originalStatus: FindingStatus;
  newStatus: FindingStatus;
  resolved: boolean;
  durationMs: number;
  executedPoC: string;
  observation: string;
  talonSynced: boolean;
}
