// phishing-detection.service.ts
import { Injectable } from '@angular/core';
import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { Observable, throwError } from 'rxjs';
import { catchError } from 'rxjs/operators';
import { environment } from '../../environments/environment';

export interface DetectionRequest {
  domain: string;
  deep_scan?: boolean;
}

export interface DomainVariant {
  domain: string;
  technique: string;
  exists: boolean;
  has_https: boolean;
  risk_score: number;
  risk_level: 'safe' | 'low' | 'medium' | 'high' | 'critical';
  similarity_score: number;
  // Threat intel flags (PhishTank removed, replaced with:)
  virustotal_detected: boolean;
  virustotal_positives: number;
  google_safe_browsing_flagged: boolean;
  urlhaus_flagged: boolean;       // replaces phishtank
  openphish_flagged: boolean;
  urlscan_flagged: boolean;
  abuseipdb_flagged: boolean;
  // Extra info
  whois_creation_date: string | null;
  domain_age_days: number | null;
  page_title: string | null;
  page_keywords: string[];
  ip_address: string | null;
  threat_intel_details: Record<string, any>;
}

export interface DetectionResult {
  id?: string;
  query_domain: string;
  is_legitimate: boolean;
  total_variants_generated: number;
  total_variants_existing: number;
  high_risk_count: number;
  overall_risk_score: number;
  overall_risk_level: string;
  variants: DomainVariant[];
  scan_duration_seconds: number;
  scanned_at: string;
  summary: string;
}

export interface DetectionResponse {
  success: boolean;
  data?: DetectionResult;
  error?: string;
}

export interface StatsData {
  total_scans: number;
  total_domains_detected: number;
  high_risk_domains: number;
  risk_distribution: Record<string, number>;
  top_targeted_domains: Array<{ domain: string; scans: number }>;
  scans_over_time: Array<{ date: string; count: number }>;
}

@Injectable({ providedIn: 'root' })
export class PhishingDetectionService {
  private apiBase = environment.apiUrl + '/api/v1';

  constructor(private http: HttpClient) {}

  detect(domain: string, deepScan = false): Observable<DetectionResponse> {
    return this.http
      .post<DetectionResponse>(`${this.apiBase}/detect`, {
        domain,
        deep_scan: deepScan
      })
      .pipe(catchError(this.handleError));
  }

  getHistory(limit = 20) {
    return this.http
      .get<any>(`${this.apiBase}/history?limit=${limit}`)
      .pipe(catchError(this.handleError));
  }

  getStats() {
    return this.http
      .get<{ success: boolean; data: StatsData }>(`${this.apiBase}/stats`)
      .pipe(catchError(this.handleError));
  }

  private handleError(error: HttpErrorResponse): Observable<never> {
    const msg = error.error?.detail || error.message || 'Unknown error';
    return throwError(() => new Error(msg));
  }
}
