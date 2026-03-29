#![cfg_attr(not(feature = "std"), no_std, no_main)]
#![allow(clippy::arithmetic_side_effects)]

use ink::prelude::string::String;
use ink::prelude::vec::Vec;
use ink::storage::Mapping;

/// Regulatory Reporting Module
///
/// Generates standardised regulatory reports (quarterly, annual) for
/// insurance regulators. Supports digital signatures, audit trails, and
/// scheduled report generation by authorised reporters.
#[ink::contract]
mod regulatory_reporting {
    use super::*;

    // ── Data types ────────────────────────────────────────────────────────────

    /// Reporting period classification required by regulators.
    #[derive(
        Debug, Clone, PartialEq, scale::Encode, scale::Decode,
        ink::storage::traits::StorageLayout,
    )]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum ReportType {
        Quarterly,
        Annual,
    }

    /// Lifecycle state of a regulatory report.
    #[derive(
        Debug, Clone, PartialEq, scale::Encode, scale::Decode,
        ink::storage::traits::StorageLayout,
    )]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum ReportStatus {
        /// Report data collected; awaiting signature
        Draft,
        /// Digitally signed by an authorised reporter
        Signed,
        /// Submitted to the regulator
        Submitted,
    }

    /// A regulatory report conforming to required data fields.
    #[derive(
        Debug, Clone, PartialEq, scale::Encode, scale::Decode,
        ink::storage::traits::StorageLayout,
    )]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct RegulatoryReport {
        /// Unique report identifier
        pub id: u64,
        /// Type of report (quarterly / annual)
        pub report_type: ReportType,
        /// Period start timestamp (Unix seconds)
        pub period_start: u64,
        /// Period end timestamp (Unix seconds)
        pub period_end: u64,
        /// Timestamp when this report was generated
        pub generated_at: u64,
        /// Total premiums collected during the period
        pub total_premiums: u128,
        /// Total claims paid during the period
        pub total_claims_paid: u128,
        /// Number of active policies at period end
        pub active_policies: u64,
        /// Number of claims filed during the period
        pub claims_filed: u64,
        /// Number of claims approved during the period
        pub claims_approved: u64,
        /// Solvency ratio × 100 (e.g. 150 = 1.5×)
        pub solvency_ratio: u32,
        /// Reporter who generated the report
        pub reporter: AccountId,
        /// Current lifecycle status
        pub status: ReportStatus,
        /// Digital signature hash (set when signed)
        pub signature: Option<[u8; 32]>,
    }

    /// An immutable audit trail entry.
    #[derive(
        Debug, Clone, PartialEq, scale::Encode, scale::Decode,
        ink::storage::traits::StorageLayout,
    )]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct AuditEntry {
        /// Human-readable description of the action performed
        pub action: String,
        /// Account that performed the action
        pub performed_by: AccountId,
        /// Block timestamp when the action occurred
        pub timestamp: u64,
        /// Optional reference to a report
        pub report_id: Option<u64>,
    }

    // ── Input ─────────────────────────────────────────────────────────────────

    /// Data supplied by the reporter when generating a new report.
    #[derive(Debug, Clone, scale::Encode, scale::Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct ReportData {
        pub report_type: ReportType,
        pub period_start: u64,
        pub period_end: u64,
        pub total_premiums: u128,
        pub total_claims_paid: u128,
        pub active_policies: u64,
        pub claims_filed: u64,
        pub claims_approved: u64,
        pub solvency_ratio: u32,
    }

    // ── Storage ───────────────────────────────────────────────────────────────

    #[ink(storage)]
    pub struct RegulatoryReporting {
        /// Contract administrator
        admin: AccountId,
        /// Accounts permitted to generate and sign reports
        reporters: Vec<AccountId>,
        /// Reports by id
        reports: Mapping<u64, RegulatoryReport>,
        /// Audit trail entries indexed sequentially
        audit_trail: Mapping<u64, AuditEntry>,
        /// Next report id
        next_report_id: u64,
        /// Next audit entry id
        next_audit_id: u64,
    }

    // ── Events ────────────────────────────────────────────────────────────────

    #[ink(event)]
    pub struct ReportGenerated {
        #[ink(topic)]
        pub report_id: u64,
        pub report_type: ReportType,
        pub period_start: u64,
        pub period_end: u64,
        pub reporter: AccountId,
    }

    #[ink(event)]
    pub struct ReportSigned {
        #[ink(topic)]
        pub report_id: u64,
        pub signed_by: AccountId,
    }

    #[ink(event)]
    pub struct ReportSubmitted {
        #[ink(topic)]
        pub report_id: u64,
        pub submitted_by: AccountId,
    }

    #[ink(event)]
    pub struct AuditEntryAdded {
        pub audit_id: u64,
        pub report_id: Option<u64>,
        pub performed_by: AccountId,
    }

    // ── Errors ────────────────────────────────────────────────────────────────

    #[derive(Debug, PartialEq, scale::Encode, scale::Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum Error {
        Unauthorised,
        ReporterNotFound,
        ReportNotFound,
        InvalidPeriod,
        AlreadySigned,
        NotSigned,
        ReporterAlreadyExists,
    }

    // ── Implementation ────────────────────────────────────────────────────────

    impl RegulatoryReporting {
        /// Deploy the module with the deployer as admin.
        #[ink(constructor)]
        pub fn new() -> Self {
            let caller = Self::env().caller();
            let mut reporters = Vec::new();
            reporters.push(caller); // admin is a reporter by default
            Self {
                admin: caller,
                reporters,
                reports: Mapping::default(),
                audit_trail: Mapping::default(),
                next_report_id: 1,
                next_audit_id: 1,
            }
        }

        /// Add an authorised reporter. Admin only.
        #[ink(message)]
        pub fn add_reporter(&mut self, reporter: AccountId) -> Result<(), Error> {
            self.require_admin()?;
            if self.reporters.contains(&reporter) {
                return Err(Error::ReporterAlreadyExists);
            }
            self.reporters.push(reporter);
            self.record_audit(
                String::from("reporter_added"),
                self.env().caller(),
                None,
            );
            Ok(())
        }

        /// Remove an authorised reporter. Admin only.
        #[ink(message)]
        pub fn remove_reporter(&mut self, reporter: AccountId) -> Result<(), Error> {
            self.require_admin()?;
            self.reporters.retain(|r| *r != reporter);
            self.record_audit(
                String::from("reporter_removed"),
                self.env().caller(),
                None,
            );
            Ok(())
        }

        /// Generate a new regulatory report. Authorised reporters only.
        #[ink(message)]
        pub fn generate_report(&mut self, data: ReportData) -> Result<u64, Error> {
            self.require_reporter()?;

            if data.period_end <= data.period_start {
                return Err(Error::InvalidPeriod);
            }

            let caller = self.env().caller();
            let now = self.env().block_timestamp();
            let id = self.next_report_id;
            self.next_report_id += 1;

            let report = RegulatoryReport {
                id,
                report_type: data.report_type.clone(),
                period_start: data.period_start,
                period_end: data.period_end,
                generated_at: now,
                total_premiums: data.total_premiums,
                total_claims_paid: data.total_claims_paid,
                active_policies: data.active_policies,
                claims_filed: data.claims_filed,
                claims_approved: data.claims_approved,
                solvency_ratio: data.solvency_ratio,
                reporter: caller,
                status: ReportStatus::Draft,
                signature: None,
            };

            self.reports.insert(id, &report);

            self.env().emit_event(ReportGenerated {
                report_id: id,
                report_type: data.report_type,
                period_start: data.period_start,
                period_end: data.period_end,
                reporter: caller,
            });

            self.record_audit(String::from("report_generated"), caller, Some(id));

            Ok(id)
        }

        /// Digitally sign a draft report. Authorised reporters only.
        ///
        /// `signature` is a 32-byte hash (e.g. SHA-256 of the serialised report
        /// produced off-chain) that serves as the digital signature.
        #[ink(message)]
        pub fn sign_report(
            &mut self,
            report_id: u64,
            signature: [u8; 32],
        ) -> Result<(), Error> {
            self.require_reporter()?;

            let mut report = self.reports.get(report_id).ok_or(Error::ReportNotFound)?;

            if report.status != ReportStatus::Draft {
                return Err(Error::AlreadySigned);
            }

            report.signature = Some(signature);
            report.status = ReportStatus::Signed;
            self.reports.insert(report_id, &report);

            let caller = self.env().caller();

            self.env().emit_event(ReportSigned {
                report_id,
                signed_by: caller,
            });

            self.record_audit(String::from("report_signed"), caller, Some(report_id));

            Ok(())
        }

        /// Submit a signed report to the regulator. Authorised reporters only.
        #[ink(message)]
        pub fn submit_report(&mut self, report_id: u64) -> Result<(), Error> {
            self.require_reporter()?;

            let mut report = self.reports.get(report_id).ok_or(Error::ReportNotFound)?;

            if report.status != ReportStatus::Signed {
                return Err(Error::NotSigned);
            }

            report.status = ReportStatus::Submitted;
            self.reports.insert(report_id, &report);

            let caller = self.env().caller();

            self.env().emit_event(ReportSubmitted {
                report_id,
                submitted_by: caller,
            });

            self.record_audit(String::from("report_submitted"), caller, Some(report_id));

            Ok(())
        }

        /// Read a report by id.
        #[ink(message)]
        pub fn get_report(&self, report_id: u64) -> Option<RegulatoryReport> {
            self.reports.get(report_id)
        }

        /// Read an audit trail entry by sequential id.
        #[ink(message)]
        pub fn get_audit_entry(&self, audit_id: u64) -> Option<AuditEntry> {
            self.audit_trail.get(audit_id)
        }

        /// Return the number of audit entries recorded so far.
        #[ink(message)]
        pub fn audit_count(&self) -> u64 {
            self.next_audit_id - 1
        }

        /// Return the total number of reports generated.
        #[ink(message)]
        pub fn report_count(&self) -> u64 {
            self.next_report_id - 1
        }

        /// Check whether an account is an authorised reporter.
        #[ink(message)]
        pub fn is_reporter(&self, account: AccountId) -> bool {
            self.reporters.contains(&account)
        }

        // ── Private helpers ───────────────────────────────────────────────────

        fn require_admin(&self) -> Result<(), Error> {
            if self.env().caller() != self.admin {
                return Err(Error::Unauthorised);
            }
            Ok(())
        }

        fn require_reporter(&self) -> Result<(), Error> {
            if !self.reporters.contains(&self.env().caller()) {
                return Err(Error::Unauthorised);
            }
            Ok(())
        }

        fn record_audit(
            &mut self,
            action: String,
            performed_by: AccountId,
            report_id: Option<u64>,
        ) {
            let id = self.next_audit_id;
            self.next_audit_id += 1;

            let entry = AuditEntry {
                action,
                performed_by,
                timestamp: self.env().block_timestamp(),
                report_id,
            };

            self.audit_trail.insert(id, &entry);

            self.env().emit_event(AuditEntryAdded {
                audit_id: id,
                report_id,
                performed_by,
            });
        }
    }
}
