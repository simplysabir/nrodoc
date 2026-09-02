//! Scan results as a table.

use std::collections::BTreeMap;
use std::path::Path;

use tabled::settings::Style;
use tabled::{Table, Tabled};

use nrodoc::core::verdict::{Report, Verdict};

#[derive(Tabled)]
struct Row {
    #[tabled(rename = "NAME")]
    name: String,
    #[tabled(rename = "FILE")]
    file: String,
    #[tabled(rename = "VERSION")]
    version: String,
    #[tabled(rename = "VERDICT")]
    verdict: &'static str,
    #[tabled(rename = "NOTE")]
    note: String,
}

/// Renders the scan table, with paths relative to the directory that was scanned.
pub fn render(reports: &[Report], root: &Path) -> String {
    let rows: Vec<Row> = reports
        .iter()
        .map(|report| Row {
            name: report.display_name(),
            file: super::relative(&report.path, root),
            version: report.version.clone().unwrap_or_default(),
            verdict: report.verdict.label(),
            note: report.headline().to_string(),
        })
        .collect();

    Table::new(rows).with(Style::psql()).to_string()
}

/// One line of counts per verdict, in a fixed order so it reads the same every run.
pub fn summary(reports: &[Report]) -> String {
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for report in reports {
        *counts.entry(report.verdict.label()).or_default() += 1;
    }

    let ordered = [
        Verdict::Ok,
        Verdict::Patched,
        Verdict::NeedsPatch,
        Verdict::PatchInsufficient,
        Verdict::Unknown,
    ];
    let parts: Vec<String> = ordered
        .iter()
        .filter_map(|verdict| {
            let count = counts.get(verdict.label())?;
            Some(format!("{count} {}", verdict.label()))
        })
        .collect();

    format!(
        "{} file(s): {}",
        reports.len(),
        if parts.is_empty() {
            "nothing to report".to_string()
        } else {
            parts.join(", ")
        }
    )
}
