//! Scan command and the scan pipeline shared with `run` and `export`:
//! scanning the mailbox (or loading a cached scan) and printing results.

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::io::{IsTerminal, Write};
use std::path::Path;
use unsubscribe_core::{
    decide_scan_action, judge_sender, load_cached_senders, observed_resumptions, scan_senders,
    AccountConfig, CachedScanSummary, Credential, DataStore, Folder, HistoryStore, LatestAttempts,
    ObtainedSenders, Preferences, Resumption, RunObserver, RunPolicy, RunWarning, ScanAction,
    ScanCacheStore, SenderInfo, SenderVerdict, UnsubscribeOutcome,
};

use crate::commands::load_history;
use crate::exit::{Exit, ExitError};
use crate::json as json_out;
use crate::note;
use crate::output;
use crate::progress::CliWarningsOnly;
use crate::terminal::{Ansi, Tty, BLUE, BOLD, CYAN, DIM, GREEN, RED, RESET, YELLOW};
use crate::time::{
    age_secs_since, format_relative_age, is_stale, now_iso8601, now_unix_secs, utc_to_local_date,
    scan_max_age_secs,
};
use crate::{make_provider, progress};

/// Scan the mailbox and return the senders worth showing, with any warnings.
///
/// A thin wrapper over the core pipeline's scan stage: this supplies the
/// provider, the progress bars, and the timestamp, and core does the rest.
pub fn do_scan(
    account: &AccountConfig,
    credential: &Credential,
    store: &dyn DataStore,
    cache_store: &dyn ScanCacheStore,
    preferences: &Preferences,
    tty: Tty,
) -> Result<(Vec<SenderInfo>, Vec<String>)> {
    let obtained = run_scan(account, credential, store, cache_store, preferences, tty)?;
    Ok((obtained.senders, obtained.warnings))
}

/// The scan stage, with the CLI's progress bars and warning wording attached.
fn run_scan(
    account: &AccountConfig,
    credential: &Credential,
    store: &dyn DataStore,
    cache_store: &dyn ScanCacheStore,
    preferences: &Preferences,
    tty: Tty,
) -> Result<ObtainedSenders> {
    note!("{BOLD}Scanning mailbox...{RESET}\n");
    let provider = make_provider(account, credential)?;
    let folders: Vec<Folder> = account.scan_folders.iter().map(|f| Folder::new(f)).collect();
    let scan_progress = progress::CliScanProgress::new(tty.stderr);

    scan_senders(
        &account.account_id,
        &folders,
        provider.as_ref(),
        cache_store,
        store,
        preferences.min_emails,
        &now_iso8601(),
        &scan_progress,
        &CliWarningsOnly,
    )
}

/// Decide between the cached scan and a fresh one, then produce the senders.
///
/// The decision itself is [`decide_scan_action`] in core; this only gathers the
/// inputs, asks the question when core says to, and carries out the answer.
#[allow(clippy::too_many_arguments)]
pub fn resolve_scan(
    account: &AccountConfig,
    credential: &Credential,
    store: &dyn DataStore,
    cache_store: &dyn ScanCacheStore,
    cached: bool,
    rescan: bool,
    preferences: &Preferences,
    prompts_allowed: bool,
    tty: Tty,
) -> Result<ObtainedSenders> {
    let usable = load_cached_senders(
        cache_store,
        &account.account_id,
        preferences.min_emails,
        &CliWarningsOnly,
    );
    let summary = usable.as_ref().map(|cache| CachedScanSummary {
        sender_count: cache.senders.len(),
        age_secs: age_secs_since(&cache.scanned_at),
    });

    let action = decide_scan_action(
        summary,
        cached,
        rescan,
        prompts_allowed,
        scan_max_age_secs(preferences.cache_max_age_days),
    );

    let use_cache = match action {
        ScanAction::UseCache => true,
        ScanAction::Rescan => false,
        ScanAction::CacheUnavailable => {
            return Err(ExitError::usage(
                "No cached scan results found. Run `unsubscribe scan` first.",
            )
            .into())
        }
        ScanAction::Ask { default_cached } => {
            let cache = usable.as_ref().expect("Ask implies a usable cache");
            prompt_use_cached(&cache.scanned_at, cache.senders.len(), default_cached)?
        }
    };

    if use_cache {
        return Ok(usable.expect("cache was checked before use"));
    }

    run_scan(account, credential, store, cache_store, preferences, tty)
}

/// Ask whether to reuse the cached scan. Returns true for "use cached".
///
/// Anything unrecognised -- including a bare Enter or a closed stdin -- takes
/// the default, which is reuse for a fresh scan and a rescan for a stale one.
fn prompt_use_cached(scanned_at: &str, sender_count: usize, default_cached: bool) -> Result<bool> {
    // Belt and braces: `decide_scan_action` only asks when prompting is
    // allowed, but nothing in this file may ever block on an unattended stdin.
    if !std::io::stdin().is_terminal() {
        return Ok(default_cached);
    }
    let when = utc_to_local_date(scanned_at).unwrap_or_else(|| scanned_at.to_string());
    let age = age_secs_since(scanned_at)
        .map(format_relative_age)
        .map(|age| {
            // A stale cache says so in red: it is the reason the default flipped.
            if default_cached {
                format!(" ({DIM}{age}{RESET})")
            } else {
                format!(" ({RED}{age}{RESET})")
            }
        })
        .unwrap_or_default();
    let choices = if default_cached {
        "[U]se cached / [r]escan"
    } else {
        "[u]se cached / [R]escan"
    };

    eprint!(
        "{BOLD}Last scan:{RESET} {when}{age} \u{2014} {sender_count} senders. {choices}: "
    );
    std::io::stderr().flush()?;

    let mut answer = String::new();
    if std::io::stdin().read_line(&mut answer).is_err() {
        return Ok(default_cached);
    }

    Ok(match answer.trim().chars().next() {
        Some('u') | Some('U') => true,
        Some('r') | Some('R') => false,
        _ => default_cached,
    })
}

pub fn print_warnings_summary(warnings: &[String]) {
    if warnings.is_empty() {
        return;
    }
    note!(
        "\n{YELLOW}{} email(s) had unparseable or missing List-Unsubscribe headers.{RESET}",
        warnings.len()
    );
    note!("{DIM}Run `unsubscribe warnings` to see details.{RESET}\n");
}

#[allow(clippy::too_many_arguments)]
pub fn cmd_scan(
    account: &AccountConfig,
    credential: &Credential,
    store: &dyn DataStore,
    cache_store: &dyn ScanCacheStore,
    history: Option<&dyn HistoryStore>,
    preferences: &Preferences,
    as_json: bool,
    tty: Tty,
) -> Result<Exit> {
    let (senders, warnings) = do_scan(account, credential, store, cache_store, preferences, tty)?;

    // Same judgement the run makes, so the two commands never disagree about
    // which sender ignored its unsubscribe -- and recording it here means a
    // plain `scan` builds the violation log too.
    let history_view = load_history(history, &account.account_id);
    let policy = run_policy(preferences);
    let now = now_unix_secs();

    // Observe first, judge second: a sender caught ignoring an unsubscribe on
    // this very scan has already spent that rung.
    let mut resumptions = history_view.resumptions;
    let observed = observed_resumptions(
        &account.account_id,
        &senders,
        &history_view.attempts,
        &resumptions,
        now,
        policy.grace_period_days,
    );
    record_scan_resumptions(&observed, history);
    resumptions.extend(observed);

    let latest = LatestAttempts::from_history(&history_view.attempts);
    let verdicts: Vec<Option<SenderVerdict>> = senders
        .iter()
        .map(|sender| {
            judge_sender(
                sender,
                &latest,
                &history_view.attempts,
                &resumptions,
                now,
                policy.grace_period_days,
            )
        })
        .collect();

    if as_json {
        output::emit_json(&scan_document(
            account,
            &senders,
            &verdicts,
            preferences,
            &warnings,
        ))?;
        return Ok(if senders.is_empty() {
            Exit::NothingToDo
        } else {
            Exit::Success
        });
    }

    if senders.is_empty() {
        note!("{YELLOW}No senders with unsubscribe links found.{RESET}");
        print_warnings_summary(&warnings);
        return Ok(Exit::NothingToDo);
    }

    println!(
        "\n{BOLD}{CYAN}Found {} senders with unsubscribe links:{RESET}\n",
        senders.len()
    );
    println!(
        "{DIM}{:<45} {:<35} {:>7} {:>8}{RESET}",
        "Name", "Email", "Method", "Emails"
    );
    println!("{DIM}{}{RESET}", "-".repeat(100));

    for (s, verdict) in senders.iter().zip(&verdicts) {
        let name = if s.display_name.is_empty() {
            "-"
        } else {
            &s.display_name
        };
        // What happened after a previous unsubscribe outranks staleness: a
        // sender that came back is the finding, stale or not.
        let (marker, marker_color) = match verdict {
            Some(verdict) => (outcome_marker(verdict), outcome_color(verdict)),
            None if is_stale(s, preferences.stale_after_months) => {
                (" [stale]".to_string(), DIM)
            }
            None => (String::new(), DIM),
        };
        let (method, method_color) = if s.one_click {
            ("1-click", GREEN)
        } else if !s.unsubscribe_urls.is_empty() {
            ("http", CYAN)
        } else {
            ("mailto", BLUE)
        };
        println!(
            " {:<44} {DIM}{:<34}{RESET} {method_color}{:>7}{RESET} {:>8}{marker_color}{marker}{RESET}",
            truncate(name, 44),
            truncate(&s.email, 34),
            method,
            s.email_count
        );
    }

    let total_emails: u32 = senders.iter().map(|s| s.email_count).sum();
    let stale_count = senders
        .iter()
        .filter(|s| is_stale(s, preferences.stale_after_months))
        .count();
    let previous_count = verdicts.iter().flatten().count();
    let resumed_count = verdicts
        .iter()
        .flatten()
        .filter(|v| v.outcome.is_resumed())
        .count();
    let notes: Vec<String> = [
        (previous_count, "previously unsubscribed"),
        (resumed_count, "resumed"),
        (stale_count, "stale"),
    ]
    .iter()
    .filter(|(count, _)| *count > 0)
    .map(|(count, label)| format!("{count} {label}"))
    .collect();
    let stale_note = if notes.is_empty() {
        String::new()
    } else {
        format!(" ({})", notes.join(", "))
    };
    println!(
        "\n{BOLD}Total:{RESET} {} senders{stale_note}, {} emails",
        senders.len(),
        total_emails
    );

    print_warnings_summary(&warnings);

    Ok(Exit::Success)
}

/// Everything `scan` found, sender by sender.
fn scan_document(
    account: &AccountConfig,
    senders: &[SenderInfo],
    verdicts: &[Option<SenderVerdict>],
    preferences: &Preferences,
    warnings: &[String],
) -> Value {
    let rows: Vec<Value> = senders
        .iter()
        .zip(verdicts)
        .map(|(sender, verdict)| {
            let mut row = json_out::identity(sender);
            json_out::merge(
                &mut row,
                json!({
                    "email_count": sender.email_count,
                    "messages": sender.messages.len(),
                    "last_seen": sender.last_seen,
                    "method": json_out::offered_method(sender),
                    "one_click": sender.one_click,
                    "stale": is_stale(sender, preferences.stale_after_months),
                    "history": verdict.as_ref().map(|v| json!({
                        "previously_unsubscribed": true,
                        "attempt_id": v.attempt_id,
                        "unsubscribed_at": v.unsubscribed_at,
                        "outcome": json_out::outcome(v.outcome),
                        "violation_count": v.violation_count,
                        "next_step": json_out::next_step(&v.next_step),
                    })),
                }),
            );
            row
        })
        .collect();

    let mut doc = json_out::document("scan", &account.account_id);
    doc.insert("senders".to_string(), json!(rows));
    doc.insert(
        "totals".to_string(),
        json!({
            "senders": senders.len(),
            "emails": senders.iter().map(|s| s.email_count).sum::<u32>(),
            "stale": senders
                .iter()
                .filter(|s| is_stale(s, preferences.stale_after_months))
                .count(),
            "previously_unsubscribed": verdicts.iter().flatten().count(),
            "resumed": verdicts
                .iter()
                .flatten()
                .filter(|v| v.outcome.is_resumed())
                .count(),
        }),
    );
    doc.insert("warnings".to_string(), json!(warnings));
    Value::Object(doc)
}

#[allow(clippy::too_many_arguments)]
pub fn cmd_export(
    account: &AccountConfig,
    credential: &Credential,
    store: &dyn DataStore,
    cache_store: &dyn ScanCacheStore,
    preferences: &Preferences,
    output_path: &Path,
    cached: bool,
    rescan: bool,
    tty: Tty,
) -> Result<Exit> {
    let resolved = resolve_scan(
        account,
        credential,
        store,
        cache_store,
        cached,
        rescan,
        preferences,
        tty.stdin,
        tty,
    )?;
    if resolved.from_cache {
        note!("{DIM}Using cached scan from {}{RESET}", resolved.scanned_at);
    }
    let senders = resolved.senders;

    let mut wtr =
        csv::Writer::from_path(output_path).context("Failed to create CSV")?;

    wtr.write_record([
        "name", "email", "domain", "list_id", "method", "emails", "url", "stale",
    ])?;

    for s in &senders {
        let method = if s.one_click {
            "one-click"
        } else if !s.unsubscribe_urls.is_empty() {
            "http"
        } else {
            "mailto"
        };
        let url = s
            .best_unsubscribe_url()
            .unwrap_or_default()
            .to_string();
        let stale = is_stale(s, preferences.stale_after_months).to_string();

        wtr.write_record([
            s.display_name.as_str(),
            s.email.as_str(),
            s.domain.as_str(),
            s.list_id.as_deref().unwrap_or(""),
            method,
            &s.email_count.to_string(),
            url.as_str(),
            stale.as_str(),
        ])?;
    }

    wtr.flush()?;
    note!(
        "{GREEN}Exported {} senders{RESET} to {output_path:?}",
        senders.len()
    );
    Ok(Exit::Success)
}

/// The policy a listing command judges senders under.
fn run_policy(preferences: &Preferences) -> RunPolicy {
    RunPolicy {
        min_emails: preferences.min_emails,
        stale_after_months: preferences.stale_after_months,
        grace_period_days: preferences.grace_period_days,
        dry_run: false,
    }
}

/// Write every resumption this listing turned up.
///
/// `scan` changes nothing about the mailbox, but observing a sender ignore an
/// unsubscribe is an observation either way, and it cannot be made again later.
fn record_scan_resumptions(observed: &[Resumption], history: Option<&dyn HistoryStore>) {
    let Some(history) = history else {
        return;
    };
    for resumption in observed {
        if let Err(e) = history.record_resumption(resumption) {
            CliWarningsOnly.on_warning(&RunWarning::ResumptionNotRecorded(e.to_string()));
        }
    }
}

/// The short marker a listing row carries for a previously unsubscribed sender.
fn outcome_marker(verdict: &SenderVerdict) -> String {
    let violations = if verdict.violation_count > 1 {
        format!(" x{}", verdict.violation_count)
    } else {
        String::new()
    };
    match verdict.outcome {
        UnsubscribeOutcome::NoNewMail => " [unsubscribed]".to_string(),
        UnsubscribeOutcome::WithinGrace { days_left } => {
            format!(" [grace: {days_left}d left]")
        }
        UnsubscribeOutcome::Resumed { days_after } => {
            format!(" [resumed {days_after}d after{violations}]")
        }
    }
}

fn outcome_color(verdict: &SenderVerdict) -> Ansi {
    match verdict.outcome {
        UnsubscribeOutcome::Resumed { .. } => RED,
        UnsubscribeOutcome::WithinGrace { .. } => YELLOW,
        UnsubscribeOutcome::NoNewMail => DIM,
    }
}

fn truncate(s: &str, max: usize) -> &str {
    match s.char_indices().nth(max) {
        Some((byte_idx, _)) => &s[..byte_idx],
        None => s,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use unsubscribe_core::{AuthType, CacheMeta, CachedScan, ProviderType, ScanWatermark};

    /// A cache store whose answer to `read_scan_cache` is fixed per test.
    ///
    /// Mocked at the port, so these tests exercise the real decision path
    /// without a database or a mailbox.
    struct FakeCacheStore {
        /// What `read_scan_cache` returns: `Err` stands in for a corrupt cache.
        answer: RefCell<Option<Result<Option<CachedScan>>>>,
    }

    impl FakeCacheStore {
        fn with(cache: Option<CachedScan>) -> Self {
            Self {
                answer: RefCell::new(Some(Ok(cache))),
            }
        }

        fn unreadable() -> Self {
            Self {
                answer: RefCell::new(Some(Err(anyhow::anyhow!("database disk image is malformed")))),
            }
        }
    }

    impl ScanCacheStore for FakeCacheStore {
        fn read_scan_cache(&self, _account: &str) -> Result<Option<CachedScan>> {
            self.answer
                .borrow_mut()
                .take()
                .unwrap_or_else(|| Ok(None))
        }

        fn write_scan_cache(&self, _cache: &CachedScan) -> Result<()> {
            Ok(())
        }

        fn remove_cached_senders(&self, _account: &str, _emails: &[String]) -> Result<()> {
            Ok(())
        }
    }

    struct NoopDataStore;

    impl DataStore for NoopDataStore {
        fn write_warnings(&self, _warnings: &[String]) -> Result<()> {
            Ok(())
        }
        fn read_warnings(&self) -> Result<Vec<String>> {
            Ok(Vec::new())
        }
    }

    fn sender(email: &str, email_count: u32) -> SenderInfo {
        SenderInfo {
            display_name: String::new(),
            email: email.to_string(),
            domain: String::new(),
            unsubscribe_urls: vec!["https://acme.com/unsub".to_string()],
            unsubscribe_mailto: Vec::new(),
            one_click: false,
            list_id: None,
            list_unsubscribe_raw: None,
            email_count,
            messages: Vec::new(),
            last_seen: None,
        }
    }

    fn cached_scan(senders: Vec<SenderInfo>) -> CachedScan {
        CachedScan {
            meta: CacheMeta {
                scanned_at: "2026-03-18T19:30:00Z".to_string(),
                format_version: 1,
                account: "user@example.com".to_string(),
            },
            senders,
            watermark: ScanWatermark {
                highest_uid: std::collections::HashMap::new(),
                uid_validity: std::collections::HashMap::new(),
                adapter_state: None,
            },
        }
    }

    fn account() -> AccountConfig {
        AccountConfig {
            account_id: "user@example.com".to_string(),
            provider_type: ProviderType::Imap,
            host: Some("imap.example.com".to_string()),
            port: Some(993),
            username: "user@example.com".to_string(),
            auth_type: AuthType::Password,
            scan_folders: vec!["INBOX".to_string()],
            archive_folder: "Unsubscribed".to_string(),
            smtp_host: None,
            smtp_port: None,
        }
    }

    // -----------------------------------------------------------------------
    // load_cached_senders, through the CLI's cache store
    // -----------------------------------------------------------------------

    #[test]
    fn an_absent_cache_is_not_usable() {
        let store = FakeCacheStore::with(None);
        assert!(load_cached_senders(&store, "user@example.com", 3, &CliWarningsOnly).is_none());
    }

    #[test]
    fn an_unreadable_cache_is_treated_as_absent_rather_than_fatal() {
        let store = FakeCacheStore::unreadable();
        assert!(load_cached_senders(&store, "user@example.com", 3, &CliWarningsOnly).is_none());
    }

    #[test]
    fn a_cache_whose_senders_all_fall_below_min_emails_is_not_usable() {
        // Nothing would be offered, so there is nothing worth asking about.
        let store = FakeCacheStore::with(Some(cached_scan(vec![
            sender("a@acme.com", 1),
            sender("b@acme.com", 2),
        ])));
        assert!(load_cached_senders(&store, "user@example.com", 3, &CliWarningsOnly).is_none());
    }

    #[test]
    fn a_cache_with_no_senders_at_all_is_not_usable() {
        let store = FakeCacheStore::with(Some(cached_scan(vec![])));
        assert!(load_cached_senders(&store, "user@example.com", 0, &CliWarningsOnly).is_none());
    }

    #[test]
    fn usable_cache_keeps_only_senders_at_or_above_min_emails() {
        let store = FakeCacheStore::with(Some(cached_scan(vec![
            sender("below@acme.com", 2),
            sender("exactly@acme.com", 3),
            sender("above@acme.com", 9),
        ])));

        let cached = load_cached_senders(&store, "user@example.com", 3, &CliWarningsOnly)
            .expect("cache is usable");
        assert_eq!(cached.scanned_at, "2026-03-18T19:30:00Z");
        assert_eq!(
            cached
                .senders
                .iter()
                .map(|s| s.email.as_str())
                .collect::<Vec<_>>(),
            ["exactly@acme.com", "above@acme.com"]
        );
    }

    // -----------------------------------------------------------------------
    // resolve_scan, on the paths that never touch the mailbox
    // -----------------------------------------------------------------------

    #[test]
    fn cached_flag_with_no_cache_fails_and_points_at_the_scan_command() {
        let store = FakeCacheStore::with(None);
        let result = resolve_scan(
            &account(),
            &Credential::Password("pw".to_string()),
            &NoopDataStore,
            &store,
            true,
            false,
            &Preferences::default(),
            false,
            Tty::detached(),
        );
        let Err(err) = result else {
            panic!("--cached with no cache must fail");
        };

        assert!(
            err.to_string().contains("unsubscribe scan"),
            "the error should say how to make a cache: {err}"
        );
    }

    #[test]
    fn cached_flag_with_an_unreadable_cache_also_fails() {
        let store = FakeCacheStore::unreadable();
        assert!(resolve_scan(
            &account(),
            &Credential::Password("pw".to_string()),
            &NoopDataStore,
            &store,
            true,
            false,
            &Preferences::default(),
            false,
            Tty::detached(),
        )
        .is_err());
    }

    #[test]
    fn cached_flag_returns_the_filtered_cached_senders_without_scanning() {
        let store = FakeCacheStore::with(Some(cached_scan(vec![
            sender("below@acme.com", 1),
            sender("keep@acme.com", 5),
        ])));

        let resolved = resolve_scan(
            &account(),
            &Credential::Password("pw".to_string()),
            &NoopDataStore,
            &store,
            true,
            false,
            &Preferences::default(),
            false,
            Tty::detached(),
        )
        .expect("the cache should satisfy --cached");

        assert!(resolved.from_cache);
        assert_eq!(resolved.scanned_at, "2026-03-18T19:30:00Z");
        assert_eq!(
            resolved
                .senders
                .iter()
                .map(|s| s.email.as_str())
                .collect::<Vec<_>>(),
            ["keep@acme.com"]
        );
        // The cache does not store warnings, so there are none to report.
        assert!(resolved.warnings.is_empty());
    }

    #[test]
    fn cached_flag_honours_the_min_emails_preference() {
        let store = FakeCacheStore::with(Some(cached_scan(vec![sender("news@acme.com", 4)])));
        let preferences = Preferences {
            min_emails: 5,
            ..Preferences::default()
        };

        // Every cached sender is filtered out, which leaves nothing to use.
        assert!(resolve_scan(
            &account(),
            &Credential::Password("pw".to_string()),
            &NoopDataStore,
            &store,
            true,
            false,
            &preferences,
            false,
            Tty::detached(),
        )
        .is_err());
    }
}
