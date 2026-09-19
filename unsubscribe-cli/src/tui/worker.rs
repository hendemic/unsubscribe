//! Running the core pipeline on the app's behalf.
//!
//! Core is sync and blocking by design -- consumers own their concurrency --
//! so everything that talks to a mailbox or a server goes through here, where
//! the adapters are built and the pipeline stages are called in order. Nothing
//! in this file decides anything: the plan comes from
//! [`unsubscribe_core::plan_run`] and the outcome from
//! [`unsubscribe_core::execute_run`].

use anyhow::Result;
use unsubscribe_core::{
    execute_run, plan_run, AccountConfig, Credential, EmailSender, Folder, HistoryStore,
    Preferences, Resumption, RunContext, RunObserver, RunOutcome, RunPlan, RunPolicy,
    ScanCacheStore, SenderInfo, UnsubscribeAttempt,
};

use crate::{http, make_email_sender, make_provider};

/// The history a selection was annotated against, carried forward to the plan.
///
/// Observe, then judge: the resumptions this scan turned up are already part
/// of the record by the time the selection screen opens, and the plan has to
/// see them or it will re-try the rung that was just shown not to work.
#[derive(Debug, Clone, Default)]
pub struct SelectionContext {
    pub attempts: Vec<UnsubscribeAttempt>,
    pub resumptions: Vec<Resumption>,
}

/// Work out what a run would do to the selected senders.
#[must_use]
pub fn plan(
    selected: Vec<SenderInfo>,
    history: &SelectionContext,
    policy: &RunPolicy,
    now: i64,
) -> RunPlan {
    plan_run(
        selected,
        &history.attempts,
        &history.resumptions,
        policy,
        now,
    )
}

/// Carry out a plan, building the adapters it needs.
///
/// A mailto sender that cannot be built is not fatal: the flow skips
/// mailto-only senders rather than aborting, exactly as the command does.
pub fn execute(
    account: &AccountConfig,
    credential: &Credential,
    cache: &dyn ScanCacheStore,
    history: Option<&dyn HistoryStore>,
    plan: &RunPlan,
    policy: &RunPolicy,
    observer: &dyn RunObserver,
) -> Result<RunOutcome> {
    let provider = make_provider(account, credential)?;
    let http_client = http::ReqwestHttpClient::new()?;
    let email_sender: Option<Box<dyn EmailSender>> = if policy.dry_run {
        None
    } else {
        make_email_sender(account, credential).ok()
    };
    let archive_folder = Folder::new(&account.archive_folder);

    let ctx = RunContext {
        account: &account.account_id,
        archive_folder: &archive_folder,
        provider: provider.as_ref(),
        http: &http_client,
        email_sender: email_sender.as_deref(),
        history,
        cache,
        observer,
    };
    execute_run(plan, &ctx, policy)
}

/// The policy a run uses, given the user's preferences and a dry-run choice.
#[must_use]
pub fn policy(preferences: &Preferences, dry_run: bool) -> RunPolicy {
    RunPolicy {
        min_emails: preferences.min_emails,
        stale_after_months: preferences.stale_after_months,
        grace_period_days: preferences.grace_period_days,
        dry_run,
    }
}
