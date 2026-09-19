//! One key map for the whole app.
//!
//! Every panel matches on an [`Action`], never on a raw `KeyCode`, so the
//! bindings cannot drift apart screen by screen the way they did when each
//! screen carried its own `match key.code`. The footer hints and the `?`
//! overlay are generated from the same table the bindings come from, so the
//! two can never disagree about what a key does.
//!
//! The reserved keys -- movement, `Enter`, `Esc`, `q`, `/`, `?`, `Space` --
//! mean the same thing everywhere. A panel's own actions are single letters
//! from [`MNEMONICS`], which is the whole app's letter budget in one place:
//! a letter means one concept, in every panel that offers that concept.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

/// Rows a page key moves.
pub const PAGE: usize = 10;

/// Rows `Ctrl` with an arrow moves.
pub const JUMP: usize = 5;

/// What a keypress means, whatever screen it arrives on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    MoveUp,
    MoveDown,
    /// `Ctrl` with an arrow: [`JUMP`] rows at a time.
    JumpUp,
    JumpDown,
    PageUp,
    PageDown,
    First,
    Last,
    /// Open, confirm, or act on whatever is under the cursor.
    Activate,
    /// Exactly one level back, or -- in the Run workflow -- out to the nav
    /// with the sub-view left standing. Never quits.
    Back,
    /// Leave the app. Only the nav answers this.
    Quit,
    Help,
    Search,
    /// Tick or untick the row under the cursor.
    Toggle,
    /// Move focus into the working area (Right), or out of it (Left).
    FocusIn,
    FocusOut,
    /// A panel's own action, a letter from [`MNEMONICS`].
    Mnemonic(char),
    /// A printable character, while a text field has focus.
    Type(char),
    /// Backspace, while a text field has focus.
    Erase,
}

/// A key and what it does, for the footer and the help overlay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hint {
    pub keys: &'static str,
    pub what: &'static str,
}

/// The app's panel-action letters: one concept per letter, everywhere.
///
/// Nothing here may collide with a reserved key (`j k g G q`, `/`, `?`), and a
/// panel that offers one of these concepts uses this letter for it.
pub const MNEMONICS: [(&str, &str); 11] = [
    ("a", "select all"),
    // `c` cancels the work in front of the user. `Ctrl-C` is a different key
    // and keeps its own meaning: the shell answers it before the key map.
    ("c", "cancel"),
    // `n` is also the "no" of a confirmation, which is the same convention in
    // every panel that asks one.
    ("n", "select none"),
    ("s", "cycle the sort order"),
    ("r", "show only senders that resumed"),
    ("f", "cycle the event filter"),
    ("d", "toggle dry run"),
    ("u", "unsubscribe from this sender again"),
    ("w", "write the settings to disk"),
    ("x", "discard unsaved changes"),
    ("y", "confirm"),
];

/// Whether `c` is one of the panel-action letters.
fn is_mnemonic(c: char) -> bool {
    MNEMONICS
        .iter()
        .any(|(letter, _)| letter.chars().next() == Some(c))
}

/// Map one keypress to what it means.
///
/// `text_field` is whether a field is taking free text right now: printable
/// keys then type rather than trigger, and only `Esc`, `Enter` and
/// `Backspace` keep their meaning.
///
/// `Ctrl-C` is deliberately absent: the shell answers it before anything else
/// so that no panel can swallow it.
#[must_use]
pub fn action(key: KeyEvent, text_field: bool) -> Option<Action> {
    if text_field {
        return match key.code {
            KeyCode::Enter => Some(Action::Activate),
            KeyCode::Esc => Some(Action::Back),
            KeyCode::Backspace => Some(Action::Erase),
            KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                Some(Action::Type(c))
            }
            _ => None,
        };
    }

    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    match key.code {
        KeyCode::Up if ctrl => Some(Action::JumpUp),
        KeyCode::Down if ctrl => Some(Action::JumpDown),
        KeyCode::Up | KeyCode::Char('k') => Some(Action::MoveUp),
        KeyCode::Down | KeyCode::Char('j') => Some(Action::MoveDown),
        KeyCode::PageUp => Some(Action::PageUp),
        KeyCode::PageDown => Some(Action::PageDown),
        KeyCode::Home | KeyCode::Char('g') => Some(Action::First),
        KeyCode::End | KeyCode::Char('G') => Some(Action::Last),
        KeyCode::Enter => Some(Action::Activate),
        KeyCode::Right => Some(Action::FocusIn),
        KeyCode::Left => Some(Action::FocusOut),
        KeyCode::Esc => Some(Action::Back),
        KeyCode::Char('q') => Some(Action::Quit),
        KeyCode::Char('?') => Some(Action::Help),
        KeyCode::Char('/') => Some(Action::Search),
        KeyCode::Char(' ') => Some(Action::Toggle),
        // A modified letter is never a panel action, so `Ctrl-C` cannot be
        // read as the cancel letter if it ever reaches the key map.
        KeyCode::Char(c) if !ctrl && is_mnemonic(c) => Some(Action::Mnemonic(c)),
        _ => None,
    }
}

/// Move a cursor, if `action` is a movement. `None` for anything else, so a
/// panel can fall through to its own handling in one `match`.
///
/// One helper rather than a `match` per screen: every list in the app then
/// pages and clamps identically, and a list can never wrap by accident.
#[must_use]
pub fn move_cursor(action: Action, cursor: usize, last: usize) -> Option<usize> {
    let moved = match action {
        Action::MoveUp => cursor.saturating_sub(1),
        Action::MoveDown => cursor.saturating_add(1),
        Action::JumpUp => cursor.saturating_sub(JUMP),
        Action::JumpDown => cursor.saturating_add(JUMP),
        Action::PageUp => cursor.saturating_sub(PAGE),
        Action::PageDown => cursor.saturating_add(PAGE),
        Action::First => 0,
        Action::Last => last,
        _ => return None,
    };
    Some(moved.min(last))
}

/// How many rows a movement covers, for a list that has to step one row at a
/// time because its rows are not a flat index range (headers, spacers).
///
/// `First` and `Last` are not steps and are not answered here: a list with an
/// unselectable first row has its own idea of where "first" is.
#[must_use]
pub fn steps(action: Action) -> Option<usize> {
    match action {
        Action::MoveUp | Action::MoveDown => Some(1),
        Action::JumpUp | Action::JumpDown => Some(JUMP),
        Action::PageUp | Action::PageDown => Some(PAGE),
        _ => None,
    }
}

/// Whether a movement goes towards the top of a list.
#[must_use]
pub fn is_backwards(action: Action) -> bool {
    matches!(
        action,
        Action::MoveUp | Action::JumpUp | Action::PageUp | Action::First
    )
}

/// How an action is written in the footer and the help overlay.
///
/// `None` for the actions that are never advertised (typing, focus arrows,
/// which are covered by the movement row).
#[must_use]
pub fn describe(action: Action) -> Option<Hint> {
    let (keys, what) = match action {
        Action::MoveUp | Action::MoveDown => ("\u{2191}\u{2193} / j k", "move"),
        Action::JumpUp | Action::JumpDown => ("Ctrl+\u{2191}\u{2193}", "move five rows"),
        Action::PageUp | Action::PageDown => ("PgUp / PgDn", "move a page"),
        Action::First | Action::Last => ("g / G", "first / last"),
        Action::Activate => ("Enter", "open"),
        Action::Back => ("Esc", "back"),
        Action::Quit => ("q", "quit"),
        Action::Help => ("?", "keys"),
        Action::Search => ("/", "search"),
        Action::Toggle => ("Space", "select"),
        Action::Mnemonic(c) => {
            return MNEMONICS
                .iter()
                .find(|(letter, _)| letter.chars().next() == Some(c))
                .map(|(keys, what)| Hint { keys, what });
        }
        Action::FocusIn | Action::FocusOut | Action::Type(_) | Action::Erase => return None,
    };
    Some(Hint { keys, what })
}

/// What separates two hints in the footer.
const SEPARATOR: &str = "  |  ";

/// What the footer says instead of the hints it had to drop. `?` opens the
/// overlay that lists every key, so the one thing the footer must never lose
/// is the way to see the rest.
const MORE: &str = "?: more";

/// The footer for a focus that answers `actions` on one line, however long
/// it comes out.
///
/// Nothing on screen uses this any more -- every footer wraps -- but the
/// tests that assert "this key is advertised" want the whole list in one
/// string, without a width deciding what they can see.
#[cfg(test)]
#[must_use]
pub fn hints(actions: &[Action]) -> String {
    let mut lines = hint_lines(actions, u16::MAX);
    lines.swap_remove(0)
}

/// The footer for a focus that answers `actions`, wrapped to `width`.
///
/// Pure, and terminal-free, because this is where the footer either tells the
/// truth or silently loses keys: panels now offer more actions than a single
/// line holds, and a clipped hint is indistinguishable from a key that does
/// not exist. Breaks only between whole `key: what` items -- half a hint is
/// worse than no hint -- and gives up at two lines, at which point the tail
/// becomes [`MORE`] rather than growing the footer over the working area.
#[must_use]
pub fn hint_lines(actions: &[Action], width: u16) -> Vec<String> {
    let items: Vec<String> = rows(actions)
        .into_iter()
        .map(|hint| format!("{}: {}", hint.keys, hint.what))
        .collect();
    if items.is_empty() {
        return vec![String::new()];
    }

    let width = width as usize;
    if fits(&items, width) {
        return vec![line(&items)];
    }

    // At least one item on the first line, however narrow the terminal: a
    // line with nothing on it would push the whole footer onto the second.
    let first = taken(&items, width, 0).max(1);
    let rest = &items[first..];
    if rest.is_empty() {
        return vec![line(&items)];
    }
    if fits(rest, width) {
        return vec![line(&items[..first]), line(rest)];
    }

    // Everything past two lines is dropped, so the second line ends with the
    // way to see what was dropped.
    let second = taken(rest, width, SEPARATOR.chars().count() + MORE.chars().count());
    let mut tail: Vec<String> = rest[..second].to_vec();
    tail.push(MORE.to_string());
    vec![line(&items[..first]), line(&tail)]
}

/// One footer line: the leading space every footer has, then the items.
fn line(items: &[String]) -> String {
    format!(" {}", items.join(SEPARATOR))
}

/// Whether `items` fit on one line of `width`.
fn fits(items: &[String], width: usize) -> bool {
    line(items).chars().count() <= width
}

/// How many of `items` fit on one line of `width`, leaving `reserved`
/// columns at the end free.
fn taken(items: &[String], width: usize, reserved: usize) -> usize {
    let budget = width.saturating_sub(reserved);
    (1..=items.len())
        .take_while(|&count| fits(&items[..count], budget))
        .last()
        .unwrap_or(0)
}

/// The rows the `?` overlay lists for a focus that answers `actions`.
#[must_use]
pub fn help_rows(actions: &[Action]) -> Vec<(&'static str, &'static str)> {
    rows(actions)
        .into_iter()
        .map(|hint| (hint.keys, hint.what))
        .collect()
}

/// The hints for `actions`, in order, with the duplicates a paired action
/// produces (up and down describe one row) collapsed.
fn rows(actions: &[Action]) -> Vec<Hint> {
    let mut hints: Vec<Hint> = Vec::new();
    for hint in actions.iter().copied().filter_map(describe) {
        if !hints.contains(&hint) {
            hints.push(hint);
        }
    }
    hints
}

/// The movement keys every list answers, as the prefix of a panel's action
/// list. Written once so no panel forgets a row.
pub const LIST_MOVEMENT: [Action; 8] = [
    Action::MoveUp,
    Action::MoveDown,
    Action::JumpUp,
    Action::JumpDown,
    Action::PageUp,
    Action::PageDown,
    Action::First,
    Action::Last,
];

/// Movement plus a panel's own actions, then the universal tail.
#[must_use]
pub fn list_actions(extra: &[Action]) -> Vec<Action> {
    LIST_MOVEMENT
        .iter()
        .copied()
        .chain(extra.iter().copied())
        .chain([Action::Help, Action::Back])
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn ctrl(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::CONTROL)
    }

    // -- the reserved keys ---------------------------------------------------

    #[test]
    fn the_vim_keys_and_the_arrows_are_the_same_movement() {
        assert_eq!(action(key(KeyCode::Char('j')), false), Some(Action::MoveDown));
        assert_eq!(action(key(KeyCode::Down), false), Some(Action::MoveDown));
        assert_eq!(action(key(KeyCode::Char('k')), false), Some(Action::MoveUp));
        assert_eq!(action(key(KeyCode::Up), false), Some(Action::MoveUp));
    }

    #[test]
    fn ctrl_with_an_arrow_jumps_rather_than_steps() {
        assert_eq!(action(ctrl(KeyCode::Down), false), Some(Action::JumpDown));
        assert_eq!(action(ctrl(KeyCode::Up), false), Some(Action::JumpUp));
    }

    #[test]
    fn esc_is_back_and_q_is_quit_and_they_are_never_the_same_key() {
        assert_eq!(action(key(KeyCode::Esc), false), Some(Action::Back));
        assert_eq!(action(key(KeyCode::Char('q')), false), Some(Action::Quit));
    }

    #[test]
    fn ctrl_c_is_never_read_as_the_cancel_letter() {
        // `c` cancels the work in front of the user; `Ctrl-C` leaves the app.
        // The shell answers Ctrl-C before this map, and the map must not
        // claim it either if that interception ever moves.
        assert_eq!(action(ctrl(KeyCode::Char('c')), false), None);
        assert_eq!(action(ctrl(KeyCode::Char('c')), true), None);
        assert_eq!(
            action(key(KeyCode::Char('c')), false),
            Some(Action::Mnemonic('c'))
        );
    }

    #[test]
    fn a_letter_that_is_not_a_mnemonic_means_nothing() {
        assert_eq!(action(key(KeyCode::Char('z')), false), None);
        assert_eq!(action(key(KeyCode::Char('m')), false), None);
    }

    // -- text fields ---------------------------------------------------------

    #[test]
    fn a_text_field_types_the_keys_that_would_otherwise_act() {
        for c in ['q', 'j', 'g', '/', '?', ' ', 'a'] {
            assert_eq!(
                action(key(KeyCode::Char(c)), true),
                Some(Action::Type(c)),
                "{c} should type in a field"
            );
        }
    }

    #[test]
    fn only_esc_enter_and_backspace_stay_special_in_a_text_field() {
        assert_eq!(action(key(KeyCode::Esc), true), Some(Action::Back));
        assert_eq!(action(key(KeyCode::Enter), true), Some(Action::Activate));
        assert_eq!(action(key(KeyCode::Backspace), true), Some(Action::Erase));
        assert_eq!(action(key(KeyCode::Down), true), None);
    }

    // -- the letter budget ---------------------------------------------------

    #[test]
    fn no_panel_letter_collides_with_a_reserved_key() {
        for (letter, _) in MNEMONICS {
            let c = letter.chars().next().expect("a letter");
            assert_eq!(letter.chars().count(), 1, "{letter} is not one letter");
            let reserved = matches!(c, 'j' | 'k' | 'g' | 'G' | 'q' | '/' | '?');
            assert!(!reserved, "{letter} is reserved");
            assert_eq!(
                action(key(KeyCode::Char(c)), false),
                Some(Action::Mnemonic(c))
            );
        }
    }

    #[test]
    fn every_letter_means_exactly_one_thing() {
        let mut letters: Vec<&str> = MNEMONICS.iter().map(|(letter, _)| *letter).collect();
        let count = letters.len();
        letters.sort_unstable();
        letters.dedup();

        assert_eq!(letters.len(), count, "a letter is listed twice");
    }

    #[test]
    fn every_letter_can_be_written_into_a_hint() {
        for (letter, what) in MNEMONICS {
            let c = letter.chars().next().expect("a letter");
            let hint = describe(Action::Mnemonic(c)).expect("a letter has a hint");
            assert_eq!(hint.what, what);
        }
    }

    // -- cursor movement -----------------------------------------------------

    #[test]
    fn movement_clamps_at_both_ends_rather_than_wrapping() {
        assert_eq!(move_cursor(Action::MoveUp, 0, 9), Some(0));
        assert_eq!(move_cursor(Action::MoveDown, 9, 9), Some(9));
        assert_eq!(move_cursor(Action::PageDown, 0, 9), Some(9));
        assert_eq!(move_cursor(Action::PageUp, 3, 9), Some(0));
        assert_eq!(move_cursor(Action::JumpDown, 0, 9), Some(5));
        assert_eq!(move_cursor(Action::First, 7, 9), Some(0));
        assert_eq!(move_cursor(Action::Last, 0, 9), Some(9));
    }

    #[test]
    fn a_jump_is_five_rows_and_clamps_like_every_other_movement() {
        assert_eq!(move_cursor(Action::JumpDown, 0, 9), Some(JUMP));
        assert_eq!(move_cursor(Action::JumpUp, 9, 9), Some(9 - JUMP));
        assert_eq!(move_cursor(Action::JumpDown, 7, 9), Some(9));
        assert_eq!(move_cursor(Action::JumpUp, 2, 9), Some(0));
    }

    #[test]
    fn the_jump_is_advertised_by_every_list() {
        let rows = help_rows(&list_actions(&[]));

        assert!(
            rows.iter().any(|(keys, _)| keys.contains("Ctrl")),
            "got {rows:?}"
        );
    }

    #[test]
    fn a_step_counting_list_moves_the_same_distance_as_an_indexed_one() {
        // The two ways a list can move must agree, or Ctrl+Down would cover a
        // different distance in Settings than in the Logs.
        for action in [
            Action::MoveDown,
            Action::JumpDown,
            Action::PageDown,
            Action::MoveUp,
            Action::JumpUp,
            Action::PageUp,
        ] {
            let steps = steps(action).expect("a movement");
            let indexed = move_cursor(action, 50, 100).expect("a movement");
            let stepped = if is_backwards(action) {
                50 - steps
            } else {
                50 + steps
            };
            assert_eq!(indexed, stepped, "{action:?}");
        }
    }

    #[test]
    fn first_and_last_are_not_steps_because_a_list_may_start_below_its_top() {
        assert_eq!(steps(Action::First), None);
        assert_eq!(steps(Action::Last), None);
        assert_eq!(steps(Action::Activate), None);
    }

    #[test]
    fn anything_that_is_not_movement_is_left_to_the_panel() {
        assert_eq!(move_cursor(Action::Activate, 0, 9), None);
        assert_eq!(move_cursor(Action::Mnemonic('s'), 0, 9), None);
    }

    // -- hints ---------------------------------------------------------------

    #[test]
    fn the_footer_and_the_overlay_are_built_from_the_same_rows() {
        let actions = list_actions(&[Action::Mnemonic('s'), Action::Search]);
        let footer = hints(&actions);

        for (keys, what) in help_rows(&actions) {
            assert!(footer.contains(keys), "{keys} missing from {footer}");
            assert!(footer.contains(what), "{what} missing from {footer}");
        }
    }

    // -- wrapping ------------------------------------------------------------

    /// A focus with more actions than a narrow footer can hold.
    fn crowded() -> Vec<Action> {
        list_actions(&[
            Action::Toggle,
            Action::Mnemonic('a'),
            Action::Mnemonic('n'),
            Action::Mnemonic('c'),
            Action::Activate,
        ])
    }

    fn widths(lines: &[String]) -> Vec<usize> {
        lines.iter().map(|line| line.chars().count()).collect()
    }

    #[test]
    fn a_footer_that_fits_stays_on_one_line() {
        let lines = hint_lines(&crowded(), 500);

        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0], hints(&crowded()));
    }

    #[test]
    fn a_footer_that_does_not_fit_wraps_onto_a_second_line() {
        let one = hints(&crowded());
        let width = one.chars().count() as u16 / 2 + 10;
        let lines = hint_lines(&crowded(), width);

        assert_eq!(lines.len(), 2);
        for w in widths(&lines) {
            assert!(w <= width as usize, "{lines:?} overflows {width}");
        }
        // Nothing is lost when two lines are enough, and nothing is cut in
        // the middle of a hint.
        for (keys, what) in help_rows(&crowded()) {
            let item = format!("{keys}: {what}");
            assert!(
                lines.iter().any(|line| line.contains(&item)),
                "{item} missing from {lines:?}"
            );
        }
    }

    #[test]
    fn a_footer_too_long_for_two_lines_ends_by_pointing_at_the_overlay() {
        let lines = hint_lines(&crowded(), 30);

        assert_eq!(lines.len(), 2);
        for w in widths(&lines) {
            assert!(w <= 30, "{lines:?} overflows 30");
        }
        assert!(lines[1].ends_with(MORE), "{lines:?}");
    }

    #[test]
    fn the_way_to_see_every_key_is_never_the_hint_that_gets_dropped() {
        // Whatever else a narrow footer loses, `?` has to survive: it is the
        // only way back to the keys that were dropped.
        for width in [10, 20, 30, 45, 60, 120] {
            let lines = hint_lines(&crowded(), width);
            assert!(
                lines.iter().any(|line| line.contains('?')),
                "width {width} lost `?`: {lines:?}"
            );
        }
    }

    #[test]
    fn a_focus_with_no_advertised_keys_has_an_empty_footer() {
        assert_eq!(hint_lines(&[], 80), vec![String::new()]);
    }

    #[test]
    fn a_paired_action_is_listed_once() {
        let rows = help_rows(&[Action::MoveUp, Action::MoveDown]);

        assert_eq!(rows.len(), 1);
    }
}
