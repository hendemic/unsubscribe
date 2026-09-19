//! The navigation state machine: which section is highlighted, which pane has
//! focus, and what going back means.
//!
//! Terminal-free on purpose. The shell owns a [`Navigator`] and a stack of
//! sub-views; every transition between them is decided here, as a plain
//! function of the current state and one [`Action`], so the whole "Enter in,
//! Esc out" model can be driven from a test without a `Tui`.

use super::keys::{self, Action};

/// One entry in the left-hand nav.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Section {
    Run,
    List,
    Warnings,
    Logs,
    Settings,
    Quit,
}

impl Section {
    pub const ALL: [Section; 6] = [
        Self::Run,
        Self::List,
        Self::Warnings,
        Self::Logs,
        Self::Settings,
        Self::Quit,
    ];

    /// The label in the nav, and the title of the working area.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Run => "Run",
            Self::List => "Unsubscribe List",
            Self::Warnings => "Warnings",
            Self::Logs => "Logs",
            Self::Settings => "Settings",
            Self::Quit => "Quit",
        }
    }

    /// Whether the section has a working area to move into. Quit has none:
    /// there is nothing to preview and nothing to focus.
    #[must_use]
    pub fn has_panel(self) -> bool {
        !matches!(self, Self::Quit)
    }
}

/// Which pane answers keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Focus {
    Nav,
    Panel,
}

/// What the nav asked the shell to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NavOutcome {
    /// Handled: the highlight moved, or the key meant nothing here.
    Stay,
    /// Focus moved into the working area of this section.
    Entered(Section),
    Quit,
    /// Toggle the help overlay.
    Help,
}

/// What backing out of the working area does, given how deep the user is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Back {
    /// Close the sub-view on top of the panel.
    PopSubView,
    /// Leave the panel's top level; the nav takes focus.
    ToNav,
    /// Already at the floor. Esc never quits.
    Nothing,
}

/// Where the user is: the highlighted section, which pane has focus, and
/// whether the help overlay is up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Navigator {
    cursor: usize,
    focus: Focus,
    pub help: bool,
}

impl Default for Navigator {
    fn default() -> Self {
        Self {
            cursor: 0,
            focus: Focus::Nav,
            help: false,
        }
    }
}

impl Navigator {
    /// The section under the nav cursor. Previewed when the nav has focus,
    /// shown in full when the working area does.
    #[must_use]
    pub fn section(&self) -> Section {
        Section::ALL[self.cursor.min(Section::ALL.len() - 1)]
    }

    #[must_use]
    pub fn nav_has_focus(&self) -> bool {
        self.focus == Focus::Nav
    }

    #[must_use]
    pub fn cursor(&self) -> usize {
        self.cursor
    }

    /// Answer a key while the nav has focus.
    pub fn on_action(&mut self, action: Action) -> NavOutcome {
        let last = Section::ALL.len() - 1;
        if let Some(cursor) = keys::move_cursor(action, self.cursor, last) {
            self.cursor = cursor;
            return NavOutcome::Stay;
        }
        match action {
            Action::Activate | Action::FocusIn => match self.section() {
                Section::Quit => NavOutcome::Quit,
                section => {
                    self.focus = Focus::Panel;
                    NavOutcome::Entered(section)
                }
            },
            // The nav is the floor: q leaves, Esc has nowhere left to go.
            Action::Quit => NavOutcome::Quit,
            Action::Help => NavOutcome::Help,
            _ => NavOutcome::Stay,
        }
    }

    /// Move focus into the working area without going through a key, for the
    /// shell's own transitions (a run finishing, a standalone entry point).
    pub fn enter_panel(&mut self, section: Section) {
        if let Some(index) = Section::ALL.iter().position(|s| *s == section) {
            self.cursor = index;
        }
        if section.has_panel() {
            self.focus = Focus::Panel;
        }
    }

    /// Give the nav focus again, leaving the highlight where it is.
    pub fn focus_nav(&mut self) {
        self.focus = Focus::Nav;
    }

    /// What `Esc` does, given how many sub-views are stacked on the panel.
    ///
    /// Exactly one level per press, and never past the nav -- the app is left
    /// with `q` or `Ctrl-C`, never by backing out of it by accident.
    #[must_use]
    pub fn back(&self, sub_views: usize) -> Back {
        match (self.focus, sub_views) {
            (Focus::Panel, 0) => Back::ToNav,
            (Focus::Panel, _) => Back::PopSubView,
            (Focus::Nav, _) => Back::Nothing,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nav() -> Navigator {
        Navigator::default()
    }

    // -- the nav itself ------------------------------------------------------

    #[test]
    fn the_app_opens_on_run_with_the_nav_in_focus() {
        let nav = nav();

        assert_eq!(nav.section(), Section::Run);
        assert!(nav.nav_has_focus());
    }

    #[test]
    fn moving_walks_the_sections_in_the_order_they_are_listed() {
        let mut nav = nav();

        for expected in [
            Section::List,
            Section::Warnings,
            Section::Logs,
            Section::Settings,
            Section::Quit,
        ] {
            assert_eq!(nav.on_action(Action::MoveDown), NavOutcome::Stay);
            assert_eq!(nav.section(), expected);
        }
    }

    #[test]
    fn the_highlight_stops_at_both_ends_rather_than_wrapping() {
        let mut nav = nav();

        for _ in 0..10 {
            nav.on_action(Action::MoveUp);
        }
        assert_eq!(nav.section(), Section::Run);

        for _ in 0..10 {
            nav.on_action(Action::MoveDown);
        }
        assert_eq!(nav.section(), Section::Quit);
    }

    #[test]
    fn moving_the_highlight_never_moves_focus() {
        let mut nav = nav();

        nav.on_action(Action::MoveDown);

        assert!(nav.nav_has_focus(), "the preview is read-only");
    }

    // -- entering and leaving ------------------------------------------------

    #[test]
    fn enter_and_right_both_move_focus_into_the_working_area() {
        for action in [Action::Activate, Action::FocusIn] {
            let mut nav = nav();

            assert_eq!(nav.on_action(action), NavOutcome::Entered(Section::Run));
            assert!(!nav.nav_has_focus());
        }
    }

    #[test]
    fn quit_is_the_one_section_with_nothing_to_focus() {
        let mut nav = nav();
        nav.on_action(Action::Last);

        assert_eq!(nav.on_action(Action::Activate), NavOutcome::Quit);
        assert!(nav.nav_has_focus());
    }

    #[test]
    fn q_leaves_the_app_from_the_nav() {
        assert_eq!(nav().on_action(Action::Quit), NavOutcome::Quit);
    }

    #[test]
    fn esc_at_the_nav_does_nothing_at_all() {
        let mut nav = nav();

        assert_eq!(nav.on_action(Action::Back), NavOutcome::Stay);
        assert_eq!(nav.back(0), Back::Nothing);
        assert_eq!(nav.back(3), Back::Nothing, "even with sub-views stacked");
    }

    // -- backing out ---------------------------------------------------------

    #[test]
    fn esc_in_a_panel_with_no_sub_view_returns_to_the_nav() {
        let mut nav = nav();
        nav.on_action(Action::Activate);

        assert_eq!(nav.back(0), Back::ToNav);
    }

    #[test]
    fn esc_inside_a_sub_view_closes_only_that_sub_view() {
        let mut nav = nav();
        nav.on_action(Action::Activate);

        assert_eq!(nav.back(1), Back::PopSubView);
        assert_eq!(nav.back(2), Back::PopSubView);
    }

    #[test]
    fn focusing_the_nav_again_leaves_the_highlight_where_it_was() {
        let mut nav = nav();
        nav.on_action(Action::MoveDown);
        nav.on_action(Action::Activate);

        nav.focus_nav();

        assert_eq!(nav.section(), Section::List);
        assert!(nav.nav_has_focus());
    }

    #[test]
    fn the_shell_can_open_a_section_without_a_keypress() {
        let mut nav = nav();

        nav.enter_panel(Section::Settings);

        assert_eq!(nav.section(), Section::Settings);
        assert!(!nav.nav_has_focus());
    }

    #[test]
    fn opening_quit_that_way_highlights_it_without_focusing_anything() {
        let mut nav = nav();

        nav.enter_panel(Section::Quit);

        assert_eq!(nav.section(), Section::Quit);
        assert!(nav.nav_has_focus());
    }

    // -- help ----------------------------------------------------------------

    #[test]
    fn the_help_key_is_answered_by_the_shell_rather_than_the_nav() {
        let mut nav = nav();

        assert_eq!(nav.on_action(Action::Help), NavOutcome::Help);
        assert!(!nav.help, "the nav reports it; the shell flips it");
    }
}
