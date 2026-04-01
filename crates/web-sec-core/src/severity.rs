/// Represents the severity levels for security issues.
#[derive(Debug, Clone, PartialEq)]
pub enum Severity {
    Ok,
    Warning,
    Fail,
}

impl Severity {
    pub fn to_emoji(&self) -> &'static str {
        match self {
            Severity::Ok => "✅",
            Severity::Warning => "⚠️",
            Severity::Fail => "⛔",
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_emoji())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ok_severity_returns_checkmark_emoji() {
        assert_eq!(Severity::Ok.to_emoji(), "✅");
    }

    #[test]
    fn warning_severity_returns_warning_emoji() {
        assert_eq!(Severity::Warning.to_emoji(), "⚠️");
    }

    #[test]
    fn fail_severity_returns_no_entry_emoji() {
        assert_eq!(Severity::Fail.to_emoji(), "⛔");
    }

    #[test]
    fn severity_display_uses_emoji() {
        assert_eq!(format!("{}", Severity::Ok), "✅");
        assert_eq!(format!("{}", Severity::Warning), "⚠️");
        assert_eq!(format!("{}", Severity::Fail), "⛔");
    }

    #[test]
    fn severity_equality() {
        assert_eq!(Severity::Ok, Severity::Ok);
        assert_eq!(Severity::Warning, Severity::Warning);
        assert_eq!(Severity::Fail, Severity::Fail);
        assert_ne!(Severity::Ok, Severity::Fail);
    }
}
