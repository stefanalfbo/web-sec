use crate::analysis_result::AnalysisResult;

const BASELINE: i32 = 100;
const MAX_SCORE: i32 = 145;
const BONUS_THRESHOLD: i32 = 90;

/// The computed score and letter grade for a scan.
#[derive(Debug, Clone, PartialEq)]
pub struct ScanScore {
    pub score: i32,
    pub grade: &'static str,
}

impl ScanScore {
    /// Calculate the score from a set of analysis results using the two-round
    /// HTTP Observatory method:
    ///
    /// - Round 1: penalties are deducted from the baseline of 100.
    /// - Round 2: bonuses are added only if the round-1 score is >= 90.
    ///
    /// Final score is clamped to [0, 145].
    pub fn calculate(results: &[AnalysisResult]) -> Self {
        let penalties: i32 = results
            .iter()
            .filter(|r| r.score_impact < 0)
            .map(|r| r.score_impact)
            .sum();

        let round1 = (BASELINE + penalties).clamp(0, BASELINE);

        let bonuses: i32 = if round1 >= BONUS_THRESHOLD {
            results
                .iter()
                .filter(|r| r.score_impact > 0)
                .map(|r| r.score_impact)
                .sum()
        } else {
            0
        };

        let score = (round1 + bonuses).clamp(0, MAX_SCORE);
        Self {
            score,
            grade: Self::grade(score),
        }
    }

    pub fn grade(score: i32) -> &'static str {
        match score {
            100..=i32::MAX => "A+",
            90..=99 => "A",
            85..=89 => "A-",
            80..=84 => "B+",
            70..=79 => "B",
            65..=69 => "B-",
            60..=64 => "C+",
            50..=59 => "C",
            45..=49 => "C-",
            40..=44 => "D+",
            30..=39 => "D",
            25..=29 => "D-",
            _ => "F",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::severity::Severity;

    fn result(score_impact: i32) -> AnalysisResult {
        AnalysisResult::new(Severity::Ok, "check", "comment").with_score(score_impact)
    }

    #[test]
    fn perfect_score_with_no_results() {
        let score = ScanScore::calculate(&[]);
        assert_eq!(score.score, 100);
        assert_eq!(score.grade, "A+");
    }

    #[test]
    fn penalty_is_deducted_from_baseline() {
        let score = ScanScore::calculate(&[result(-25)]);
        assert_eq!(score.score, 75);
        assert_eq!(score.grade, "B");
    }

    #[test]
    fn multiple_penalties_are_summed() {
        let score = ScanScore::calculate(&[result(-20), result(-20), result(-5)]);
        assert_eq!(score.score, 55);
        assert_eq!(score.grade, "C");
    }

    #[test]
    fn score_is_clamped_to_zero() {
        let score = ScanScore::calculate(&[result(-200)]);
        assert_eq!(score.score, 0);
        assert_eq!(score.grade, "F");
    }

    #[test]
    fn bonus_applied_when_round1_score_is_90_or_more() {
        let score = ScanScore::calculate(&[result(10)]);
        assert_eq!(score.score, 110);
        assert_eq!(score.grade, "A+");
    }

    #[test]
    fn bonus_not_applied_when_round1_score_below_90() {
        // -20 penalty brings score to 80, bonus should NOT apply
        let score = ScanScore::calculate(&[result(-20), result(10)]);
        assert_eq!(score.score, 80);
        assert_eq!(score.grade, "B+");
    }

    #[test]
    fn score_is_clamped_to_max() {
        let score = ScanScore::calculate(&[result(100)]);
        assert_eq!(score.score, MAX_SCORE);
    }

    #[test]
    fn grade_boundaries() {
        assert_eq!(ScanScore::grade(100), "A+");
        assert_eq!(ScanScore::grade(99), "A");
        assert_eq!(ScanScore::grade(90), "A");
        assert_eq!(ScanScore::grade(89), "A-");
        assert_eq!(ScanScore::grade(85), "A-");
        assert_eq!(ScanScore::grade(84), "B+");
        assert_eq!(ScanScore::grade(80), "B+");
        assert_eq!(ScanScore::grade(79), "B");
        assert_eq!(ScanScore::grade(70), "B");
        assert_eq!(ScanScore::grade(69), "B-");
        assert_eq!(ScanScore::grade(65), "B-");
        assert_eq!(ScanScore::grade(64), "C+");
        assert_eq!(ScanScore::grade(60), "C+");
        assert_eq!(ScanScore::grade(59), "C");
        assert_eq!(ScanScore::grade(50), "C");
        assert_eq!(ScanScore::grade(49), "C-");
        assert_eq!(ScanScore::grade(45), "C-");
        assert_eq!(ScanScore::grade(44), "D+");
        assert_eq!(ScanScore::grade(40), "D+");
        assert_eq!(ScanScore::grade(39), "D");
        assert_eq!(ScanScore::grade(30), "D");
        assert_eq!(ScanScore::grade(29), "D-");
        assert_eq!(ScanScore::grade(25), "D-");
        assert_eq!(ScanScore::grade(24), "F");
        assert_eq!(ScanScore::grade(0), "F");
    }
}
