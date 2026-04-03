use crate::analysis_result::AnalysisResult;

/// Trait for security analysis implementations.
pub trait Analyze {
    fn analyze(&self) -> Vec<AnalysisResult>;
}
