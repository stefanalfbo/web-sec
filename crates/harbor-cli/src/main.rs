use std::{io, path::PathBuf};

use clap::{Parser, Subcommand};
use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use harbor_core::{
    analysis_result::AnalysisResult,
    har_scanner::{HarScanner, ScanReport},
    scoring::ScanScore,
    severity::Severity,
};
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
};

#[derive(Parser)]
#[command(name = "harbor")]
#[command(about = "Analyzes security headers in HAR files")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a HAR file for security issues
    Scan {
        /// Path to the HAR file to analyze
        #[arg(value_name = "HAR_FILE")]
        file: PathBuf,
    },
}

fn main() -> io::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan { file } => {
            let report = HarScanner::scan_file(&file)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
            run_tui(report)?;
        }
    }

    Ok(())
}

fn run_tui(report: ScanReport) -> io::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = event_loop(&mut terminal, &report.results, &report.score);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}

fn event_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    results: &[AnalysisResult],
    score: &ScanScore,
) -> io::Result<()> {
    loop {
        terminal.draw(|frame| render(frame, results, score))?;

        if event::poll(std::time::Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.code == KeyCode::Char('q') || key.code == KeyCode::Esc {
                    break;
                }
            }
        }
    }
    Ok(())
}

fn grade_color(grade: &str) -> Color {
    match grade {
        "A+" | "A" | "A-" => Color::Green,
        "B+" | "B" | "B-" => Color::LightGreen,
        "C+" | "C" | "C-" => Color::Yellow,
        "D+" | "D" | "D-" => Color::LightRed,
        _ => Color::Red,
    }
}

fn render(frame: &mut ratatui::Frame, results: &[AnalysisResult], score: &ScanScore) {
    let area = frame.area();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // title
            Constraint::Length(3), // score bar
            Constraint::Min(0),    // results table
            Constraint::Length(1), // footer
        ])
        .split(area);

    // Title
    let title = Paragraph::new("Harbor - HAR Security Analyzer")
        .style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(title, chunks[0]);

    // Score bar
    let color = grade_color(score.grade);
    let score_text = format!(
        "  Score: {}  |  Grade: {}  |  {} failures detected",
        score.score,
        score.grade,
        results
            .iter()
            .filter(|r| r.severity == Severity::Fail)
            .count()
    );
    let score_bar = Paragraph::new(score_text)
        .style(Style::default().fg(color).add_modifier(Modifier::BOLD))
        .block(Block::default().borders(Borders::ALL).title("Result"));
    frame.render_widget(score_bar, chunks[1]);

    // Results table
    let header = Row::new(vec![
        Cell::from("Severity").style(
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("Score").style(
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("Check").style(
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("Finding").style(
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
    ])
    .height(1)
    .bottom_margin(1);

    let rows: Vec<Row> = results
        .iter()
        .map(|r| {
            let (sev_color, sev_label) = match r.severity {
                Severity::Ok => (Color::Green, "OK ✅"),
                Severity::Warning => (Color::Yellow, "WARN ⚠️"),
                Severity::Fail => (Color::Red, "FAIL ⛔"),
            };
            let score_str = match r.score_impact {
                0 => "  0".to_string(),
                n if n > 0 => format!("+{n:2}"),
                n => format!("{n:3}"),
            };
            Row::new(vec![
                Cell::from(sev_label).style(Style::default().fg(sev_color)),
                Cell::from(score_str).style(Style::default().fg(sev_color)),
                Cell::from(r.name.as_str()).style(Style::default().fg(Color::White)),
                Cell::from(r.comment.as_str()).style(Style::default().fg(Color::Gray)),
            ])
        })
        .collect();

    let placeholder;
    let display_rows: Vec<Row> = if rows.is_empty() {
        placeholder = Row::new(vec![
            Cell::from(""),
            Cell::from(""),
            Cell::from("No issues found.").style(Style::default().fg(Color::Green)),
            Cell::from(""),
        ]);
        vec![placeholder]
    } else {
        rows
    };

    let table = Table::new(
        display_rows,
        [
            Constraint::Length(10),
            Constraint::Length(6),
            Constraint::Percentage(30),
            Constraint::Fill(1),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title("Security Checks"),
    );

    frame.render_widget(table, chunks[2]);

    // Footer
    let footer =
        Paragraph::new("Press 'q' or Esc to quit").style(Style::default().fg(Color::DarkGray));
    frame.render_widget(footer, chunks[3]);
}
