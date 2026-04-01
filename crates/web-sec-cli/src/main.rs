use std::{io, path::PathBuf};

use clap::{Parser, Subcommand};
use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
    Terminal,
};
use web_sec_core::{analysis_result::AnalysisResult, har_scanner::HarScanner, severity::Severity};

#[derive(Parser)]
#[command(name = "web-sec")]
#[command(about = "A web security analysis tool for HAR files")]
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
            let results = HarScanner::scan_file(&file)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
            run_tui(results)?;
        }
    }

    Ok(())
}

fn run_tui(results: Vec<AnalysisResult>) -> io::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = event_loop(&mut terminal, &results);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}

fn event_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    results: &[AnalysisResult],
) -> io::Result<()> {
    loop {
        terminal.draw(|frame| render(frame, results))?;

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

fn render(frame: &mut ratatui::Frame, results: &[AnalysisResult]) {
    let area = frame.area();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(area);

    // Title bar
    let title = Paragraph::new("web-sec — Security Analysis Results")
        .style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(title, chunks[0]);

    // Results table
    let header = Row::new(vec![
        Cell::from("Severity").style(
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("Name").style(
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("Comment").style(
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
            let color = match r.severity {
                Severity::Ok => Color::Green,
                Severity::Warning => Color::Yellow,
                Severity::Fail => Color::Red,
            };
            Row::new(vec![
                Cell::from(r.severity.to_emoji())
                    .style(Style::default().fg(color)),
                Cell::from(r.name.as_str())
                    .style(Style::default().fg(Color::White)),
                Cell::from(r.comment.as_str())
                    .style(Style::default().fg(Color::White)),
            ])
        })
        .collect();

    let empty_msg;
    let display_rows: Vec<Row> = if rows.is_empty() {
        empty_msg = Row::new(vec![
            Cell::from(""),
            Cell::from("No security issues found.")
                .style(Style::default().fg(Color::Gray)),
            Cell::from(""),
        ]);
        vec![empty_msg]
    } else {
        rows
    };

    let table = Table::new(
        display_rows,
        [
            Constraint::Length(10),
            Constraint::Percentage(35),
            Constraint::Fill(1),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title("Results"),
    );

    frame.render_widget(table, chunks[1]);

    // Footer
    let footer = Paragraph::new("Press 'q' or Esc to quit")
        .style(Style::default().fg(Color::DarkGray));
    frame.render_widget(footer, chunks[2]);
}
