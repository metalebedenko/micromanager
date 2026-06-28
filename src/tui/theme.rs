//! Визуальная идентичность: палитра «цифрового дождя», стиль-хелперы и ASCII-логотип.

use ratatui::style::{Color, Modifier, Style};

// «Цифровой дождь»: неоново-зелёный на чёрном. Color::Rgb → truecolor;
// на не-truecolor терминалах ratatui деградирует до ближайшего ANSI (не падает).
pub const MATRIX_GREEN: Color = Color::Rgb(0, 255, 65); // #00FF41 — акцент / активное / allow
pub const DIM_GREEN: Color = Color::Rgb(0, 140, 40); // тусклое: неактивные рамки, «вы ›»
pub const AMBER: Color = Color::Rgb(255, 191, 0); // ask-подтверждение
pub const GLITCH_RED: Color = Color::Rgb(255, 60, 60); // dangerous / deny
pub const FG: Color = Color::Rgb(190, 255, 200); // обычный текст

/// Яркий акцент (активное, заголовки, логотип).
pub fn accent() -> Style {
    Style::default().fg(MATRIX_GREEN).add_modifier(Modifier::BOLD)
}

/// Тусклый зелёный (неактивное).
pub fn dim() -> Style {
    Style::default().fg(DIM_GREEN)
}

/// Цвет рамки панели: ярко при фокусе, тускло иначе.
pub fn border(active: bool) -> Style {
    if active {
        accent()
    } else {
        dim()
    }
}

/// Цвет строки журнала действий по вердикту (первое слово).
pub fn activity_style(line: &str) -> Style {
    let l = line.to_ascii_lowercase();
    let color = if l.starts_with("deny") || l.starts_with("dangerous") {
        GLITCH_RED
    } else if l.starts_with("ask") {
        AMBER
    } else {
        MATRIX_GREEN
    };
    Style::default().fg(color)
}

/// ASCII-логотип (MM-монограмма). Ведущий перевод строки убирается при рендере.
pub const LOGO: &str = r#"
  ███╗   ███╗ ███╗   ███╗
  ████╗ ████║ ████╗ ████║
  ██╔████╔██║ ██╔████╔██║
  ██║╚██╔╝██║ ██║╚██╔╝██║
  ██║ ╚═╝ ██║ ██║ ╚═╝ ██║
  ╚═╝     ╚═╝ ╚═╝     ╚═╝
  ░▒▓ m i c r o m a n a g e r ▓▒░
        hands for the machine"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logo_contains_wordmark() {
        // вордмарк под монограммой — буквы через пробел (стиль «разрядки»)
        assert!(LOGO.contains("m i c r o m a n a g e r"));
        assert!(LOGO.contains("hands for the machine"));
    }

    #[test]
    fn activity_style_colors_by_verdict() {
        assert_eq!(activity_style("deny Write: /etc").fg, Some(GLITCH_RED));
        assert_eq!(activity_style("dangerous Exec: rm").fg, Some(GLITCH_RED));
        assert_eq!(activity_style("ask Write: /tmp/x").fg, Some(AMBER));
        assert_eq!(activity_style("allow Read: /tmp").fg, Some(MATRIX_GREEN));
        assert_eq!(activity_style("result Read: ok").fg, Some(MATRIX_GREEN));
    }

    #[test]
    fn border_brighter_when_active() {
        assert_ne!(border(true).fg, border(false).fg);
        assert_eq!(border(true).fg, Some(MATRIX_GREEN));
    }
}
