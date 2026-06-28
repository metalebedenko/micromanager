//! Текстовое поле с курсором: общий компонент для всех вводов TUI.
//! `cursor` — индекс В СИМВОЛАХ (UTF-8-safe: русский/эмодзи не ломаются).
//! Чистый компонент без UI: владеет text+cursor, держит курсор на границе
//! символа в [0, char_count]. Рендер берёт `as_str()` + `cursor_line_col()`.

#[derive(Clone, Debug, Default)]
pub struct TextInput {
    text: String,
    cursor: usize, // в символах, 0..=char_count
}

impl TextInput {
    pub fn new() -> Self {
        Self::default()
    }

    fn char_count(&self) -> usize {
        self.text.chars().count()
    }

    /// Байтовый офсет начала символа с индексом `char_idx` (len при char_idx==char_count).
    fn byte_at(&self, char_idx: usize) -> usize {
        self.text
            .char_indices()
            .nth(char_idx)
            .map(|(b, _)| b)
            .unwrap_or(self.text.len())
    }

    pub fn as_str(&self) -> &str {
        &self.text
    }

    pub fn is_empty(&self) -> bool {
        self.text.is_empty()
    }

    pub fn cursor(&self) -> usize {
        self.cursor
    }

    pub fn clear(&mut self) {
        self.text.clear();
        self.cursor = 0;
    }

    /// Заменить весь текст, курсор в конец (навигация по истории ↑/↓).
    pub fn set(&mut self, s: &str) {
        self.text = s.to_string();
        self.cursor = self.char_count();
    }

    /// Вернуть текст и сбросить поле (для mem::take-сайтов).
    pub fn take(&mut self) -> String {
        self.cursor = 0;
        std::mem::take(&mut self.text)
    }

    pub fn insert_char(&mut self, c: char) {
        let at = self.byte_at(self.cursor);
        self.text.insert(at, c);
        self.cursor += 1;
    }

    pub fn insert_newline(&mut self) {
        self.insert_char('\n');
    }

    pub fn backspace(&mut self) {
        if self.cursor == 0 {
            return;
        }
        let start = self.byte_at(self.cursor - 1);
        let end = self.byte_at(self.cursor);
        self.text.replace_range(start..end, "");
        self.cursor -= 1;
    }

    pub fn delete(&mut self) {
        if self.cursor >= self.char_count() {
            return;
        }
        let start = self.byte_at(self.cursor);
        let end = self.byte_at(self.cursor + 1);
        self.text.replace_range(start..end, "");
        // курсор остаётся на месте
    }

    pub fn left(&mut self) {
        if self.cursor > 0 {
            self.cursor -= 1;
        }
    }

    pub fn right(&mut self) {
        if self.cursor < self.char_count() {
            self.cursor += 1;
        }
    }

    /// В начало текущей логической строки (после предыдущего '\n' или начало).
    pub fn home(&mut self) {
        let chars: Vec<char> = self.text.chars().collect();
        let mut i = self.cursor;
        while i > 0 && chars[i - 1] != '\n' {
            i -= 1;
        }
        self.cursor = i;
    }

    /// В конец текущей логической строки (до следующего '\n' или конец).
    pub fn end(&mut self) {
        let chars: Vec<char> = self.text.chars().collect();
        let mut i = self.cursor;
        while i < chars.len() && chars[i] != '\n' {
            i += 1;
        }
        self.cursor = i;
    }

    /// (индекс логической строки, столбец в символах) позиции курсора — для рендера.
    pub fn cursor_line_col(&self) -> (usize, usize) {
        let mut line = 0;
        let mut col = 0;
        for (i, ch) in self.text.chars().enumerate() {
            if i == self.cursor {
                break;
            }
            if ch == '\n' {
                line += 1;
                col = 0;
            } else {
                col += 1;
            }
        }
        (line, col)
    }
}

impl From<&str> for TextInput {
    fn from(s: &str) -> Self {
        Self {
            text: s.to_string(),
            cursor: s.chars().count(),
        }
    }
}

impl From<String> for TextInput {
    fn from(s: String) -> Self {
        let cursor = s.chars().count();
        Self { text: s, cursor }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_at_end_and_middle() {
        let mut t = TextInput::new();
        for c in "abc".chars() {
            t.insert_char(c);
        }
        assert_eq!(t.as_str(), "abc");
        assert_eq!(t.cursor(), 3);
        t.left();
        t.left(); // курсор между a и b
        t.insert_char('X');
        assert_eq!(t.as_str(), "aXbc");
        assert_eq!(t.cursor(), 2);
    }

    #[test]
    fn cyrillic_insert_and_delete_is_safe() {
        let mut t = TextInput::from("привет");
        t.home(); // в начало
        t.insert_char('ё');
        assert_eq!(t.as_str(), "ёпривет");
        t.delete(); // удалить 'п' (под курсором после 'ё')
        assert_eq!(t.as_str(), "ёривет");
        t.backspace(); // удалить 'ё' слева
        assert_eq!(t.as_str(), "ривет");
    }

    #[test]
    fn left_right_clamp_at_bounds() {
        let mut t = TextInput::from("ab");
        t.right();
        t.right();
        t.right(); // за конец — клампится
        assert_eq!(t.cursor(), 2);
        t.left();
        t.left();
        t.left(); // за начало — клампится
        assert_eq!(t.cursor(), 0);
    }

    #[test]
    fn backspace_at_start_and_delete_at_end_noop() {
        let mut t = TextInput::from("x");
        t.home();
        t.backspace(); // в начале — no-op
        assert_eq!(t.as_str(), "x");
        t.end();
        t.delete(); // в конце — no-op
        assert_eq!(t.as_str(), "x");
    }

    #[test]
    fn home_end_within_logical_line_multiline() {
        let mut t = TextInput::from("abc\ndefg");
        // курсор в конце (после g). end текущей (второй) строки — там же.
        t.home();
        assert_eq!(t.cursor(), 4); // начало второй строки (после '\n')
        t.end();
        assert_eq!(t.cursor(), 8); // конец второй строки
    }

    #[test]
    fn left_crosses_newline() {
        let mut t = TextInput::from("a\nb");
        t.home(); // начало второй строки (cursor=2, перед 'b')
        t.left(); // через '\n' назад
        assert_eq!(t.cursor(), 1); // после 'a'
    }

    #[test]
    fn cursor_line_col_multiline() {
        let mut t = TextInput::from("ab\ncd");
        // курсор в конце ("cd") → строка 1, столбец 2
        assert_eq!(t.cursor_line_col(), (1, 2));
        t.home(); // строка 1, столбец 0
        assert_eq!(t.cursor_line_col(), (1, 0));
        t.left(); // на '\n' границу → строка 0, столбец 2
        assert_eq!(t.cursor_line_col(), (0, 2));
    }

    #[test]
    fn set_moves_cursor_to_end_take_resets() {
        let mut t = TextInput::from("ab");
        t.home();
        t.set("новый");
        assert_eq!(t.as_str(), "новый");
        assert_eq!(t.cursor(), 5); // в конец
        let taken = t.take();
        assert_eq!(taken, "новый");
        assert!(t.is_empty());
        assert_eq!(t.cursor(), 0);
    }

    #[test]
    fn clear_and_is_empty() {
        let mut t = TextInput::from("x");
        assert!(!t.is_empty());
        t.clear();
        assert!(t.is_empty());
        assert_eq!(t.cursor(), 0);
    }
}
