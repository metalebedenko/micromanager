//! micromanager — библиотечный крейт ядра.
//!
//! Модули переиспользуются бинарём (`src/main.rs`) и интеграционными тестами.
//! По мере плана фазы 1 добавляются: safety, audit, platform.

pub mod audit;
pub mod brain;
pub mod command;
pub mod net;
pub mod paths;
pub mod platform;
pub mod safety;
pub mod server;
pub mod tg;
pub mod tui;
