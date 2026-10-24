//! Диалог выбора файла (.exe) через `rfd`.

pub fn pick_executable() -> Option<String> {
    rfd::FileDialog::new()
        .set_title("Выбор программы (.exe)")
        .add_filter("Программы", &["exe"])
        .add_filter("Все файлы", &["*"])
        .pick_file()
        .map(|p| p.display().to_string())
}
