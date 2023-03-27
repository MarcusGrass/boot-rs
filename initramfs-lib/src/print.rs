#[derive(Debug, Copy, Clone)]
pub enum Color {
    Green,
    Red,
    Yellow,
}

impl Color {
    pub fn to_code(self) -> &'static str {
        match self {
            Color::Green => "\u{001b}[32;1m",
            Color::Red => "\u{001b}[31;1m",
            Color::Yellow => "\u{001b}[33;1m",
        }
    }
}

#[macro_export]
macro_rules! format_colored {
    ($color: expr, $fmt:expr) => {{
        format_args!("{}{}\u{001b}[0m", $color.to_code(), format_args!($fmt))
    }};

    ($color: expr, $fmt:expr, $($args:tt)*) => {{
        format_args!("{}{}\u{001b}[0m", $color.to_code(), format_args!($fmt, $($args)*))
    }};
}

#[macro_export]
macro_rules! print_ok {
    ($fmt:expr) => {
        unix_print::unix_println!("{}{}",
            $crate::format_colored!($crate::print::Color::Green, "[initramfs-lib]: "),
            format_args!($fmt)
        )
    };
    ($fmt:expr, $($args:tt)*) => {
        unix_print::unix_println!("{}{}",
            $crate::format_colored!($crate::print::Color::Green, "[initramfs-lib]: "),
            format_args!($fmt, $($args)*)
        )
    };
}

#[macro_export]
macro_rules! print_pending {
    ($fmt:expr) => {
        unix_print::unix_println!("{}{}",
            $crate::format_colored!($crate::print::Color::Yellow, "[initramfs-lib]: "),
            format_args!($fmt)
        )
    };
    ($fmt:expr, $($args:tt)*) => {
        unix_print::unix_println!("{}{}",
            $crate::format_colored!($crate::print::Color::Yellow, "[initramfs-lib]: "),
            format_args!($fmt, $($args)*)
        )
    };
}

#[macro_export]
macro_rules! print_error {
    ($fmt:expr) => {
        unix_print::unix_println!("{}{}",
            $crate::format_colored!($crate::print::Color::Red, "[initramfs-lib]: "),
            format_args!($fmt)
        )
    };
    ($fmt:expr, $($args:tt)*) => {
        unix_print::unix_println!("{}{}",
            $crate::format_colored!($crate::print::Color::Red, "[initramfs-lib]: "),
            format_args!($fmt, $($args)*)
        )
    };
}

#[cfg(test)]
mod tests {
    use crate::print::Color;
    use unix_print::unix_println;

    #[test]
    fn test_print() {
        unix_println!("{}", format_colored!(Color::Green, "Hello"));
        unix_println!(
            "{}",
            format_colored!(Color::Red, "My fmt {}", "other thing")
        );
        print_ok!("Hello again!");
        print_ok!("Hello {} again!", "with format args");
    }
}
