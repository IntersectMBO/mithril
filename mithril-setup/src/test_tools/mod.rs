//! Tools shared by the tests of the crate

pub mod file;
pub mod logs;

/// Return the path of the given function.
/// If the last function is `f`, it is removed.
/// The last `{{closure}}` is also removed.
pub fn format_current_function_module<T>(f: T) -> &'static str {
    fn type_name_of<T>(_: T) -> &'static str {
        std::any::type_name::<T>()
    }

    let name = type_name_of(f);
    let name = name.strip_suffix("::f").unwrap_or(name);
    name.strip_suffix("::{{closure}}").unwrap_or(name)
}

/// Return a string representing the path of the given function.
pub fn format_current_function_path<T>(f: T) -> String {
    let name = format_current_function_module(f);
    name.replace("::", "/")
}

/// Returns the path of the function that called this macro.
#[macro_export]
macro_rules! current_function_path {
    () => {{
        fn f() {}

        std::path::PathBuf::from($crate::test_tools::format_current_function_path(f))
    }};
}
