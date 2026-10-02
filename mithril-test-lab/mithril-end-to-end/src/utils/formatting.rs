use crate::utils::is_running_in_github_actions;

/// Handle printing a log group title and a separator.
///
/// If running in GitHub actions, the logs produced between the creation of the group and its
/// drop will be wrapped within a `::group::` and `::endgroup::` github action command.
pub struct LogGroup;

impl LogGroup {
    pub fn new(name: &str, title: &str) -> Self {
        let group_title = Self::group_title(name, title);
        if is_running_in_github_actions() {
            println!("::group::{group_title}");
        }
        Self::print_header(&group_title);

        Self
    }

    fn group_title(name: &str, title: &str) -> String {
        format!("{} LOGS - {}:", name.to_uppercase(), title)
    }

    fn print_header(title: &str) {
        println!("{:-^100}", "");
        println!("{title:^30}",);
        println!("{:-^100}", "");
    }
}

impl Drop for LogGroup {
    fn drop(&mut self) {
        if is_running_in_github_actions() {
            println!("::endgroup::");
        }
    }
}
