use anyhow::Context;
use std::{
    fs::{self, create_dir_all},
    path::Path,
    process::Stdio,
};
use tokio::process::Command;

use mithril_common::StdResult;

/// Tail a file into the given stream
///
/// For the sake of simplicity, it uses internally the `tail` command, so be sure to have it on
/// your system.
pub async fn tail(file_path: &Path, number_of_line: u64) -> StdResult<String> {
    let tail_result = Command::new("tail")
        .args(vec![
            "-n",
            &number_of_line.to_string(),
            file_path.to_str().unwrap(),
        ])
        .kill_on_drop(true)
        .output()
        .await
        .with_context(|| format!("Failed to tail file `{}`", file_path.display()))?;

    String::from_utf8(tail_result.stdout).with_context(|| "Failed to parse tail output to utf8")
}

/// Count the number of lines matching the given extended regex in a file.
///
/// For the sake of simplicity, it uses internally the `grep` command, so be sure to have it on
/// your system.
pub async fn count_matching_lines(file_path: &Path, needle: &str) -> StdResult<usize> {
    let grep_result = Command::new("grep")
        .args(vec!["--count", "--extended-regexp", needle])
        .arg(file_path.as_os_str())
        .kill_on_drop(true)
        .output()
        .await
        .with_context(|| format!("Failed to grep file `{}`", file_path.display()))?;

    // grep exit codes: 0 = match found, 1 = no match, other = error
    if !matches!(grep_result.status.code(), Some(0) | Some(1)) {
        anyhow::bail!(
            "Failed to grep file `{}`: {}",
            file_path.display(),
            String::from_utf8_lossy(&grep_result.stderr).trim()
        );
    }

    let output = String::from_utf8(grep_result.stdout)
        .with_context(|| "Failed to parse grep output to utf8")?;
    output
        .trim()
        .parse::<usize>()
        .with_context(|| format!("Failed to parse grep output `{output}` to a number"))
}

/// Return the lastest errors in a file with the lines preceding them.
///
/// For the sake of simplicity, it uses internally the `tail` and `grep` commands, so be sure to have them on
/// your system.
pub async fn last_errors(file_path: &Path, number_of_error: u64) -> StdResult<String> {
    let number_of_line_before = 5;
    let mut grep = Command::new("grep")
        .args(vec![
            "-n",
            "\"level\":50",
            file_path.to_str().unwrap(),
            "-B",
            &number_of_line_before.to_string(),
        ])
        .stdout(Stdio::piped())
        .spawn()
        .with_context(|| format!("Failed to spawn grep file `{}`", file_path.display()))?;

    let tail_stdin: Stdio = grep
        .stdout
        .take()
        .unwrap()
        .try_into()
        .with_context(|| "Failed to convert to Stdio.".to_string())?;

    let result = Command::new("tail")
        .args(vec![
            "-n",
            &(number_of_error * (number_of_line_before + 1)).to_string(),
        ])
        .stdin(tail_stdin)
        .kill_on_drop(true)
        .output()
        .await
        .with_context(|| format!("Failed to tail file `{}`", file_path.display()))?;

    String::from_utf8(result.stdout)
        .map(|s| s.replace("\\n", "\n"))
        .with_context(|| "Failed to parse command output to utf8")
}

/// Join the bin_dir with the bin_name and return the absolute path to the process, failing if the process does not exist.
pub fn get_process_path(bin_name: &str, bin_dir: &Path) -> StdResult<std::path::PathBuf> {
    use anyhow::Context;

    let process_path = std::path::absolute(bin_dir)
        .with_context(|| {
            format!(
                "failed to get absolute path for '{bin_dir}/{bin_name}'",
                bin_dir = bin_dir.display(),
            )
        })?
        .join(bin_name);

    if !process_path.exists() {
        anyhow::bail!(
            "cannot find '{bin_name}' executable in expected location '{bin_dir}'",
            bin_dir = bin_dir.display(),
        );
    }
    Ok(process_path)
}

pub fn copy_dir_all(from: impl AsRef<Path>, to: impl AsRef<Path>) -> StdResult<()> {
    create_dir_all(&to)?;
    for entry in fs::read_dir(from)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        if ty.is_dir() {
            copy_dir_all(entry.path(), to.as_ref().join(entry.file_name()))?;
        } else {
            fs::copy(entry.path(), to.as_ref().join(entry.file_name()))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::prelude::*;
    use std::path::PathBuf;

    use crate::utils::file_utils;

    use mithril_common::{current_function, test::TempDir};

    use super::*;

    fn get_temp_dir(subfolder_name: &str) -> PathBuf {
        TempDir::create("e2e-file-utils", subfolder_name)
    }

    fn write_file(path: &Path, file_content: &str) {
        let mut source_file = File::create(path).unwrap();
        write!(source_file, "{file_content}").unwrap();
    }

    #[tokio::test]
    pub async fn should_tail_file() {
        let file_path = get_temp_dir(current_function!()).join("tail_file.txt");
        write_file(
            &file_path,
            r"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod
        tempor incididunt ut labore et dolore magna aliqua. Nibh venenatis cras sed felis eget
        velit aliquet. Sed adipiscing diam donec adipiscing tristique risus. Luctus accumsan
        tortor posuere ac.
        
        Bibendum enim facilisis gravida neque. Mi eget mauris pharetra et ultrices neque.
        Risus quis varius quam quisque id diam vel quam. Nunc sed velit dignissim sodales ut eu
        sem integer vitae. Integer eget aliquet nibh praesent.
        
        Senectus et netus et malesuada fames ac turpis. Neque convallis a cras semper auctor neque.
        Ac felis donec et odio pellentesque diam.
        Cras ornare arcu dui vivamus arcu felis.
        
        Enim ut tellus elementum sagittis vitae et.
        Aliquam malesuada bibendum arcu vitae elementum curabitur.
        Eu mi bibendum neque egestas congue quisque egestas diam.",
        );

        let tail_result = file_utils::tail(&file_path, 2).await.expect("failed to tail file");

        assert_eq!(
            r"        Aliquam malesuada bibendum arcu vitae elementum curabitur.
        Eu mi bibendum neque egestas congue quisque egestas diam."
                .to_string(),
            tail_result
        );
    }

    #[tokio::test]
    pub async fn should_return_last_error() {
        let temp_dir = get_temp_dir(current_function!());
        let file_path = temp_dir.join("file_with_error.txt");
        write_file(
            &file_path,
            r#"{"msg":"A","content":"Ok"}
{"msg":"B","level":50,"content":"First error\n\nStack backtrace:\nline 1\nline 2"}
{"msg":"C","content":"Ok"}
{"msg":"D","content":"Ok"}
{"msg":"E","content":"Ok"}
{"msg":"F","content":"Ok"}
{"msg":"G","content":"Ok"}
{"msg":"H","content":"Ok"}
{"msg":"I","level":50,"content":"Second error\n\nStack backtrace:\nline 1\nline 2"}
{"msg":"J","level":70,"content":"other error"}
{"msg":"K","content":"Ok"}"#,
        );

        let error_result = file_utils::last_errors(&file_path, 1)
            .await
            .expect("failed to grep file");

        write_file(
            &temp_dir.join("expected.txt"),
            r#"4-{"msg":"D","content":"Ok"}
5-{"msg":"E","content":"Ok"}
6-{"msg":"F","content":"Ok"}
7-{"msg":"G","content":"Ok"}
8-{"msg":"H","content":"Ok"}
9-{"msg":"I","level":50,"content":"Second error

Stack backtrace:
line 1
line 2"}
"#,
        );

        write_file(&temp_dir.join("obtain.txt"), &error_result);

        assert_eq!(
            r#"4-{"msg":"D","content":"Ok"}
5-{"msg":"E","content":"Ok"}
6-{"msg":"F","content":"Ok"}
7-{"msg":"G","content":"Ok"}
8-{"msg":"H","content":"Ok"}
9:{"msg":"I","level":50,"content":"Second error

Stack backtrace:
line 1
line 2"}
"#
            .to_string(),
            error_result
        );
    }

    mod count_matching_lines {
        use super::*;

        #[tokio::test]
        async fn should_count_lines_matching_needle() {
            let file_path = get_temp_dir(current_function!()).join("file.txt");
            write_file(
                &file_path,
                r"needle
haystack
needle and needle
haystack
needle",
            );

            let count = file_utils::count_matching_lines(&file_path, "needle").await.unwrap();

            assert_eq!(3, count);
        }

        #[tokio::test]
        async fn should_match_needle_as_an_extended_regex() {
            let file_path = get_temp_dir(current_function!()).join("file.txt");
            write_file(
                &file_path,
                r#"{"msg":"a","level":50}
{"msg":"b","level":30}
{"msg":"c","level":60}"#,
            );

            let count = file_utils::count_matching_lines(&file_path, r#""level":(50|60)"#)
                .await
                .unwrap();

            assert_eq!(2, count);
        }

        #[tokio::test]
        async fn should_return_zero_when_needle_is_not_found() {
            let file_path = get_temp_dir(current_function!()).join("file.txt");
            write_file(&file_path, "haystack\nhaystack");

            let count = file_utils::count_matching_lines(&file_path, "needle").await.unwrap();

            assert_eq!(0, count);
        }

        #[tokio::test]
        async fn should_fail_when_file_does_not_exist() {
            let file_path = get_temp_dir(current_function!()).join("not_exist.txt");

            let error = file_utils::count_matching_lines(&file_path, "needle")
                .await
                .expect_err("count_matching_lines should fail when the file does not exist");

            assert!(
                format!("{error:?}").contains("No such file or directory"),
                "error should contain grep stderr, got: {error:?}"
            );
        }
    }

    mod copy_dir_all {
        use mithril_common::assert_dir_eq;

        use super::*;

        #[test]
        fn should_copy_directory() {
            let base_dir = get_temp_dir(current_function!());
            let source_dir = base_dir.join("copy_dir_all_source");
            create_dir_all(source_dir.join("subfolder1")).unwrap();
            create_dir_all(source_dir.join("subfolder2")).unwrap();
            let target_dir = base_dir.join("copy_dir_all_target");
            write_file(
                &source_dir.join("subfolder1").join("file1.txt"),
                "file 1 content",
            );
            write_file(
                &source_dir.join("subfolder2").join("file2.txt"),
                "file 2 content",
            );
            write_file(&source_dir.join("file3.txt"), "file 3 content");

            file_utils::copy_dir_all(&source_dir, &target_dir).unwrap();

            assert!(target_dir.exists());
            assert_dir_eq!(
                &target_dir,
                "
                * subfolder1/
                ** file1.txt
                * subfolder2/
                ** file2.txt
                * file3.txt
                "
                .trim()
            );
        }
    }
}
