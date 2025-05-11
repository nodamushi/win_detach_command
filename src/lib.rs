// src/lib.rs

use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::io;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::ptr;
use windows::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows::Win32::System::Threading::{
    CREATE_NEW_CONSOLE, CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT, CreateProcessW,
    PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, STARTF_USESHOWWINDOW, STARTF_USESTDHANDLES,
    STARTUPINFOW,
};
use windows::Win32::UI::WindowsAndMessaging::{SW_HIDE, SW_SHOW};
use windows::core::{PCWSTR, PWSTR};


pub type Result<T> = io::Result<T>;

/// Windowsプロセスをデタッチモードで起動
#[derive(Debug, Clone)]
pub struct WinDetachCommand {
    executable: OsString,
    args: Vec<OsString>,
    working_dir: Option<OsString>,
    env_vars: Option<HashMap<OsString, OsString>>,
    show_console: bool,
}

impl WinDetachCommand {
    /// Create new command
    pub fn new<S: AsRef<OsStr>>(executable: S) -> Self {
        WinDetachCommand {
            executable: executable.as_ref().to_os_string(),
            args: Vec::new(),
            working_dir: None,
            env_vars: None,
            show_console: false,
        }
    }

    /// Add an argument
    pub fn arg<S: AsRef<OsStr>>(&mut self, arg: S) -> &mut Self {
        self.args.push(arg.as_ref().to_os_string());
        self
    }

    /// Add arguments
    pub fn args<I, S>(&mut self, args: I) -> &mut Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        for arg in args {
            self.args.push(arg.as_ref().to_os_string());
        }
        self
    }

    /// Set process working directory
    pub fn working_dir<S: AsRef<OsStr>>(&mut self, dir: S) -> &mut Self {
        self.working_dir = Some(dir.as_ref().to_os_string());
        self
    }

    /// Set environment variable
    pub fn set_env<K, V>(&mut self, key: K, value: V) -> &mut Self
    where
        K: AsRef<OsStr>,
        V: AsRef<OsStr>,
    {
        self.env_vars
            .get_or_insert_with(HashMap::new)
            .insert(key.as_ref().to_os_string(), value.as_ref().to_os_string());
        self
    }

    /// Show console or not
    pub fn show_console(&mut self, show: bool) -> &mut Self {
        self.show_console = show;
        self
    }

    /// Spawn new process
    pub fn spawn(&self) -> Result<u32> {
        // 1. コマンドライン文字列の構築
        let command_line_os = build_command_line_os(&self.executable, &self.args);
        let mut command_line_wide = to_wide_null_terminated(&command_line_os);

        // 2. 環境変数ブロックの構築
        let mut env_block_wide_option: Option<Vec<u16>> = None;
        match &self.env_vars {
            Some(custom_vars_to_merge) => {
                let mut effective_vars: HashMap<OsString, OsString> = std::env::vars_os().collect();
                effective_vars.extend(custom_vars_to_merge.clone());
                let built_block = build_environment_block(&effective_vars)?;
                env_block_wide_option = Some(built_block);
            }
            None => {} // 親の環境を継承
        }

        let penvironment = env_block_wide_option
            .as_ref()
            .map_or(ptr::null_mut(), |v| v.as_ptr() as *mut std::ffi::c_void);

        // 3. 作業ディレクトリの準備
        let working_dir_str_op: Option<Vec<u16>> = self
            .working_dir
            .as_ref()
            .map(|wd| to_wide_null_terminated(wd));

        let pworking_dir: PCWSTR = working_dir_str_op
            .as_ref()
            .map_or(PCWSTR::null(), |v_ptr| PCWSTR::from_raw(v_ptr.as_ptr()));

        // 4. STARTUPINFOW の設定
        let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        si.dwFlags = STARTF_USESHOWWINDOW;

        // _null_* = RAII
        let (_null_input, _null_output) = if self.show_console {
            si.wShowWindow = SW_SHOW.0 as u16;
            (None, None)
        } else {
            si.wShowWindow = SW_HIDE.0 as u16;
            let nul_str = to_wide_null_terminated(OsStr::new("NUL"));

            let h_in = unsafe {
                CreateFileW(
                    PCWSTR::from_raw(nul_str.as_ptr()),
                    FILE_GENERIC_READ.0,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    None,
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    None,
                )
            }?;
            let h_nul_input_guard = Some(DropHandle::new(h_in));

            let h_out = unsafe {
                CreateFileW(
                    PCWSTR::from_raw(nul_str.as_ptr()),
                    FILE_GENERIC_WRITE.0,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    None,
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    None,
                )
            }?;
            let h_nul_output_guard = Some(DropHandle::new(h_out));

            si.dwFlags |= STARTF_USESTDHANDLES;
            si.hStdInput = h_nul_input_guard.as_ref().unwrap().as_raw_handle();
            si.hStdOutput = h_nul_output_guard.as_ref().unwrap().as_raw_handle();
            si.hStdError = h_nul_output_guard.as_ref().unwrap().as_raw_handle();
            (h_nul_input_guard, h_nul_output_guard)
        };

        // 5. プロセス作成フラグ
        let mut creation_flags = PROCESS_CREATION_FLAGS(0);
        if penvironment != ptr::null_mut() {
            creation_flags |= CREATE_UNICODE_ENVIRONMENT;
        }
        if self.show_console {
            creation_flags |= CREATE_NEW_CONSOLE;
        } else {
            creation_flags |= CREATE_NO_WINDOW;
        }

        // 6. PROCESS_INFORMATION 構造体の準備
        let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

        // 7. CreateProcessW の呼び出し
        unsafe {
            CreateProcessW(
                PCWSTR::null(),
                Some(PWSTR(command_line_wide.as_mut_ptr())),
                None,
                None,
                false,
                creation_flags,
                Some(penvironment as *const std::ffi::c_void),
                pworking_dir,
                &si,
                &mut pi,
            )
        }
        .map_err(|e| io::Error::from_raw_os_error(e.code().0))?;

        // RAII
        let _h_process_guard = DropHandle::new(pi.hProcess);
        let _h_thread_guard = DropHandle::new(pi.hThread);

        Ok(pi.dwProcessId)
    }
}


impl std::fmt::Display for WinDetachCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Exec: '{:?}'", self.executable)?;

        write!(f, "; Args: [")?;
        if !self.args.is_empty() {
            for (i, arg) in self.args.iter().enumerate() {
                if i > 0 {
                    write!(f, ", ")?;
                }
                write!(f, "'{:?}'", arg)?;
            }
        }
        write!(f, "]")?;

        write!(f, "; Working Directory: ")?;
        if let Some(wd) = &self.working_dir {
            write!(f, "'{:?}'", wd)?;
        } else {
            write!(f, "None")?;
        }

        write!(f, "; Environment: ")?;
        match &self.env_vars {
            Some(vars) => {
                if vars.is_empty() {
                    write!(f, "(Inherits parent, no custom overrides)")?;
                } else {
                    write!(f, "(Custom, merges with parent): {{")?;
                    let mut first = true;
                    for (key, value) in vars {
                        if !first {
                            write!(f, ", ")?;
                        }
                        write!(f, "'{:?}'='{:?}'", key, value)?;
                        first = false;
                    }
                    write!(f, "}}")?;
                }
            }
            None => {
                write!(f, "(Inherits parent fully)")?;
            }
        }

        write!(f, "; Show Console: {}", self.show_console)?;
        Ok(())
    }
}

// ---- Helper -------------------------------------------------------

struct DropHandle(HANDLE);
impl DropHandle {
    fn new(handle: HANDLE) -> Self {
        DropHandle(handle)
    }

    fn as_raw_handle(&self) -> HANDLE {
        self.0
    }
}
impl Drop for DropHandle {
    fn drop(&mut self) {
        if self.0 != INVALID_HANDLE_VALUE && !self.0.is_invalid() {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}


fn to_wide_null_terminated(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0)).collect()
}

fn escape_arg_os(arg: &OsStr) -> OsString {
    let s_lossy = arg.to_string_lossy();

    if s_lossy.is_empty() {
        return OsString::from("\"\"");
    }

    let needs_quoting = s_lossy.contains(|c: char| matches!(c, ' ' | '\t' | '\n' | '\x0B' | '"'));

    if !needs_quoting {
        return arg.to_os_string();
    }

    let mut result_wide_vec: Vec<u16> = Vec::with_capacity(arg.len() + 2);
    result_wide_vec.push(b'"' as u16);

    let wide_arg: Vec<u16> = arg.encode_wide().collect();
    let mut backslashes = 0;
    for &char_code in wide_arg.iter() {
        if char_code == (b'\\' as u16) {
            backslashes += 1;
        } else if char_code == (b'"' as u16) {
            result_wide_vec.extend(std::iter::repeat(b'\\' as u16).take(backslashes * 2 + 1));
            result_wide_vec.push(b'"' as u16);
            backslashes = 0;
        } else {
            result_wide_vec.extend(std::iter::repeat(b'\\' as u16).take(backslashes));
            result_wide_vec.push(char_code);
            backslashes = 0;
        }
    }
    result_wide_vec.extend(std::iter::repeat(b'\\' as u16).take(backslashes * 2));
    result_wide_vec.push(b'"' as u16);

    OsString::from_wide(&result_wide_vec)
}

fn build_command_line_os(executable: &OsStr, args: &[OsString]) -> OsString {
    let mut cmd_line = escape_arg_os(executable);
    for arg in args {
        cmd_line.push(OsStr::new(" "));
        cmd_line.push(escape_arg_os(arg));
    }
    cmd_line
}

fn build_environment_block(vars: &HashMap<OsString, OsString>) -> Result<Vec<u16>> {
    if vars.is_empty() {
        return Ok(vec![0, 0]);
    }

    let mut block: Vec<u16> = Vec::new();
    for (key, value) in vars {
        if key.is_empty() {
            continue;
        }
        block.extend(key.encode_wide());
        block.push(b'=' as u16);
        block.extend(value.encode_wide());
        block.push(0);
    }
    block.push(0);
    Ok(block)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escape_arg() {
        assert_eq!(
            escape_arg_os(OsStr::new("simple")),
            OsString::from("simple")
        );
        assert_eq!(escape_arg_os(OsStr::new("")), OsString::from("\"\""));
        assert_eq!(
            escape_arg_os(OsStr::new("with space")),
            OsString::from("\"with space\"")
        );
        assert_eq!(
            escape_arg_os(OsStr::new("with\"quote")),
            OsString::from("\"with\\\"quote\"")
        );
        assert_eq!(
            escape_arg_os(OsStr::new("c:\\path\\to\\file")),
            OsString::from("c:\\path\\to\\file")
        );
        assert_eq!(
            escape_arg_os(OsStr::new("c:\\path with space\\to\\file")),
            OsString::from("\"c:\\path with space\\to\\file\"")
        );
        assert_eq!(
            escape_arg_os(OsStr::new("ends with\\")),
            OsString::from("\"ends with\\\\\"")
        );
        assert_eq!(
            escape_arg_os(OsStr::new("ends with\\\"")),
            OsString::from("\"ends with\\\\\\\"\"")
        );
    }

    #[test]
    fn test_build_command_line() {
        let executable = OsString::from("test.exe");
        let args = vec![OsString::from("arg1"), OsString::from("arg with space")];
        assert_eq!(
            build_command_line_os(&executable, &args),
            OsString::from("test.exe arg1 \"arg with space\"")
        );

        let executable_with_space = OsString::from("C:\\Program Files\\App\\test.exe");
        let args_empty: Vec<OsString> = vec![];
        assert_eq!(
            build_command_line_os(&executable_with_space, &args_empty),
            OsString::from("\"C:\\Program Files\\App\\test.exe\"")
        );

        let executable_no_space = OsString::from("myprog.exe");
        let arg_simple = vec![OsString::from("foo")];
        assert_eq!(
            build_command_line_os(&executable_no_space, &arg_simple),
            OsString::from("myprog.exe foo")
        );
    }

    #[test]
    fn test_environment_block_building_custom_only() {
        let mut vars = HashMap::new();
        vars.insert(OsString::from("VAR1"), OsString::from("VALUE1"));
        vars.insert(OsString::from("VAR2"), OsString::from("VALUE TWO"));

        let block_custom_only = build_environment_block(&vars).unwrap();

        let block_as_strings = parse_env_block_for_test(&block_custom_only);
        assert_eq!(block_as_strings.len(), 2);
        assert!(block_as_strings.contains(&OsString::from("VAR1=VALUE1")));
        assert!(block_as_strings.contains(&OsString::from("VAR2=VALUE TWO")));
    }

    #[test]
    fn test_environment_block_building_empty() {
        let vars = HashMap::new();
        let block = build_environment_block(&vars).unwrap();
        assert_eq!(block, vec![0, 0]);
        let block_as_strings = parse_env_block_for_test(&block);
        assert!(block_as_strings.is_empty());
    }

    fn parse_env_block_for_test(block: &[u16]) -> Vec<OsString> {
        if block.is_empty() || (block.len() == 2 && block[0] == 0 && block[1] == 0) {
            return Vec::new();
        }

        let mut result = Vec::new();
        let mut current_entry_start = 0;
        loop {
            let mut current_entry_end = current_entry_start;
            // blockの範囲を超えないようにチェックを追加
            while current_entry_end < block.len() && block[current_entry_end] != 0 {
                current_entry_end += 1;
            }

            // current_entry_start == current_entry_end は、連続するヌル文字か、
            // ブロックの末尾（最後のヌル文字の後）を指している場合
            if current_entry_start >= current_entry_end {
                // current_entry_start がブロックの終わりか、それ以降なら終了
                break;
            }

            result.push(OsString::from_wide(
                &block[current_entry_start..current_entry_end],
            ));

            current_entry_start = current_entry_end + 1;
            // ブロックの終端（ダブルヌル）に達したか、またはブロックの物理的な終端に達したかを確認
            if current_entry_start >= block.len()
                || block[current_entry_start - 1] == 0 && block[current_entry_start] == 0
            {
                break;
            }
        }
        result
    }
}
